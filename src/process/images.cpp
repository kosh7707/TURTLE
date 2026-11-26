#include "process/images.hpp"
#include "process/process.hpp"
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <memory>
#include <poll.h>
#include <set>
#include <sstream>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
namespace turtle::process {
using artifact::Json;
namespace fs = std::filesystem;
namespace {
void check(bool ok, const char *error) {
  if (!ok)
    throw std::runtime_error(error);
}
fs::path proc(pid_t pid) { return fs::path("/proc") / std::to_string(pid); }
bool child_of(pid_t pid, pid_t launcher) {
  for (int i = 0; i < 64 && pid > 1; ++i) {
    if (pid == launcher)
      return true;
    std::ifstream status(proc(pid) / "status");
    std::string line;
    pid_t parent = 0;
    while (std::getline(status, line))
      if (line.starts_with("PPid:")) {
        std::istringstream(line.substr(5)) >> parent;
        break;
      }
    pid = parent;
  }
  return false;
}
bool sha(const Json &s) {
  if (!s.is_string())
    return false;
  const auto &str = s.get_ref<const std::string &>();
  return str.size() == 64 &&
         str.find_first_not_of("0123456789abcdef") == str.npos;
}
struct File {
  int fd;
  struct stat before{};
  explicit File(const fs::path &path)
      : fd(open(path.c_str(), O_RDONLY | O_NONBLOCK)) {}
  ~File() {
    if (fd >= 0)
      close(fd);
  }
};
// Runs in the snapshot group. Both /proc/file access and the external hasher
// are optional: neither is allowed to hold the supervisor past its deadline.
Json collect_images(pid_t launcher, pid_t participant, Deadline until) {
  Json inventory = {
      {"launcher_pid", launcher}, {"pid", participant}, {"available", false}};
  try {
    check(child_of(participant, launcher), "image_participant_not_child");
    auto procdir = proc(participant);
    auto exe = fs::read_symlink(procdir / "exe").native();
    std::ifstream maps(procdir / "maps");
    check(maps.good(), "image_maps_unavailable");
    std::map<std::string, std::unique_ptr<File>> files;
    std::string line;
    while (std::getline(maps, line)) {
      std::istringstream fields(line);
      std::string range, perms, offset, device, path;
      unsigned long long inode;
      check(bool(fields >> range >> perms >> offset >> device >> inode),
            "image_map_malformed");
      if (perms.size() < 3 || perms[2] != 'x')
        continue;
      std::getline(fields >> std::ws, path);
      // Kernel-provided executable gateway mappings are not userspace files.
      if (path == "[vdso]" || path == "[vsyscall]" || path == "[vectors]" ||
          path == "[sigpage]")
        continue;
      check(inode && !path.empty() && path[0] == '/' &&
                !path.ends_with(" (deleted)"),
            "image_executable_mapping_unresolved");
      auto &f = files[path];
      if (!f) {
        f = std::make_unique<File>(procdir / "root" /
                                   fs::path(path).relative_path());
        check(f->fd >= 0 && fstat(f->fd, &f->before) == 0 &&
                  S_ISREG(f->before.st_mode),
              "image_file_unavailable");
      }
      unsigned maj, min;
      char last;
      check(std::sscanf(device.c_str(), "%x:%x%c", &maj, &min, &last) == 2,
            "image_map_malformed");
      check(f->before.st_dev == makedev(maj, min) && f->before.st_ino == inode,
            path == exe ? "participant_executable_replaced"
                        : "image_mapping_replaced");
      check(files.size() <= 1024, "too_many_executable_images");
    }
    check(maps.eof() && files.contains(exe), "image_executable_unmapped");
    struct stat running{};
    check(stat((procdir / "exe").c_str(), &running) == 0 &&
              S_ISREG(running.st_mode),
          "participant_executable_stat_failed");
    check(files.at(exe)->before.st_dev == running.st_dev &&
              files.at(exe)->before.st_ino == running.st_ino,
          "participant_executable_replaced");
    // Only the synchronous sha256sum child inherits these read-only
    // descriptors. Opening and matching dev/inode before hashing avoids hashing
    // a replacement reached by re-resolving a loader pathname.
    Args args{"sha256sum"};
    for (auto &[_, f] : files)
      args.push_back("/proc/self/fd/" + std::to_string(f->fd));
    Child hash(args, {}, {}, Child::Group::inherit);
    hash.close_input();
    std::istringstream hashes(hash.collect(until));
    check(hash.wait(until) == 0, "image_digest_failed");
    Json mapped = Json::object();
    for (auto &[path, f] : files) {
      std::string hash, name;
      check(bool(hashes >> hash >> name) && sha(hash) &&
                name == "/proc/self/fd/" + std::to_string(f->fd),
            "image_digest_malformed");
      struct stat after{};
      check(fstat(f->fd, &after) == 0, "image_file_restat_failed");
      check(after.st_size == f->before.st_size &&
                after.st_ctim.tv_sec == f->before.st_ctim.tv_sec &&
                after.st_ctim.tv_nsec == f->before.st_ctim.tv_nsec,
            "image_changed_during_hash");
      mapped[path] = hash;
    }
    inventory.update({{"available", true}, {"exe", exe}, {"mapped", mapped}});
  } catch (const std::exception &e) {
    inventory["reason"] = e.what();
  }
  return inventory;
}
enum class Wait { complete, timeout, cancelled, failed };
Wait wait_bounded(pid_t pid, Deadline until, int cancel_fd) {
  pollfd cancel{cancel_fd, POLLIN, 0};
  for (;;) {
    siginfo_t info{};
    auto rc = waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT);
    if (rc == 0 && info.si_pid == pid)
      return Wait::complete;
    if (rc < 0 && errno != EINTR)
      return Wait::failed;
    auto ms = std::chrono::ceil<std::chrono::milliseconds>(
        until - std::chrono::steady_clock::now()).count();
    if (ms <= 0)
      return Wait::timeout;
    auto ready = poll(&cancel, 1, static_cast<int>(std::min<int64_t>(ms, 5)));
    if (ready > 0)
      return Wait::cancelled;
    if (ready < 0 && errno != EINTR)
      return Wait::failed;
  }
}
pid_t reap(pid_t pid, int *status = nullptr) {
  pid_t rc;
  do {
    rc = waitpid(pid, status, 0);
  } while (rc < 0 && errno == EINTR);
  return rc;
}
constexpr size_t limit = 8 * 1024 * 1024;
// A private subreaper owns only the file scanner and its hash process tree.
// It can reap them even when the scanner itself is killed during a file read.
[[noreturn]] void monitor_images(pid_t launcher, pid_t participant, char *buffer,
                                 Deadline until, int cancel_fd) {
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
    _exit(1);
  const auto scanner = fork();
  if (!scanner) {
    close(cancel_fd);
    if (setpgid(0, 0) < 0)
      _exit(1);
    try {
      const auto text = collect_images(launcher, participant, until).dump();
      if (text.size() >= limit)
        _exit(1);
      std::memcpy(buffer, text.c_str(), text.size() + 1);
      _exit(0);
    } catch (...) {
      _exit(1);
    }
  }
  if (scanner < 0)
    _exit(1);
  setpgid(scanner, scanner);
  int status = 0;
  const auto result = wait_bounded(scanner, until, cancel_fd);
  // WNOWAIT pins this PID even on success. Clean up an inherited background
  // hash helper before releasing the group ID, never another app's group.
  kill(-scanner, SIGKILL);
  if (result != Wait::complete)
    kill(scanner, SIGKILL);
  auto reaped = reap(scanner, &status);
  while (reap(-1) > 0) {} // Only descendants of this private monitor.

  if (result == Wait::timeout)
    _exit(2);
  _exit(reaped == scanner && result == Wait::complete && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : 1);
}
} // namespace
ImageSnapshots::~ImageSnapshots() {
  if (monitor_ > 0)
    reap(monitor_);
}
Json ImageSnapshots::collect(pid_t launcher, pid_t participant, Deadline until, int cancel_fd) {
  auto unavailable = [&](const char *reason) -> Json {
    return {{"launcher_pid", launcher}, {"pid", participant}, {"available", false}, {"reason", reason}};
  };
  if (monitor_ > 0) {
    auto rc = waitpid(monitor_, nullptr, WNOHANG);
    if (!rc || (rc < 0 && errno == EINTR))
      return unavailable("previous_image_snapshot_stopping");
    monitor_ = -1;
  }
  // Reserve a slice of the existing budget for stopping work before release.
  const auto stop_at = until - std::chrono::milliseconds(20);
  if (std::chrono::steady_clock::now() >= stop_at)
    return unavailable("image_snapshot_timeout");
  // Only pages written by the helper are populated. A large inventory cannot
  // stall the helper on pipe capacity while its parent waits for completion.
  void *shared = mmap(nullptr, limit, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared == MAP_FAILED)
    return unavailable("image_snapshot_buffer_failed");
  auto unmap = [](char *p) { munmap(p, limit); };
  std::unique_ptr<char, decltype(unmap)> buffer(static_cast<char *>(shared), unmap);
  int control[2];
  if (pipe2(control, O_CLOEXEC) < 0)
    return unavailable("image_snapshot_pipe_failed");
  monitor_ = fork();
  if (!monitor_) {
    close(control[1]);
    monitor_images(launcher, participant, buffer.get(), stop_at, control[0]);
  }
  close(control[0]);
  if (monitor_ < 0) {
    close(control[1]);
    return unavailable("image_snapshot_fork_failed");
  }
  int status = 0;
  const auto result = wait_bounded(monitor_, stop_at, cancel_fd);
  close(control[1]); // EOF cancels only this inventory, not either TLS role.
  if (result != Wait::complete) {
    auto retire_by = std::min(until, std::chrono::steady_clock::now() + std::chrono::milliseconds(20));
    if (wait_bounded(monitor_, retire_by, -1) == Wait::complete) {
      reap(monitor_);
      monitor_ = -1;
    }
    return unavailable(result == Wait::timeout ? "image_snapshot_timeout" :
                       result == Wait::cancelled ? "image_snapshot_cancelled" : "image_snapshot_wait_failed");
  }
  reap(monitor_, &status);
  monitor_ = -1;
  if (WIFEXITED(status) && WEXITSTATUS(status) == 2)
    return unavailable("image_snapshot_timeout");
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    return unavailable("image_snapshot_failed");
  try {
    return Json::parse(buffer.get());
  } catch (const Json::Invalid &) {
    return unavailable("image_snapshot_invalid");
  }
}
Json image_key(const Json &inv, pid_t pid) {
  check(inv.value("available", false) && pid > 0 && inv.at("pid") == pid,
        "participant_image_unconfirmed");
  const auto &mapped = inv.at("mapped");
  const auto &exe = inv.at("exe").get_ref<const std::string &>();
  check(mapped.is_object() && mapped.contains(exe),
        "participant_executable_missing");
  for (auto &[file, hash] : mapped.items())
    check(!file.empty() && file[0] == '/' && sha(hash), "invalid_mapped_image");
  return {{"exe", exe}, {"mapped", mapped}};
}
} // namespace turtle::process
