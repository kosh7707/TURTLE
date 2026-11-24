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
      check(std::sscanf(device.c_str(), "%x:%x%c", &maj, &min, &last) == 2 &&
                f->before.st_dev == makedev(maj, min) &&
                f->before.st_ino == inode,
            "image_mapping_replaced");
      check(files.size() <= 1024, "too_many_executable_images");
    }
    check(maps.eof() && files.contains(exe), "image_executable_unmapped");
    struct stat running{};
    check(stat((procdir / "exe").c_str(), &running) == 0 &&
              files.at(exe)->before.st_dev == running.st_dev &&
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
      check(fstat(f->fd, &after) == 0 && after.st_size == f->before.st_size &&
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
} // namespace
Json image_inventory(pid_t launcher, pid_t participant, Deadline until, int cancel_fd) {
  auto unavailable = [&](const char *reason) -> Json {
    return {{"launcher_pid", launcher}, {"pid", participant}, {"available", false}, {"reason", reason}};
  };
  // A cancelled helper may still be in a kernel file operation. Do not
  // block joint release on waitpid, or accumulate more helpers behind it.
  static thread_local pid_t stopping = -1;
  if (stopping > 0) {
    auto reaped = waitpid(stopping, nullptr, WNOHANG);
    if (!reaped || (reaped < 0 && errno == EINTR))
      return unavailable("previous_image_snapshot_stopping");
    stopping = -1;
  }
  if (std::chrono::steady_clock::now() >= until)
    return unavailable("image_snapshot_timeout");
  // Only pages written by the helper are populated. A large inventory cannot
  // stall the helper on pipe capacity while its parent waits for completion.
  constexpr size_t limit = 8 * 1024 * 1024;
  void *shared = mmap(nullptr, limit, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared == MAP_FAILED)
    return unavailable("image_snapshot_buffer_failed");
  auto unmap = [](char *p) { munmap(p, limit); };
  std::unique_ptr<char, decltype(unmap)> buffer(static_cast<char *>(shared), unmap);
  const auto pid = fork();
  if (!pid) {
    if (setpgid(0, 0) != 0)
      _exit(1);
    try {
      auto text = collect_images(launcher, participant, until).dump();
      if (text.size() >= limit)
        _exit(1);
      std::memcpy(buffer.get(), text.c_str(), text.size() + 1);
      _exit(0);
    } catch (...) {
      _exit(1);
    }
  }
  if (pid < 0)
    return unavailable("image_snapshot_fork_failed");
  setpgid(pid, pid);
  pollfd cancel{cancel_fd, POLLIN, 0};
  int status = 0;
  for (;;) {
    const auto rc = waitpid(pid, &status, WNOHANG);
    if (rc == pid)
      break;
    if (rc < 0 && errno != EINTR)
      return unavailable("image_snapshot_wait_failed");
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        until - std::chrono::steady_clock::now()).count();
    if (ms > 0 && poll(&cancel, 1, static_cast<int>(std::min<int64_t>(ms, 5))) <= 0)
      continue;
    kill(-pid, SIGKILL); // includes sha256sum; never signal either TLS role
    stopping = pid;
    return unavailable(ms > 0 ? "image_snapshot_cancelled" : "image_snapshot_timeout");
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    return unavailable("image_snapshot_failed");
  auto inventory = Json::parse(buffer.get(), nullptr, false);
  return inventory.is_discarded() ? unavailable("image_snapshot_invalid") : inventory;
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
