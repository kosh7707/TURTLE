#include "process/images.hpp"
#include "process/process.hpp"
#include <fcntl.h>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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
} // namespace
Json image_inventory(pid_t launcher, pid_t participant) {
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
    auto result = command(args);
    check(result.at("returncode") == 0, "image_digest_failed");
    std::istringstream hashes(result.at("stdout").get<std::string>());
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
