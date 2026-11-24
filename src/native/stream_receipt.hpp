#pragma once
#include "process/process.hpp"
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace turtle::native::detail {
// A retry executes archived argv. A raw digest inside the same imported
// archive is not authorization to launch it. Bind local creation to a private
// user-owned receipt; analysis and ordinary collection need no state directory.
class Receipts {
  int fd = -1;

public:
  Receipts() {
    const char *x = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
    std::filesystem::path base;
    if (x && *x)
      base = x;
    else if (home && *home)
      base = std::filesystem::path(home) / ".local/state";
    if (!base.is_absolute())
      return;
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    if (ec)
      return;
    struct stat owner{};
    if (lstat(base.c_str(), &owner) || !S_ISDIR(owner.st_mode) ||
        owner.st_uid != getuid() || (owner.st_mode & 0022))
      return;
    auto path = base / "turtle-retry";
    if (::mkdir(path.c_str(), 0700) && errno != EEXIST)
      return;
    fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    struct stat s{};
    if (fd >= 0 &&
        (fstat(fd, &s) || s.st_uid != getuid() || (s.st_mode & 0777) != 0700)) {
      close(fd);
      fd = -1;
    }
  }
  ~Receipts() {
    if (fd >= 0)
      close(fd);
  }
  Receipts(const Receipts &) = delete;
  bool verify_or_store(const std::filesystem::path &root,
                       const artifact::Json &manifest, bool store) {
    auto id = manifest.at("run_id").get<std::string>();
    if (fd < 0 || id.size() != 36 ||
        id.find_first_not_of("abcdef0123456789-") != id.npos)
      return false;
    // Hash the same immutable parsed manifest the caller will use, never
    // re-open the path between checking authority and using its argv.
    process::Child hash({"sha256sum"});
    hash.send(manifest.dump());
    hash.close_input();
    auto end = process::deadline(10);
    auto digest = hash.collect(end);
    if (hash.wait(end) != 0 || digest.size() < 64)
      return false;
    auto expected =
        artifact::Json{{"source", std::filesystem::canonical(root).string()},
                       {"manifest_sha256", digest.substr(0, 64)}}
            .dump();
    int f = openat(fd, id.c_str(),
                   O_CLOEXEC | O_NOFOLLOW |
                       (store ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY) |
                       O_NONBLOCK,
                   0600);
    if (f < 0)
      return false;
    struct Close {
      int f;
      ~Close() { close(f); }
    } closefd{f};
    struct stat s{};
    if (fstat(f, &s) || !S_ISREG(s.st_mode) || s.st_uid != getuid() ||
        s.st_nlink != 1 || (s.st_mode & 0777) != 0600)
      return false;
    if (store) {
      size_t n = 0;
      while (n < expected.size()) {
        auto r = write(f, expected.data() + n, expected.size() - n);
        if (r < 0 && errno == EINTR)
          continue;
        if (r <= 0)
          return false;
        n += r;
      }
      return true;
    }
    if (s.st_size != static_cast<off_t>(expected.size()))
      return false;
    std::string actual(expected.size(), '\0');
    size_t n = 0;
    while (n < actual.size()) {
      auto r = read(f, actual.data() + n, actual.size() - n);
      if (r < 0 && errno == EINTR)
        continue;
      if (r <= 0)
        return false;
      n += r;
    }
    return actual == expected;
  }
};
} // namespace turtle::native::detail
