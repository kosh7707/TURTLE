#include "artifact/json.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
namespace turtle::artifact {
namespace {
struct Descriptor {
  int fd;
  explicit Descriptor(int value) : fd(value) {}
  Descriptor(const Descriptor &) = delete;
  ~Descriptor() {
    if (fd >= 0)
      ::close(fd);
  }
};
struct Temporary {
  int directory;
  const char *name;
  ~Temporary() {
    if (name)
      ::unlinkat(directory, name, 0);
  }
};
} // namespace
std::string read_text(const std::filesystem::path &p) {
  std::ifstream f(p, std::ios::binary);
  if (!f)
    throw std::runtime_error("cannot_read:" + p.string());
  return {std::istreambuf_iterator<char>(f), {}};
}
Bytes read_bytes(const std::filesystem::path &p) {
  auto s = read_text(p);
  return {s.begin(), s.end()};
}
Json load(const std::filesystem::path &p) { return Json::parse(read_text(p)); }
void require_only_fields(const Json &object,
                         std::initializer_list<std::string_view> allowed) {
  if (!object.is_object())
    throw std::runtime_error("object_required");
  for (const auto &[key, value] : object.items())
    if (std::find(allowed.begin(), allowed.end(), key) == allowed.end())
      throw std::runtime_error("unknown_field:" + key);
}
void write_text(const std::filesystem::path &p, const std::string &s) {
  std::ofstream f(p, std::ios::binary);
  f.write(s.data(), static_cast<std::streamsize>(s.size()));
  f.close();
  if (!f)
    throw std::runtime_error("cannot_write:" + p.string());
}
void save(const std::filesystem::path &p, const Json &j) {
  const auto data = j.dump(2) + "\n";
  const auto file = p.filename().native();
  auto fail = [&] { throw std::runtime_error("cannot_save:" + p.string()); };
  if (file.empty() || file == "." || file == ".." ||
      p.native().find('\0') != std::string::npos)
    fail();

  constexpr int flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
  Descriptor dir(::open(p.is_absolute() ? "/" : ".", flags));
  if (dir.fd < 0)
    fail();
  for (const auto &part : p.parent_path().relative_path()) {
    if (part == "." || part.empty())
      continue;
    int next = ::openat(dir.fd, part.c_str(), flags);
    if (next < 0)
      fail();
    ::close(dir.fd);
    dir.fd = next;
  }
  struct stat st{};
  if (::fstatat(dir.fd, file.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
    if (!S_ISREG(st.st_mode))
      fail();
  } else if (errno != ENOENT)
    fail();

  // mkostemp creates mode 0600 with O_EXCL. Pin the directory for creation,
  // cleanup and publication rather than resolving any archive component again.
  std::string prefix = "/proc/self/fd/" + std::to_string(dir.fd) + "/";
  std::string path = prefix + ".turtle-write-XXXXXX";
  Descriptor output(::mkostemp(path.data(), O_CLOEXEC));
  if (output.fd < 0)
    fail();
  Temporary tmp{dir.fd, path.c_str() + prefix.size()};
  for (std::size_t offset = 0; offset < data.size();) {
    auto n = ::write(output.fd, data.data() + offset, data.size() - offset);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      fail();
    offset += static_cast<std::size_t>(n);
  }
  int written = output.fd;
  output.fd = -1;
  if (::close(written) < 0 ||
      ::renameat(dir.fd, tmp.name, dir.fd, file.c_str()) < 0)
    fail();
  tmp.name = nullptr;
}
std::uint64_t integer(const Json &j) {
  if (!j.is_number_integer() ||
      (j.is_number_integer() && !j.is_number_unsigned() &&
       j.get<std::int64_t>() < 0))
    throw std::runtime_error("nonnegative_integer_required");
  return j.get<std::uint64_t>();
}
Json measurement(Json v, std::string a, Json r) {
  return {{"value", std::move(v)},
          {"availability", std::move(a)},
          {"reason", std::move(r)}};
}
Json interval(const Json &a, const Json &b) {
  Json d = Json::object();
  for (auto k : {"wall_ns", "thread_cpu_ns"}) {
    auto x = integer(a.at(k)), y = integer(b.at(k));
    if (y < x)
      throw std::runtime_error("clock_reversed");
    d[k] = y - x;
  }
  return {{"begin", a}, {"end", b}, {"duration", d}};
}
} // namespace turtle::artifact
