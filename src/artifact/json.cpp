#include "artifact/json.hpp"
#include <fstream>
#include <iterator>
#include <stdexcept>
namespace turtle::artifact {
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
void write_text(const std::filesystem::path &p, const std::string &s) {
  std::ofstream f(p, std::ios::binary);
  f.write(s.data(), static_cast<std::streamsize>(s.size()));
  f.close();
  if (!f)
    throw std::runtime_error("cannot_write:" + p.string());
}
void save(const std::filesystem::path &p, const Json &j) {
  auto temporary = p;
  temporary += ".tmp";
  write_text(temporary, j.dump(2) + "\n");
  std::filesystem::rename(temporary, p);
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
