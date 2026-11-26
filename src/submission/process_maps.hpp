#pragma once

#include <charconv>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace turtle::submission {
enum class MapsState { unavailable, incomplete, contradicted, matched };
inline constexpr std::string_view maps_trailer = "# turtle-maps rows=";

// Keep raw Linux maps rows, then attest that the source reached a clean EOF.
// The caller publishes this file atomically only after a successful close.
inline bool write_process_maps(std::istream &in, std::ostream &out) {
  if (!in || !out)
    return false;
  unsigned long long rows = 0;
  for (std::string line; std::getline(in, line); ++rows)
    if (in.eof() || !(out << line << '\n'))
      return false;
  return in.eof() && !in.bad() && rows > 0 &&
         bool(out << maps_trailer << rows << '\n');
}

// This checks post-task pathnames, not the file identities of the live images;
// the independent prepared image receipt supplies that evidence when available.
inline MapsState process_maps(std::istream &in, const std::filesystem::path &exe,
                              const std::vector<std::filesystem::path> &libs) {
  if (!in)
    return MapsState::unavailable;
  auto number = [](std::string_view field, int base, unsigned long long &value) {
    if (field.empty())
      return false;
    const auto end = field.data() + field.size();
    const auto [last, error] = std::from_chars(field.data(), end, value, base);
    return error == std::errc{} && last == end;
  };
  std::set<std::string> files;
  unsigned long long rows = 0;
  bool complete = false;
  for (std::string line; std::getline(in, line);) {
    if (in.eof())
      return MapsState::incomplete;
    if (line.starts_with(maps_trailer)) {
      unsigned long long declared;
      if (!number(std::string_view(line).substr(maps_trailer.size()), 10, declared) ||
          rows == 0 || rows != declared)
        return MapsState::incomplete;
      complete = in.peek() == std::char_traits<char>::eof() && in.eof() && !in.bad();
      break;
    }
    std::istringstream fields(line);
    std::string range, perms, offset, device, inode, path;
    if (!(fields >> range >> perms >> offset >> device >> inode))
      return MapsState::incomplete;
    const auto dash = range.find('-'), colon = device.find(':');
    const std::string_view addresses = range, dev = device;
    unsigned long long start, end, ignored;
    if (dash == range.npos || colon == device.npos ||
        !number(addresses.substr(0, dash), 16, start) ||
        !number(addresses.substr(dash + 1), 16, end) || start >= end ||
        perms.size() != 4 || (perms[0] != 'r' && perms[0] != '-') ||
        (perms[1] != 'w' && perms[1] != '-') ||
        (perms[2] != 'x' && perms[2] != '-') ||
        (perms[3] != 'p' && perms[3] != 's') ||
        !number(offset, 16, ignored) || !number(dev.substr(0, colon), 16, ignored) ||
        !number(dev.substr(colon + 1), 16, ignored) || !number(inode, 10, ignored))
      return MapsState::incomplete;
    ++rows;
    if (std::getline(fields >> std::ws, path) && path.starts_with('/'))
      files.insert(path);
  }
  if (!complete)
    return MapsState::incomplete;
  if (!files.contains(exe.native()))
    return MapsState::contradicted;
  for (const auto &library : libs)
    if (!files.contains(library.native()))
      return MapsState::contradicted;
  return MapsState::matched;
}

inline MapsState process_maps(const std::filesystem::path &snapshot,
                              const std::filesystem::path &exe,
                              const std::vector<std::filesystem::path> &libs) {
  std::error_code error;
  if (!std::filesystem::is_regular_file(snapshot, error))
    return MapsState::unavailable;
  std::ifstream in(snapshot);
  return process_maps(in, exe, libs);
}
} // namespace turtle::submission
