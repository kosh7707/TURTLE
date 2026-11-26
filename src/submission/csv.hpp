#pragma once
#include <charconv>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace turtle::submission {
using Fields = std::vector<std::string>;
using Record = std::map<std::string, std::string>;

// Role records contain one physical line per row. Quotes/commas in a reason
// are escaped; line breaks are reserved for record boundaries.
inline void write_row(std::ostream &out, const Fields &fields) {
  for (size_t i = 0; i < fields.size(); ++i) {
    if (i) out.put(',');
    const auto &s = fields[i];
    const bool quote = s.find_first_of(",\"") != s.npos;
    if (quote) out.put('"');
    for (char ch : s) {
      if (ch == '"') out.put('"');
      out.put(ch == '\n' || ch == '\r' ? ' ' : ch);
    }
    if (quote) out.put('"');
  }
  out << '\n';
  if (!out) throw std::runtime_error("could not write CSV");
}
inline Fields split_row(const std::string &s) {
  Fields row;
  size_t i = 0;
  for (;;) {
    std::string value;
    if (i < s.size() && s[i] == '"') {
      ++i;
      for (;;) {
        if (i == s.size()) throw std::runtime_error("unterminated quoted CSV field");
        char ch = s[i++];
        if (ch != '"') { value += ch; continue; }
        if (i == s.size() || s[i] != '"') break;
        ++i; value += '"';
      }
    } else {
      while (i < s.size() && s[i] != ',') {
        if (s[i] == '"') throw std::runtime_error("unexpected quote in CSV");
        value += s[i++];
      }
    }
    row.push_back(std::move(value));
    if (i == s.size()) return row;
    if (s[i++] != ',') throw std::runtime_error("invalid CSV separator");
  }
}
class CsvInput {
  std::ifstream in_;
  std::string label_;
  Fields header_;
public:
  explicit CsvInput(const std::filesystem::path &path) : in_(path), label_(path.filename().string()) {
    std::string line;
    if (!std::getline(in_, line)) throw std::runtime_error("missing CSV header: " + label_);
    header_ = split_row(line);
  }
  bool next(Record &row) {
    std::string line;
    if (!std::getline(in_, line)) {
      if (!in_.eof() || in_.bad()) throw std::runtime_error("CSV read failed: " + label_);
      return false;
    }
    if (in_.eof()) throw std::runtime_error("incomplete CSV row: " + label_);
    auto values = split_row(line);
    if (values.size() != header_.size()) throw std::runtime_error("wrong CSV column count: " + label_);
    row.clear();
    for (size_t i = 0; i < values.size(); ++i)
      if (!row.emplace(header_[i], std::move(values[i])).second)
        throw std::runtime_error("duplicate CSV column: " + label_);
    return true;
  }
};
inline Record read_role(const std::filesystem::path &path) {
  CsvInput file(path);
  Record row, extra;
  if (!file.next(row) || file.next(extra)) throw std::runtime_error("expected one role row: " + path.filename().string());
  return row;
}
template<class T> inline T number(std::string_view s) {
  T value{};
  auto [end, err] = std::from_chars(s.data(), s.data() + s.size(), value);
  if (s.empty() || err != std::errc{} || end != s.data() + s.size())
    throw std::runtime_error("invalid numeric value: " + std::string(s));
  return value;
}
} // namespace turtle::submission
