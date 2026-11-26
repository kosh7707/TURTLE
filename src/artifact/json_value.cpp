#include "artifact/json_value.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <system_error>

namespace turtle::artifact {
Json::Json(double n) {
  if (!std::isfinite(n))
    throw Invalid("non-finite JSON number");
  data_ = n;
}

Json::Json(const std::vector<std::string> &a) : data_(Array{}) {
  auto &out = elements();
  out.reserve(a.size());
  for (const auto &s : a)
    out.emplace_back(s);
}

Json::Json(const std::map<std::string, std::string> &o) : data_(Object{}) {
  for (const auto &[key, s] : o)
    items().emplace(key, s);
}

// The in-source literal convenience is not used to classify parsed input.
Json::Json(std::initializer_list<Json> rows) {
  if (std::all_of(rows.begin(), rows.end(), [](const Json &r) {
        return r.is_array() && r.size() == 2 && r.at(0).is_string();
      })) {
    data_ = Object{};
    for (const auto &row : rows)
      items().insert_or_assign(row.at(0).get_ref<const std::string &>(), row.at(1));
  } else {
    data_ = Array(rows);
  }
}

std::size_t Json::size() const {
  if (const auto *a = std::get_if<Array>(&data_))
    return a->size();
  if (const auto *o = std::get_if<Object>(&data_))
    return o->size();
  return is_null() ? 0 : 1;
}

const Json *Json::find_member(std::string_view key) const {
  if (const auto *o = std::get_if<Object>(&data_))
    if (const auto i = o->find(key); i != o->end())
      return &i->second;
  return nullptr;
}

Json &Json::at(std::string_view key) {
  return const_cast<Json &>(std::as_const(*this).at(key));
}

const Json &Json::at(std::string_view key) const {
  const auto i = items().find(key);
  if (i == items().end())
    throw std::out_of_range("missing JSON field: " + std::string(key));
  return i->second;
}

Json &Json::operator[](std::string_view key) {
  if (is_null())
    data_ = Object{};
  return items().try_emplace(std::string(key)).first->second;
}

Json &Json::operator[](std::size_t i) {
  return at(i);
}

void Json::push_back(Json value) {
  if (is_null())
    data_ = Array{};
  elements().push_back(std::move(value));
}

void Json::erase(std::string_view key) {
  auto &object = items();
  if (auto it = object.find(key); it != object.end())
    object.erase(it);
}

void Json::update(const Json &object) {
  if (is_null())
    data_ = Object{};
  for (const auto &[key, value] : object.items())
    items().insert_or_assign(key, value);
}

bool operator==(const Json &a, const Json &b) {
  if (a.data_.index() == b.data_.index())
    return a.data_ == b.data_;
  if (a.is_number_integer() && b.is_number_integer()) {
    const auto &s = a.is_number_unsigned() ? b : a;
    const auto &u = a.is_number_unsigned() ? a : b;
    return std::cmp_equal(s.get<std::int64_t>(), u.get<std::uint64_t>());
  }
  if (a.is_number() && b.is_number()) {
    const auto &integer = a.is_number_integer() ? a : b;
    const auto &fraction = a.is_number_integer() ? b : a;
    const auto n = fraction.get<double>();
    // Convert only in the integer type's exact range. Require equality with
    // the converted integer too, so fractional values cannot compare equal.
    const auto same_integer = [&]<typename T>(double lower, double upper) {
      if (n < lower || n >= upper)
        return false;
      const auto rounded = static_cast<T>(n);
      return n == static_cast<double>(rounded) && integer.get<T>() == rounded;
    };
    return integer.is_number_unsigned()
               ? same_integer.operator()<std::uint64_t>(0, 0x1p64)
               : same_integer.operator()<std::int64_t>(-0x1p63, 0x1p63);
  }
  return false;
}

namespace {
bool is_digit(char c) { return c >= '0' && c <= '9'; }
int hex_digit(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Validate raw UTF-8 (including overlong encodings and surrogate code points)
// when decoding and writing. Escaped Unicode is decoded to the same bytes.
unsigned utf8_width(std::string_view s) {
  const unsigned char a = s.front();
  if (a < 0x80) return 1;
  const unsigned n = a >= 0xC2 && a <= 0xDF ? 2 :
                     a >= 0xE0 && a <= 0xEF ? 3 :
                     a >= 0xF0 && a <= 0xF4 ? 4 : 0;
  if (!n || s.size() < n) return 0;
  const unsigned char b = s[1];
  if ((a == 0xE0 && b < 0xA0) || (a == 0xED && b >= 0xA0) ||
      (a == 0xF0 && b < 0x90) || (a == 0xF4 && b >= 0x90)) return 0;
  for (unsigned i = 1; i < n; ++i)
    if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) return 0;
  return n;
}

void append_utf8(std::string &s, unsigned code) {
  if (code < 0x80) {
    s += static_cast<char>(code);
    return;
  }
  const unsigned n = code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  constexpr unsigned head[]{0, 0, 0xC0, 0xE0, 0xF0};
  s += static_cast<char>(head[n] | (code >> (6 * (n - 1))));
  for (unsigned i = n - 1; i; --i)
    s += static_cast<char>(0x80 | ((code >> (6 * (i - 1))) & 0x3F));
}

class Reader {
public:
  explicit Reader(std::string_view text) : input(text) {}

  Json parse() {
    if (input.size() > Json::max_text_bytes)
      fail("input size limit");
    auto result = value(0);
    space();
    if (pos != input.size()) fail("unexpected data after value");
    return result;
  }

private:
  static constexpr std::size_t max_values = 2'000'000;
  std::string_view input;
  std::size_t pos = 0, values = 0;

  [[noreturn]] void fail(std::string_view why) const {
    throw Json::Invalid("invalid JSON at byte " + std::to_string(pos) +
                        ": " + std::string(why));
  }
  char peek() const { return pos < input.size() ? input[pos] : '\0'; }
  bool consume(char c) {
    if (pos == input.size() || input[pos] != c) return false;
    ++pos;
    return true;
  }
  void expect(char c) {
    if (!consume(c)) fail("unexpected character");
  }
  void space() {
    while (peek() == ' ' || peek() == '\n' || peek() == '\r' || peek() == '\t')
      ++pos;
  }
  void literal(std::string_view name) {
    if (!input.substr(pos).starts_with(name)) fail("expected literal");
    pos += name.size();
  }
  unsigned unicode_unit() {
    unsigned code = 0;
    for (unsigned j = 0; j < 4; ++j) {
      const auto h = hex_digit(peek());
      if (h < 0) fail("invalid Unicode escape");
      code = (code << 4) | static_cast<unsigned>(h);
      ++pos;
    }
    return code;
  }
  std::string string() {
    expect('"');
    std::string out;
    while (pos < input.size()) {
      char c = input[pos++];
      switch (c) {
      case '"': return out;
      case '\\':
        switch (peek()) {
        case '"': case '\\': case '/': out += input[pos++]; break;
        case 'b': ++pos; out += '\b'; break;
        case 'f': ++pos; out += '\f'; break;
        case 'n': ++pos; out += '\n'; break;
        case 'r': ++pos; out += '\r'; break;
        case 't': ++pos; out += '\t'; break;
        case 'u': {
          ++pos;
          auto code = unicode_unit();
          if (code >= 0xD800 && code <= 0xDBFF) {
            expect('\\');
            expect('u');
            const auto low = unicode_unit();
            if (low < 0xDC00 || low > 0xDFFF) fail("unpaired surrogate");
            code = 0x10000 + ((code - 0xD800) << 10U) + (low - 0xDC00);
          } else if (code >= 0xDC00 && code <= 0xDFFF) {
            fail("unpaired surrogate");
          }
          append_utf8(out, code);
          break;
        }
        default: fail("invalid string escape");
        }
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) fail("unescaped control character");
        if (static_cast<unsigned char>(c) < 0x80) {
          out += c;
        } else {
          const auto tail = input.substr(pos - 1);
          const unsigned n = utf8_width(tail);
          if (!n) fail("invalid UTF-8");
          out += tail.substr(0, n);
          pos += n - 1;
        }
      }
    }
    fail("unterminated string");
  }
  template <typename T> Json number_as(std::string_view digits) const {
    T n{};
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
    if (ec != std::errc{} || end != digits.data() + digits.size()) fail("number out of range");
    return n;
  }
  Json number() {
    const auto begin = pos;
    const bool negative = consume('-');
    if (!consume('0')) {
      if (!is_digit(peek())) fail("expected digit");
      do { ++pos; } while (is_digit(peek()));
    }
    const bool fraction = consume('.');
    if (fraction) {
      if (!is_digit(peek())) fail("expected fractional digit");
      do { ++pos; } while (is_digit(peek()));
    }
    const bool exponent = consume('e') || consume('E');
    if (exponent) {
      if (!consume('+')) consume('-');
      if (!is_digit(peek())) fail("expected exponent digit");
      do { ++pos; } while (is_digit(peek()));
    }
    const auto digits = input.substr(begin, pos - begin);
    if (fraction || exponent) return number_as<double>(digits);
    return negative ? number_as<std::int64_t>(digits) : number_as<std::uint64_t>(digits);
  }
  Json value(unsigned depth) {
    if (depth > Json::max_depth) fail("nesting limit");
    if (++values > max_values) fail("value count limit");
    space();
    switch (peek()) {
    case 'n': literal("null"); return nullptr;
    case 't': literal("true"); return true;
    case 'f': literal("false"); return false;
    case '"': return string();
    case '[': {
      ++pos;
      Json::Array array;
      space();
      if (consume(']')) return array;
      do {
        array.push_back(value(depth + 1));
        space();
      } while (consume(','));
      expect(']');
      return array;
    }
    case '{': {
      ++pos;
      Json::Object object;
      space();
      if (consume('}')) return object;
      do {
        space();
        auto key = string();
        space();
        expect(':');
        if (!object.try_emplace(key, value(depth + 1)).second)
          fail("duplicate field: " + key);
        space();
      } while (consume(','));
      expect('}');
      return object;
    }
    default: return number();
    }
  }
};

void quote(std::string &out, std::string_view text) {
  constexpr char hex[] = "0123456789abcdef";
  out += '"';
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char c = text[i];
    switch (c) {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    case '\b': out += "\\b"; break;
    case '\f': out += "\\f"; break;
    default:
      if (c < 0x20) {
        out += "\\u00";
        out += hex[c >> 4];
        out += hex[c & 15];
      } else if (c < 0x80) {
        out += static_cast<char>(c);
      } else {
        const auto rest = text.substr(i);
        const unsigned n = utf8_width(rest);
        if (!n) throw Json::Invalid("invalid UTF-8 in output");
        out += rest.substr(0, n);
        i += n - 1;
      }
    }
  }
  out += '"';
}
template <typename T> void number_text(std::string &out, T value) {
  char buf[64];
  const auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), value);
  if (ec != std::errc{}) throw Json::Invalid("cannot serialize number");
  auto text = std::string_view(buf, static_cast<std::size_t>(end - buf));
  out += text;
  if constexpr (std::same_as<T, double>)
    if (text.find_first_of(".eE") == text.npos) out += ".0";
}

void write(std::string &out, const Json &j, unsigned depth, int indent) {
  if (depth > Json::max_depth) throw Json::Invalid("JSON output nesting limit");
  auto newline = [&](unsigned level) {
    if (indent >= 0) {
      out += '\n';
      out.append(level * static_cast<unsigned>(indent), ' ');
    }
  };
  if (j.is_null()) out += "null";
  else if (j.is_boolean()) out += j.get<bool>() ? "true" : "false";
  else if (j.is_string()) quote(out, j.get_ref<const std::string &>());
  else if (j.is_number_unsigned()) number_text(out, j.get<std::uint64_t>());
  else if (j.is_number_integer()) number_text(out, j.get<std::int64_t>());
  else if (j.is_number()) number_text(out, j.get<double>());
  else {
    const bool object = j.is_object();
    out += object ? '{' : '[';
    bool first = true;
    auto row = [&](const Json &v, const std::string *key) {
      if (!first) out += ',';
      first = false;
      newline(depth + 1);
      if (key) {
        quote(out, *key);
        out += indent >= 0 ? ": " : ":";
      }
      write(out, v, depth + 1, indent);
    };
    if (object) {
      for (const auto &[k, v] : j.items()) row(v, &k);
    } else {
      for (const auto &v : j) row(v, nullptr);
    }
    if (!first) newline(depth);
    out += object ? '}' : ']';
  }
}
} // namespace

Json Json::parse(std::string_view text) { return Reader(text).parse(); }
std::string Json::dump(int indent) const {
  if (indent < -1 || indent > 8)
    throw Invalid("JSON indentation out of range");
  std::string out;
  write(out, *this, 0, indent);
  return out;
}

} // namespace turtle::artifact
