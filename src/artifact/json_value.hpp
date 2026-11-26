#pragma once

#include <concepts>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace turtle::artifact {

// Values used by TURTLE's versioned profiles and legacy evidence artifacts.
// Exact integer storage matters: timestamps and counters often exceed 2^53.
class Json {
public:
  using Array = std::vector<Json>;
  using Object = std::map<std::string, Json, std::less<>>;
  static constexpr std::size_t max_text_bytes = 128 * 1024 * 1024;
  static constexpr unsigned max_depth = 64;

  Json() = default;
  Json(std::nullptr_t) {}
  Json(bool b) : data_(b) {}
  template <std::integral T> requires (!std::same_as<T, bool>)
  Json(T n) : data_(static_cast<std::conditional_t<std::is_signed_v<T>,
                                                  std::int64_t, std::uint64_t>>(n)) {}
  Json(double n);
  Json(const char *s) : data_(std::string(s)) {}
  Json(std::string s) : data_(std::move(s)) {}
  Json(std::string_view s) : data_(std::string(s)) {}
  Json(Array a) : data_(std::move(a)) {}
  Json(Object o) : data_(std::move(o)) {}
  Json(const std::vector<std::string> &a);
  Json(const std::map<std::string, std::string> &o);
  Json(std::initializer_list<Json> rows);

  static Json object() { return Object{}; }
  static Json array(Array values = {}) { return values; }
  static Json parse(std::string_view text);
  // Only syntax/data errors are handled by optional legacy consumers.
  class Invalid : public std::runtime_error { using std::runtime_error::runtime_error; };
  std::string dump(int indent = -1) const;

  bool is_null() const { return holds<std::nullptr_t>(); }
  bool is_boolean() const { return holds<bool>(); }
  bool is_string() const { return holds<std::string>(); }
  bool is_array() const { return holds<Array>(); }
  bool is_object() const { return holds<Object>(); }
  bool is_number_unsigned() const { return holds<std::uint64_t>(); }
  bool is_number_integer() const { return holds<std::int64_t>() || is_number_unsigned(); }
  bool is_number() const { return is_number_integer() || holds<double>(); }
  std::size_t size() const;
  bool empty() const { return size() == 0; }
  const Json *find_member(std::string_view key) const;
  bool contains(std::string_view key) const { return find_member(key) != nullptr; }

  Object &items() { return as<Object>(); }
  const Object &items() const { return as<Object>(); }
  Array &elements() { return as<Array>(); }
  const Array &elements() const { return as<Array>(); }
  auto begin() { return elements().begin(); }
  auto end() { return elements().end(); }
  auto begin() const { return elements().begin(); }
  auto end() const { return elements().end(); }
  Json &front() { return elements().front(); }
  const Json &front() const { return elements().front(); }
  Json &back() { return elements().back(); }
  const Json &back() const { return elements().back(); }
  using Iterator = Array::iterator;
  void erase(Iterator p) { elements().erase(p); }
  void erase(Iterator p, Iterator q) { elements().erase(p, q); }
  void erase(std::size_t i) { at(i); erase(begin() + i); }
  void erase(std::string_view k);
  void insert(Iterator p, Json value) { elements().insert(p, std::move(value)); }
  void push_back(Json value);
  void update(const Json &object);

  Json &at(std::string_view key);
  const Json &at(std::string_view key) const;
  Json &at(std::size_t i) { return elements().at(i); }
  const Json &at(std::size_t i) const { return elements().at(i); }
  Json &operator[](std::string_view key);
  const Json &operator[](std::string_view key) const { return at(key); }
  Json &operator[](std::size_t index);
  const Json &operator[](std::size_t index) const { return at(index); }

  template <typename Ref> Ref get_ref() const { return as<std::remove_cvref_t<Ref>>(); }
  template <typename Ref> Ref get_ref() { return as<std::remove_cvref_t<Ref>>(); }
  template <typename T> T get() const {
    if constexpr (std::same_as<T, Json>) {
      return *this;
    } else if constexpr (std::same_as<T, std::vector<std::string>>) {
      T result;
      for (const auto &value : elements())
        result.push_back(value.get<std::string>());
      return result;
    } else if constexpr (std::same_as<T, std::map<std::string, std::string>>) {
      T result;
      for (const auto &[key, value] : items())
        result.emplace(key, value.get<std::string>());
      return result;
    } else if constexpr (std::integral<T> && !std::same_as<T, bool>) {
      if (const auto *i = std::get_if<std::int64_t>(&data_)) {
        if (std::in_range<T>(*i))
          return static_cast<T>(*i);
      } else if (const auto *u = std::get_if<std::uint64_t>(&data_)) {
        if (std::in_range<T>(*u))
          return static_cast<T>(*u);
      }
      throw std::runtime_error("JSON integer out of range or wrong type");
    } else if constexpr (std::same_as<T, double>) {
      if (const auto *i = std::get_if<std::int64_t>(&data_))
        return static_cast<double>(*i);
      if (const auto *u = std::get_if<std::uint64_t>(&data_))
        return static_cast<double>(*u);
      return as<double>();
    } else {
      return as<T>();
    }
  }
  template <typename T> T value(std::string_view key, T fallback) const {
    auto it = items().find(key);
    return it == items().end() ? std::move(fallback) : it->second.get<T>();
  }
  std::string value(std::string_view key, const char *fallback) const {
    return value(key, std::string(fallback));
  }

  friend bool operator==(const Json &a, const Json &b);
  friend std::ostream &operator<<(std::ostream &out, const Json &value) {
    return out << value.dump();
  }

private:
  template <typename T> bool holds() const { return std::holds_alternative<T>(data_); }
  template <typename T> T &as() {
    if (auto *v = std::get_if<T>(&data_))
      return *v;
    throw std::runtime_error("wrong JSON value type");
  }
  template <typename T> const T &as() const {
    if (auto *v = std::get_if<T>(&data_))
      return *v;
    throw std::runtime_error("wrong JSON value type");
  }

  using Storage = std::variant<std::nullptr_t, bool, std::int64_t,
                               std::uint64_t, double, std::string, Array, Object>;
  Storage data_{nullptr};
};

} // namespace turtle::artifact
