#pragma once
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include "artifact/json_value.hpp"
#include <string>
#include <string_view>
#include <vector>
namespace turtle::artifact {
using Bytes = std::vector<unsigned char>;
Json load(const std::filesystem::path &);
void require_only_fields(const Json &object,
                         std::initializer_list<std::string_view> allowed);
void save(const std::filesystem::path &, const Json &);
Bytes read_bytes(const std::filesystem::path &);
std::string read_text(const std::filesystem::path &);
void write_text(const std::filesystem::path &, const std::string &);
std::uint64_t integer(const Json &);
Json measurement(Json value = nullptr, std::string availability = "available",
                 Json reason = nullptr);
Json interval(const Json &begin, const Json &end);
} // namespace turtle::artifact
