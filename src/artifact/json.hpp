#pragma once
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
namespace turtle::artifact {
using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
Json load(const std::filesystem::path &);
void save(const std::filesystem::path &, const Json &);
Bytes read_bytes(const std::filesystem::path &);
std::string read_text(const std::filesystem::path &);
void write_text(const std::filesystem::path &, const std::string &);
std::uint64_t integer(const Json &);
Json measurement(Json value = nullptr, std::string availability = "available",
                 Json reason = nullptr);
Json interval(const Json &begin, const Json &end);
} // namespace turtle::artifact
