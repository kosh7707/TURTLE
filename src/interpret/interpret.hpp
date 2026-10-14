#pragma once
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <span>
#include <string_view>
namespace turtle::interpret {
// Inputs are complete directional streams, not packet boundaries.
nlohmann::json decode(std::span<const std::uint8_t> client_sent,
                      std::span<const std::uint8_t> server_sent, std::string_view keylog);
nlohmann::json analyze(const std::filesystem::path& role_jsonl,
                       const std::filesystem::path& output_json);
} // namespace turtle::interpret
