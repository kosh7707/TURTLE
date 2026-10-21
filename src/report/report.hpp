#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <span>
#include <vector>
namespace turtle::report {
struct Statistics {
    std::size_t count = 0;
    double minimum = 0, maximum = 0;
    std::array<double, 3> stq{};
};
Statistics statistics(std::span<const double> values);
struct Comparison {
    double difference = 0;
    double lower = 0, upper = 0;
    bool distinguishable = false;
};
Comparison compare(std::span<const double> a, std::span<const double> b, std::uint64_t seed = 1,
                   std::size_t repetitions = 2000);
nlohmann::json partition(const nlohmann::json& header, const std::vector<nlohmann::json>& events);
nlohmann::json summarize_lookup(const std::filesystem::path& input,
                                const std::filesystem::path& output);
nlohmann::json summarize(const std::filesystem::path& input, const std::filesystem::path& output,
                         bool repeated_context = false);
} // namespace turtle::report
