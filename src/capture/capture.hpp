#pragma once
#include "artifact/json.hpp"
#include <map>
#include <span>
namespace turtle::capture {
using artifact::Bytes;
using artifact::Json;
using Range = std::pair<std::uint64_t, std::uint64_t>;
using Ranges = std::vector<Range>;
artifact::Json range_rows(const Ranges &);
Ranges overlap(const Ranges &, std::uint64_t, std::uint64_t);
void merge(Ranges &, std::uint64_t, std::uint64_t);
Json records(std::span<const unsigned char> wire);
Json raw_records(std::span<const unsigned char> wire);
void verify_tls(std::span<const unsigned char> wire,
                std::span<const unsigned char> tls);
Json mapping(const Json &, std::uint64_t, std::uint64_t);
Json analyze(const std::filesystem::path &,
             const std::map<std::string, Bytes> &,
             const std::map<std::string, std::uint64_t> &, const std::string &,
             const std::string &, bool raw_tls = false);
Json probe(const std::string &interface);
int collect(const std::string &interface, const std::filesystem::path &output,
            const std::filesystem::path &status, unsigned server_port = 0);
} // namespace turtle::capture
