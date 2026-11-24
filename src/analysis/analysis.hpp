#pragma once
#include "artifact/json.hpp"
#include <array>
#include <map>
namespace turtle::analysis {
using artifact::Bytes;
using artifact::Json;
struct Endpoint {
  Json summary, events, records, links, metrics, phases;
  std::map<std::string, Bytes> streams;
};
using Endpoints = std::map<std::string, Endpoint>;
inline constexpr std::array<const char *, 4> phase_names{
    "client_hello", "server_hello", "server_auth", "client_finished"};
inline constexpr std::array<const char *, 4> phase_labels{
    "ClientHello", "ServerHello",
    "EncryptedExtensions + Certificate + CertificateVerify + Finished",
    "Client Finished"};
inline constexpr std::array<const char *, 4> senders{"client", "server",
                                                     "server", "client"};
inline constexpr std::array<const char *, 2> clocks{"wall_ns", "thread_cpu_ns"};
template <class F> Json select(const Json &rows, F predicate) {
  Json result = Json::array();
  for (const auto &r : rows)
    if (predicate(r))
      result.push_back(r);
  return result;
}
const Json &handshake(const Endpoint &);
std::string flow(const std::string &, const std::string &);
Endpoint endpoint(const std::filesystem::path &);
Json phases(Endpoints &, const Json &captures, const Json &network,
            bool success);
Json counters(const std::filesystem::path &, const Endpoint &);
Json counter_delta(const Json &, const Json &, const std::string &,
                   Json reason = nullptr);
Json attempt(const std::filesystem::path &, Json error = nullptr);
Json finished_boundary(const Json &records, std::uint64_t application_bytes,
                       const std::string &cipher, bool declared_unpadded_tail);
bool is_hello_retry(const Bytes &hello);
Json assess(const std::filesystem::path &, const Json &config,
            const Json &scheduled, Json *image_baselines = nullptr);
bool regenerate_lifecycle(const std::filesystem::path &, const Json &manifest);
std::filesystem::path attempt_directory(const std::filesystem::path &root,
                                        const std::filesystem::path &declared);
bool regenerate(const std::filesystem::path &);
} // namespace turtle::analysis
