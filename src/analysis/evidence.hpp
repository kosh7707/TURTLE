#pragma once
#include "analysis/analysis.hpp"
#include <algorithm>
#include <cctype>
#include <stdexcept>
namespace turtle::analysis::evidence {
inline void require(bool ok, const char *reason) {
  if (!ok)
    throw std::runtime_error(reason);
}
inline Json missing(const std::string &reason) {
  return artifact::measurement(nullptr, "missing", reason);
}
inline bool available(const Json &m) {
  return m.at("availability") == "available";
}
struct Task {
  std::string name, auth, role, recording;
  bool named_flights;
  std::size_t request, greeting, response;
  explicit Task(const Json &config)
      : name(config.at("scenario")), auth(config.at("auth")),
        role(config.at("measured_role")), recording(config.at("recording")),
        named_flights(config.value("record_contract", "") ==
                      "flight-boundaries.v1") {
    const auto &app = config.at("application");
    request = (name == "S1" || name == "S3" || name == "S4")
                  ? app.at("request").get_ref<const std::string &>().size()
                  : 0;
    greeting = (name == "S2" || name == "S4")
                   ? app.at("greeting").get_ref<const std::string &>().size()
                   : 0;
    response = (name == "S3" || name == "S4")
                   ? app.at("response").get_ref<const std::string &>().size()
                   : 0;
  }
  std::size_t sent(bool client) const {
    return client ? request : greeting + response;
  }
};
inline std::string canonical(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return std::toupper(c); });
  // wolfSSL names TLS 1.3 suites TLS13-AES128-GCM-SHA256, OpenSSL uses
  // TLS_AES_128_GCM_SHA256.
  value.erase(std::remove_if(value.begin(), value.end(),
                             [](char c) { return c == '-' || c == '_'; }),
              value.end());
  if (value.starts_with("TLS13"))
    value.erase(3, 2);
  return value;
}
void collect(const std::filesystem::path &dir, const Task &,
             bool include_capture, bool task_matches, Endpoint &,
             const Json &roles, Json &observations, Json &out);
void annotate_tls_records(const Task &, const Json &roles, Endpoint &,
                          Json &observations);
void collect_tcp_evidence(const std::filesystem::path &dir, const Task &,
                          Endpoint &, Json &observations, Json &out);
} // namespace turtle::analysis::evidence
