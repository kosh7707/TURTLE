#include "native/launch_profile.hpp"
#include "artifact/network_evidence.hpp"
#include "native/evidence.hpp"
#include "process/process.hpp"
#include "profiling/profiling.hpp"
#include <algorithm>
#include <cmath>
#include <iterator>
#include <map>
#include <set>
#include <stdexcept>
#include <unistd.h>
#include <utility>

namespace turtle::native::detail {
using artifact::Json;
using artifact::require_only_fields;
namespace fs = std::filesystem;
namespace {
void require(bool ok, const std::string &why) {
  if (!ok)
    throw std::runtime_error(why);
}
void resolve_participants(Json &p, const fs::path &base, const fs::path &self) {
  require_only_fields(p.at("target"), {"role", "argv"});
  auto role = p.at("target").at("role");
  require(role == "client" || role == "server", "invalid_target_role");
  p["stock_peer"] = !p.contains("peer");
  const auto reference = self.parent_path() / "turtle-reference";
  p["scenario_contract"] = endpoint_contract_id;
  if (p["stock_peer"] == true) {
    const auto peer_role = role == "client" ? "server" : "client";
    p["peer"] = {
        {"argv", Json::array({reference.string(), "--native-stream", peer_role,
                              p.value("auth", "mtls"), "{host}", "{port}"})}};
  } else {
    require_only_fields(p.at("peer"), {"argv"});
  }
  for (auto key : {"target", "peer"}) {
    auto &av = p.at(key).at("argv");
    require(av.is_array() && !av.empty(), "argv_required");
    for (auto &a : av)
      require(a.is_string() && a.get_ref<const std::string &>().find('\0') ==
                                   std::string::npos,
              "invalid_argument");
    auto exe = av.front().get<std::string>();
    require(!exe.empty(), "empty_executable");
    if (exe.find('/') != exe.npos)
      exe = (base / exe).string();
    av.front() = process::executable(exe);
    require(access(av.front().get_ref<const std::string &>().c_str(), X_OK) ==
                0,
            "not_executable:" + exe);
  }
  std::error_code ec;
  require(!fs::equivalent(p["target"]["argv"][0].get<std::string>(), reference,
                          ec),
          "stock_reference_cannot_be_measured_target");
}

void resolve_credentials(Json &p, const fs::path &base) {
  if (!p.contains("credentials"))
    return;
  auto &c = p.at("credentials");
  require_only_fields(c, {"ca", "client", "server", "client_name", "server_name"});
  auto checked = [&](Json &x) {
    auto path = fs::canonical(base / x.get<std::string>());
    require(fs::is_regular_file(path) && access(path.c_str(), R_OK) == 0,
            "invalid_fixture_path");
    x = path.string();
  };
  checked(c.at("ca"));
  for (auto who : {"client", "server"}) {
    if (std::string_view(who) == "client" && p.at("auth") == "server" &&
        !c.contains(who))
      continue;
    auto &identity = c.at(who);
    require_only_fields(identity, {"cert", "key"});
    checked(identity.at("cert"));
    checked(identity.at("key"));
  }
  for (auto key : {"server_name", "client_name"})
    if (c.contains(key)) {
      auto name = c.at(key).get<std::string>();
      require(!name.empty() && name.find('\0') == name.npos,
              "invalid_peer_name");
    }
}

void resolve_expected_negotiation(Json &p) {
  auto expected = p.value("expected", Json::object());
  require_only_fields(expected, {"group", "suite", "cipher"});
  const std::map<std::string, int> groups = {
      {"P-256", 23},     {"prime256v1", 23}, {"secp256r1", 23}, {"P-384", 24},
      {"secp384r1", 24}, {"P-521", 25},      {"secp521r1", 25}, {"X25519", 29},
      {"x25519", 29},    {"X448", 30},       {"x448", 30}};
  const std::map<std::string, int> suites = {
      {"TLS_AES_128_GCM_SHA256", 0x1301},
      {"TLS_AES_256_GCM_SHA384", 0x1302},
      {"TLS_CHACHA20_POLY1305_SHA256", 0x1303},
      {"TLS_AES_128_CCM_SHA256", 0x1304},
      {"TLS_AES_128_CCM_8_SHA256", 0x1305}};
  auto normalized = Json::object();
  for (auto &[key, v] : expected.items()) {
    const auto &aliases = key == "group" ? groups : suites;
    auto canonical = key == "cipher" ? "suite" : key;
    std::uint64_t id = 0;
    if (v.is_string()) {
      auto name = v.get<std::string>();
      require(aliases.contains(name), "unknown_negotiation_name:" + name);
      id = aliases.at(name);
    } else
      id = artifact::integer(v);
    require(id > 0 && id <= 65535, "invalid_negotiation_id");
    require(!normalized.contains(canonical) || normalized[canonical] == id,
            "contradictory_expected_negotiation");
    normalized[canonical] = id;
  }
  p["expected"] = std::move(normalized);
}

void resolve_metrics(Json &p) {
  std::set<std::string> selected;
  for (auto key : {"required_metrics", "optional_metrics"}) {
    auto m = p.value(key, Json::array());
    require(m.is_array(), "metrics_array_required");
    for (auto &v : m) {
      require(v.is_string(), "invalid_metric");
      require(selected.insert(canonical_metric_name(v.get<std::string>())).second,
              "duplicate_metric:" + v.get<std::string>());
    }
    p[key] = m;
  }
  auto measurement = p.value("measurement", Json::object());
  require_only_fields(measurement, {"cpu_samples", "capture"});
  if (measurement.contains("capture"))
    require(measurement["capture"].is_boolean(), "invalid_capture_flag");
  if (selected.contains("capture") || selected.contains("tcp_ack"))
    measurement["capture"] = true;
  if (measurement.contains("cpu_samples") || selected.contains("cpu_samples")) {
    auto options = measurement.value("cpu_samples", Json::object());
    require_only_fields(options, {"event", "frequency_hz", "perf"});
    profiling::validate_settings(options);
    measurement["cpu_samples"] = options;
  }
  p["measurement"] = measurement;
}
} // namespace

std::string canonical_metric_name(const std::string &name) {
  static const std::map<std::string, std::string> aliases = {
      {"scenario_wall_ns", "timing"},
      {"perf_counters", "pmu"},
      {"records", "record_layout"},
      {"headers", "header_layout"},
      {"public_io", "library_io"}};
  static const std::set<std::string> allowed = {
      "timing", "pmu", "task", "peer_task", "authentication", "profile",
      "message_timeline", "ordinary_server_first", "transport_counts",
      "ciphertext_bytes", "record_layout", "timed_records", "header_layout",
      "library_io", "tls_flights", "capture", "tcp_ack", "cpu_samples"};
  auto i = aliases.find(name);
  if (i != aliases.end())
    return i->second;
  require(allowed.contains(name), "unknown_metric:" + name);
  return name;
}

Json normalize_launch_profile(Json p, const fs::path &base, const fs::path &self) {
  require_only_fields(p,
                 {"v", "target", "peer", "scenario", "auth", "timeout_seconds",
                  "warmups", "repetitions", "application", "required_metrics",
                  "optional_metrics", "network", "expected", "recording",
                  "credentials", "measurement", "netem"});
  require(p.at("v") == 1, "native_profile_v1_required");
  resolve_participants(p, base, self);
  p["network"] = p.value("network", "loopback");
  require(p["network"] == "loopback" || p["network"] == "netem",
          "invalid_network");
  require(!p.contains("netem") || p["network"] == "netem",
          "netem_requires_isolated_network");
  if (p["network"] == "netem")
    p["netem"] = artifact::normalized_netem(p.value("netem", Json::object()));
  p["scenario"] = p.value("scenario", "S3");
  p["auth"] = p.value("auth", "mtls");
  constexpr std::string_view scenarios[] = {"S0", "S1", "S2", "S3", "S4"};
  const auto &scenario = p["scenario"].get_ref<const std::string &>();
  require(std::ranges::find(scenarios, scenario) != std::end(scenarios),
          "invalid_scenario");
  require(p["auth"] == "server" || p["auth"] == "mtls", "invalid_auth");
  resolve_credentials(p, base);
  for (auto key : {"warmups", "repetitions"}) {
    auto n = artifact::integer(
        p.value(key, Json(std::string_view(key) == "warmups" ? 1 : 2)));
    require(n <= 100000 && (n || std::string_view(key) == "warmups"),
            "attempt_count_out_of_range");
    p[key] = n;
  }
  auto timeout = p.value("timeout_seconds", 10.0);
  require(std::isfinite(timeout) && timeout > 0 && timeout <= 3600,
          "timeout_out_of_range");
  p["timeout_seconds"] = timeout;
  auto app = p.value("application", Json::object());
  require_only_fields(app, {"request", "greeting", "response"});
  for (auto [key, def] : {std::pair{"request", "ping"},
                         {"greeting", "helo"},
                         {"response", "pong"}}) {
    std::string s = app.value(key, def);
    require(!s.empty() && s.size() <= 16384 && s.find('\0') == s.npos,
            "invalid_application_bytes");
    app[key] = s;
  }
  p["application"] = app;
  resolve_expected_negotiation(p);
  auto rec = p.value("recording", "basic");
  require(rec == "basic" || rec == "detailed", "invalid_recording");
  resolve_metrics(p);
  return p;
}
} // namespace turtle::native::detail
