#include "control/spec.hpp"
#include "capture/capture.hpp"
#include "profiling/profiling.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <set>
#include <unistd.h>
namespace turtle::control {
namespace fs = std::filesystem;
namespace {
void require(bool ok, const std::string &reason) {
  if (!ok)
    throw std::runtime_error(reason);
}
bool has(const Json &list, const std::string &value) {
  return std::find(list.begin(), list.end(), value) != list.end();
}
void choice(Json &c, const char *key, const char *fallback,
            const std::set<std::string> &allowed) {
  auto s = c.value(key, std::string(fallback));
  require(allowed.contains(s), std::string("invalid_") + key);
  c[key] = s;
}
std::string string_arg(const Json &arg) {
  auto s = arg.get<std::string>();
  require(s.find('\0') == std::string::npos, "NUL_in_argument");
  return s;
}
void validate_endpoint(Json &ep) {
  auto name = string_arg(ep.at("binary"));
  require(!name.empty(), "empty_binary");
  try {
    ep["binary"] = process::executable(name);
  } catch (const std::exception &) { /* preflight reports this configuration */
  }
  auto args = ep.value("args", Json::array()),
       env = ep.value("env", Json::object());
  require(args.is_array() && env.is_object(), "invalid_endpoint_arguments");
  for (const auto &arg : args)
    string_arg(arg);
  for (const auto &[k, v] : env.items()) {
    require(!k.empty() && k.find('=') == std::string::npos &&
                k.find('\0') == std::string::npos,
            "invalid_environment_key");
    string_arg(v);
  }
}
Json resolve_application(Json app) {
  static const std::map<std::string, std::string> defaults{
      {"greeting", "helo"}, {"request", "ping"}, {"response", "pong"}};
  require(app.is_object(), "invalid_application");
  for (const auto &field : app.items())
    require(defaults.contains(field.key()),
            "unknown_application_field:" + field.key());
  for (const auto &[key, fallback] : defaults) {
    auto value = string_arg(app.value(key, Json(fallback)));
    require(!value.empty() && value.size() <= 16384,
            "application_size_out_of_range");
    app[key] = std::move(value);
  }
  return app;
}
void validate_netem(const Json &netem) {
  require(netem.is_object(), "invalid_netem_settings");
  const auto mtu = artifact::integer(netem.value("mtu", Json(1500)));
  require(mtu >= 576 && mtu <= 65535, "invalid_netem_mtu");
  for (auto direction : {"client_to_server", "server_to_client"}) {
    const auto rule = netem.value(direction, Json::object());
    require(rule.is_object(), "invalid_netem_direction");
    for (auto key : {"delay_ms", "loss_pct", "rate_mbit"}) {
      auto n = rule.value(key, 0.0);
      require(std::isfinite(n) && n >= 0 &&
                  (std::string_view(key) != "loss_pct" || n <= 100),
              "invalid_netem_value");
    }
    require(artifact::integer(rule.value("limit", Json(10000))) > 0 &&
                artifact::integer(rule.value("seed", Json(0))) <= UINT32_MAX,
            "invalid_netem_limit_or_seed");
  }
}
void resolve_measurement(Json &config) {
  static const std::set<std::string> allowed{
      "scenario_wall_ns", "records",       "public_io",  "headers",
      "capture",          "perf_counters", "cpu_samples"};
  auto options = config.value("measurement", Json::object());
  require(options.is_object(), "invalid_measurement_options");
  for (auto key : {"capture", "perf_counters"})
    require(options.value(key, Json(false)).is_boolean(),
            "invalid_measurement_options");
  if (options.contains("cpu_samples"))
    profiling::validate_settings(options.at("cpu_samples"));

  std::set<std::string> selected;
  for (auto key : {"required_metrics", "optional_metrics"}) {
    auto list = config.value(key, Json::array());
    require(list.is_array(), "metric_list_required");
    for (const auto &entry : list) {
      auto name = entry.get<std::string>();
      require(allowed.contains(name) && selected.insert(name).second,
              "unknown_or_duplicate_metric:" + name);
    }
    config[key] = std::move(list);
  }
  require(!has(config.at("optional_metrics"), "scenario_wall_ns"),
          "scenario_wall_ns_is_required");
  if (selected.insert("scenario_wall_ns").second)
    config["required_metrics"].push_back("scenario_wall_ns");

  // Keep explicit order; inferred metrics follow in recording/observer order.
  auto add_optional = [&](const char *name) {
    if (selected.insert(name).second)
      config["optional_metrics"].push_back(name);
  };
  if (config.at("recording") == "detailed")
    for (auto name : {"records", "public_io", "headers"})
      add_optional(name);
  for (auto name : {"capture", "perf_counters"})
    if (options.value(name, false))
      add_optional(name);
  if (options.contains("cpu_samples"))
    add_optional("cpu_samples");

  if (selected.contains("cpu_samples") && !options.contains("cpu_samples"))
    options["cpu_samples"] = Json::object();
  for (auto key : {"perf_counters", "capture"})
    options[key] = selected.contains(key);
  config["measurement"] = std::move(options);
}
bool netem_permissions() {
  // Netns mount/creation and veth/qdisc configuration require both
  // capabilities.
  std::ifstream status("/proc/self/status");
  for (std::string line; std::getline(status, line);)
    if (line.starts_with("CapEff:")) {
      auto bits = std::stoull(line.substr(7), nullptr, 16);
      return (bits & (1ULL << 21)) && (bits & (1ULL << 12));
    }
  return false;
}
} // namespace
bool requested(const Json &c, const std::string &name) {
  return has(c.at("required_metrics"), name) ||
         has(c.at("optional_metrics"), name);
}
bool server_first(const Json &c) {
  return c.at("scenario") == "S2" || c.at("scenario") == "S4";
}
Json resolve_spec(Json spec) {
  auto &configs = spec.at("configurations");
  require(configs.is_array() && !configs.empty(), "configurations_required");
  auto reps = artifact::integer(spec.value("repetitions", Json(30)));
  auto warmups = artifact::integer(spec.value("warmups", Json(1)));
  auto seed = artifact::integer(spec.value("seed", Json(0)));
  auto timeout = spec.value("timeout_seconds", 30.0);
  require(reps > 0 && std::isfinite(timeout) && timeout > 0 && timeout <= 3600,
          "invalid_repetitions_or_timeout");
  choice(spec, "network", "loopback", {"loopback", "netem"});
  std::set<std::string> ids;
  for (auto &c : configs) {
    auto id = string_arg(c.at("id"));
    require(!id.empty() && ids.insert(id).second,
            "configuration_ids_must_be_nonempty_and_unique");
    for (auto role : {"client", "server"})
      validate_endpoint(c.at(role));
    choice(c, "scenario", "S3", {"S0", "S1", "S2", "S3", "S4"});
    choice(c, "auth", "server", {"server", "mtls"});
    choice(c, "measured_role", "client", {"client", "server"});
    choice(c, "recording", "basic", {"off", "basic", "detailed"});
    c["warmups"] = artifact::integer(c.value("warmups", Json(warmups)));
    for (auto key : {"app_chunk", "io_chunk"})
      c[key] = artifact::integer(c.value(key, Json(0)));
    c["application"] =
        resolve_application(c.value("application", Json::object()));
    validate_netem(c.value("netem", Json::object()));
    auto inputs = c.value("inputs", Json::array());
    require(inputs.is_array(), "invalid_inputs");
    for (const auto &path : inputs)
      string_arg(path);
    auto expected = c.value("expected", Json::object());
    require(expected.is_object(), "invalid_expected_negotiation");
    for (const auto &[k, v] : expected.items())
      require((k == "group" || k == "cipher") && !string_arg(v).empty(),
              "invalid_expected_negotiation");
    c["expected"] = expected;
    resolve_measurement(c);
    c["io_path"] = "raw_tls_tcp";
  }
  auto baseline =
      spec.value("baseline", configs.front().at("id").get<std::string>());
  require(ids.contains(baseline), "unknown_baseline");
  spec.update({{"repetitions", reps},
               {"warmups", warmups},
               {"seed", seed},
               {"baseline", baseline},
               {"timeout_seconds", timeout}});
  return spec;
}
process::Args endpoint_args(const Json &c, const std::string &role,
                            const std::string &purpose, process::Args flags) {
  process::Args a = {c.at(role).at("binary"),
                     "--role",
                     role,
                     "--purpose",
                     purpose,
                     "--scenario",
                     c.at("scenario"),
                     "--auth",
                     c.at("auth"),
                     "--measured-role",
                     c.at("measured_role"),
                     "--recording",
                     c.at("recording"),
                     "--app-chunk",
                     c.at("app_chunk").dump(),
                     "--io-chunk",
                     c.at("io_chunk").dump()};
  for (const auto &[k, v] : c.at("application").items()) {
    a.push_back("--" + k);
    a.push_back(v.get<std::string>());
  }
  a.insert(a.end(), flags.begin(), flags.end());
  a.push_back("--");
  for (const auto &arg : c.at(role).value("args", Json::array()))
    a.push_back(arg.get<std::string>());
  return a;
}
Json preflight(const Json &spec, int cancel) {
  Json checks = Json::object();
  bool ready = true;
  for (const auto &c : spec.at("configurations")) {
    Json reasons = Json::array(), features = Json::object(),
         endpoints = Json::object();
    bool detailed = c.at("recording") == "detailed";
    for (auto role : {"client", "server"}) {
      try {
        bool measured = c.at("measured_role") == role;
        process::Args flags{"--check"};
        if (measured && requested(c, "perf_counters"))
          flags.push_back("--perf-counters");
        auto r = process::command(
            endpoint_args(c, role, "measurement", flags),
            spec.at("timeout_seconds"),
            c.at(role).value("env", process::Environment{}), cancel);
        if (r.at("returncode") != 0)
          throw std::runtime_error(
              "endpoint_check_failed:" + r.at("stderr").get<std::string>() +
              r.at("stdout").get<std::string>());
        auto ep = Json::parse(r.at("stdout").get<std::string>());
        require(ep.at("ready") == true, "adapter_prepare_failed");
        endpoints[role] = ep;
        if (std::string_view(role) == "server" && server_first(c) &&
            ep.at("server_first") != true)
          reasons.push_back("server_first_adapter_unavailable");
        if (measured) {
          for (auto name : {"headers", "public_io"})
            features[name] = {
                {"availability",
                 detailed && ep.at(name) == true ? "available" : "unsupported"},
                {"reason", !detailed ? "detailed_recording_disabled"
                           : ep.at(name) == true
                               ? Json(nullptr)
                               : Json("adapter_hook_unavailable")}};
          if (requested(c, "perf_counters"))
            features["perf_counters"] = {
                {"availability",
                 ep.at("perf_counters") == true ? "available" : "unsupported"},
                {"reason", ep.at("perf_reason")}};
        }
      } catch (const std::exception &e) {
        endpoints[role] = {{"ready", false}, {"reason", e.what()}};
        reasons.push_back(std::string(role) + ":" + e.what());
      }
    }
    for (const auto &path : c.value("inputs", Json::array()))
      if (!fs::is_regular_file(path.get<std::string>()) ||
          ::access(path.get<std::string>().c_str(), R_OK))
        reasons.push_back("input_unreadable:" + path.get<std::string>());
    if (spec.at("network") == "netem") {
      try {
        for (auto name : {"ip", "tc", "ethtool", "sysctl"})
          process::executable(name);
        require(netem_permissions(), "netem_requires_net_admin_and_sys_admin");
      } catch (const std::exception &e) {
        reasons.push_back(e.what());
      }
    }
    bool clock_ready = endpoints.at(c.at("measured_role").get<std::string>())
                           .value("monotonic_clock", false);
    features["scenario_wall_ns"] = {
        {"availability", clock_ready ? "available" : "missing"},
        {"reason",
         clock_ready ? Json(nullptr) : Json("endpoint_clock_not_confirmed")}};
    features["records"] = {
        {"availability", detailed ? "available" : "unsupported"},
        {"reason",
         detailed ? Json(nullptr) : Json("detailed_recording_disabled")}};
    if (requested(c, "capture")) {
      features["capture"] =
          detailed ? capture::probe("lo")
                   : Json{{"availability", "unsupported"},
                          {"reason",
                           "raw_byte_correlation_requires_detailed_recording"}};
    }
    if (requested(c, "cpu_samples"))
      features["cpu_samples"] =
          profiling::probe(c.at("measurement").at("cpu_samples"), cancel);
    for (const auto &name : c.at("required_metrics"))
      if (features.value(name.get<std::string>(), Json::object())
              .value("availability", "") != "available")
        reasons.push_back("required_metric_unavailable:" +
                          name.get<std::string>());
    checks[c.at("id").get<std::string>()] = {{"ready", reasons.empty()},
                                             {"reasons", reasons},
                                             {"endpoints", endpoints},
                                             {"features", features}};
    ready = ready && reasons.empty();
  }
  return {{"schema", "turtle.check.v1"},
          {"ready", ready},
          {"connection_verified", false},
          {"configurations", checks}};
}
} // namespace turtle::control
