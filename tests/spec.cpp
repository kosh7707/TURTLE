#include "control/spec.hpp"
#include <iostream>
#include <stdexcept>

using turtle::artifact::Json;
namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

Json resolve(Json options = Json::object()) {
  const Json endpoint = {{"binary", "/bin/true"}};
  Json config = {{"id", "one"}, {"client", endpoint}, {"server", endpoint}};
  config.update(options);
  return turtle::control::resolve_spec(
      {{"configurations", Json::array({config})}});
}

void rejects(const Json &options, const std::string &reason) {
  try {
    resolve(options);
  } catch (const std::exception &e) {
    if (e.what() == reason)
      return;
    throw std::runtime_error("expected " + reason + ", got " + e.what());
  }
  throw std::runtime_error("expected rejection: " + reason);
}

void defaults_and_overrides() {
  const auto spec = resolve();
  const auto &c = spec.at("configurations").at(0);
  require(spec.at("network") == "loopback" && spec.at("baseline") == "one" &&
              c.at("recording") == "basic" && !c.contains("netem"),
          "default configuration");
  require(c.at("application") == Json{{"greeting", "helo"},
                                      {"request", "ping"},
                                      {"response", "pong"}} &&
              c.at("required_metrics") == Json::array({"scenario_wall_ns"}) &&
              c.at("optional_metrics").empty(),
          "default application and metrics");

  const Json netem = {{"mtu", 576},
                      {"client_to_server", {{"loss_pct", 0}}},
                      {"server_to_client", {{"loss_pct", 100}, {"seed", 42}}}};
  const auto detailed =
      resolve({{"recording", "detailed"},
               {"netem", netem},
               {"application", {{"request", "custom"}}},
               {"required_metrics", {"headers", "cpu_samples"}},
               {"optional_metrics", {"perf_counters"}},
               {"measurement", {{"capture", true}, {"custom_option", 7}}}})
          .at("configurations")
          .at(0);
  require(detailed.at("netem") == netem &&
              detailed.at("application").at("request") == "custom",
          "explicit input values preserved");
  require(
      detailed.at("required_metrics") ==
              Json::array({"headers", "cpu_samples", "scenario_wall_ns"}) &&
          detailed.at("optional_metrics") ==
              Json::array({"perf_counters", "records", "public_io", "capture"}),
      "implicit metrics follow explicit metrics without duplicates");
  require(detailed.at("measurement") == Json{{"capture", true},
                                             {"custom_option", 7},
                                             {"perf_counters", true},
                                             {"cpu_samples", Json::object()}},
          "explicit and implicit measurement settings");
}

void invalid_settings() {
  const Json bad_netem = {{"server_to_client", {{"loss_pct", 100.01}}}};
  rejects({{"application", {{"unknown", 1}, {"request", ""}}},
           {"netem", bad_netem}},
          "unknown_application_field:unknown");
  rejects({{"netem", bad_netem}, {"measurement", false}},
          "invalid_netem_value");
  rejects({{"measurement", false}, {"required_metrics", {"unknown"}}},
          "invalid_measurement_options");
  rejects(
      {{"required_metrics", {"headers"}}, {"optional_metrics", {"headers"}}},
      "unknown_or_duplicate_metric:headers");
  rejects({{"optional_metrics", {"scenario_wall_ns"}}},
          "scenario_wall_ns_is_required");
}
} // namespace

int main() {
  try {
    defaults_and_overrides();
    invalid_settings();
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
