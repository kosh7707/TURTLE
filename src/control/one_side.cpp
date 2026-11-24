#include "control/one_side.hpp"
#include "process/process.hpp"
#include <algorithm>
#include <cstdlib>
#include <set>
#include <unistd.h>
namespace turtle::control {
using artifact::Json;
namespace fs = std::filesystem;
namespace {
void fields(const Json &obj, const std::set<std::string> &allowed) {
  if (!obj.is_object())
    throw std::runtime_error("object_required");
  for (const auto &[key, value] : obj.items())
    if (!allowed.contains(key))
      throw std::runtime_error("unknown_one_sided_option:" + key);
}
bool contains(const Json &list, const char *key) {
  return std::find(list.begin(), list.end(), key) != list.end();
}
} // namespace
Json one_side(const Json &input, const fs::path &base,
              const fs::path &controller) {
  fields(input, {"v", "target", "scenario", "auth", "warmups", "repetitions",
                 "timeout_seconds", "application", "expected", "recording",
                 "required_metrics", "optional_metrics", "measurement",
                 "network", "netem", "app_chunk", "io_chunk"});
  if (input.at("v") != 1)
    throw std::runtime_error("unknown_one_sided_version");
  const auto &target = input.at("target");
  fields(target, {"role", "argv"});
  auto role = target.at("role").get<std::string>();
  if (role != "client" && role != "server")
    throw std::runtime_error("invalid_target_role");
  const auto &args = target.at("argv");
  if (!args.is_array() || args.empty())
    throw std::runtime_error("target_argv_required");
  for (const auto &v : args)
    if (!v.is_string() ||
        v.get_ref<const std::string &>().find('\0') != std::string::npos)
      throw std::runtime_error("invalid_target_argv");
  if (args.front().get_ref<const std::string &>().empty())
    throw std::runtime_error("empty_target");
  Json dut = {
      {"binary",
       (base / args.front().get<std::string>()).lexically_normal().string()},
      {"args", Json(args.begin() + 1, args.end())}};
  Json stock = {
      {"binary", (controller.parent_path() / "turtle-reference").string()},
      {"args", Json::array()}};
  if (input.contains("expected") && input.at("expected").contains("group"))
    stock["args"] = {"--groups", input.at("expected").at("group")};
  Json config = {{"id", "target"},
                 {"measured_role", role},
                 {"measurement_contract", "counts-enough.v1"},
                 {"scenario", input.value("scenario", "S3")},
                 {"auth", input.value("auth", "mtls")},
                 {role, dut},
                 {role == "client" ? "server" : "client", stock},
                 {"probe_client", stock}};
  for (const char *key :
       {"application", "expected", "recording", "required_metrics",
        "optional_metrics", "measurement", "netem", "app_chunk", "io_chunk"})
    if (input.contains(key))
      config[key] = input.at(key);
  if (config.value("recording", "basic") == "off")
    throw std::runtime_error("basic_run_requires_call_boundaries");
  auto required = config.value("required_metrics", Json::array());
  if (!required.is_array())
    throw std::runtime_error("metric_list_required");
  for (auto key : {"scenario_wall_ns", "perf_counters"})
    if (!contains(required, key))
      required.push_back(key);
  config["required_metrics"] = required;
  if (input.contains("netem") && input.value("network", "netem") != "netem")
    throw std::runtime_error("netem_requested_on_loopback");
  Json spec = {
      {"configurations", Json::array({config})},
      {"repetitions", input.value("repetitions", Json(2))},
      {"network",
       input.value("network", input.contains("netem") ? "netem" : "loopback")}};
  for (auto key : {"warmups", "timeout_seconds"})
    if (input.contains(key))
      spec[key] = input.at(key);
  return spec;
}
TrialIdentities::~TrialIdentities() {
  if (!directory_.empty()) {
    std::error_code ignored;
    fs::remove_all(directory_, ignored);
  }
}
void TrialIdentities::export_public(const fs::path &output) const {
  if (directory_.empty())
    return;
  fs::create_directory(output / "certificates");
  for (auto name : {"ca.crt", "client.crt", "server.crt"})
    fs::copy_file(directory_ / "leaves" / name, output / "certificates" / name);
}
void TrialIdentities::prepare(Json &spec, const fs::path &controller,
                              int cancel) {
  for (auto &cfg : spec.at("configurations")) {
    if (cfg.value("measurement_contract", "") != "counts-enough.v1")
      continue;
    if (directory_.empty()) {
      auto path =
          (fs::temp_directory_path() / "turtle-identity-XXXXXX").string();
      if (!::mkdtemp(path.data()))
        throw std::runtime_error("private_fixture_directory_failed");
      directory_ = fs::absolute(path);
      auto cmd = process::command(
          {"/bin/sh",
           (controller.parent_path() / "turtle-issue-test-leaves.sh").string(),
           (directory_ / "leaves").string()},
          30, {}, cancel);
      if (cmd.at("returncode") != 0)
        throw std::runtime_error("local_test_identity_issuance_failed:" +
                                 cmd.at("stderr").get<std::string>());
    }
    auto base = directory_ / "leaves";
    for (auto who : {"client", "server", "probe_client"}) {
      bool server = std::string_view(who) == "server",
           mutual = cfg.at("auth") == "mtls";
      auto key = server ? "server" : "client";
      auto &ep = cfg.at(who);
      auto &env = ep["env"];
      env["TURTLE_CA"] = !server || mutual ? (base / "ca.crt").string() : "";
      env["TURTLE_CERT"] =
          server || mutual ? (base / (std::string(key) + ".crt")).string() : "";
      env["TURTLE_KEY"] =
          server || mutual ? (base / (std::string(key) + ".key")).string() : "";
      env["TURTLE_PEER_NAME"] = !server  ? "localhost"
                                : mutual ? "client.turtle.test"
                                         : "";
      auto hash = process::digest(ep.at("binary").get<std::string>());
      if (spec.contains("retry_of") && cfg.at("build_sha256").at(who) != hash)
        throw std::runtime_error("retry_endpoint_binary_changed");
      cfg["build_sha256"][who] = hash;
    }
    for (auto name : {"ca", "client", "server"})
      cfg["fixture_sha256"][name] =
          process::digest(base / (std::string(name) + ".crt"));
  }
}
} // namespace turtle::control
