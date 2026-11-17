#include "control/controller.hpp"
#include "analysis/analysis.hpp"
#include "build_info.hpp"
#include "control/network.hpp"
#include "profiling/profiling.hpp"
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <poll.h>
#include <random>
#include <set>
#include <sstream>
#include <sys/utsname.h>
#include <unistd.h>
namespace turtle::control {
using artifact::Json;
namespace fs = std::filesystem;
Json run_pair(const Json &config, const fs::path &directory,
              const std::string &run_id,
              const std::map<std::string, Args> &prefixes,
              const std::string &host, double timeout, int cancel) {
  auto root = fs::absolute(directory);
  fs::create_directories(root);
  std::map<std::string, std::unique_ptr<Child>> children;
  Json commands = Json::object(), codes = Json::object(), error = nullptr;
  std::map<std::string, std::string> controls;
  auto end = deadline(timeout);
  auto measurement = config.value("measurement", Json::object());
  bool profile = measurement.contains("cpu_samples");
  auto launch = [&](const std::string &role, unsigned port) {
    auto target = root / role;
    fs::create_directory(target);
    auto ep = config.at(role);
    Args args = prefixes.contains(role) ? prefixes.at(role) : Args{};
    if (profile) {
      auto p = profiling::prepare(target, measurement.at("cpu_samples"));
      args.insert(args.end(), p.begin(), p.end());
    }
    Args rest = {ep.at("binary"),
                 "--role",
                 role,
                 "--host",
                 host,
                 "--port",
                 std::to_string(port),
                 "--output",
                 target.string(),
                 "--run-id",
                 run_id,
                 "--controlled",
                 "--timeout",
                 std::to_string(std::max(1, static_cast<int>(timeout))),
                 "--io-chunk",
                 config.value("io_chunk", Json(0)).dump()};
    args.insert(args.end(), rest.begin(), rest.end());
    if (measurement.value("perf_counters", false))
      args.push_back("--perf-counters");
    if (profile)
      args.push_back("--cpu-samples");
    args.push_back("--");
    for (const auto &a : ep.value("args", Json::array()))
      args.push_back(a.get<std::string>());
    Environment env = profile ? profiling::environment(target) : Environment{};
    auto environment_options = ep.value("env", Json::object());
    for (const auto &[k, v] : environment_options.items())
      env[k] = v.get<std::string>();
    if (profile)
      env["DEBUGINFOD_URLS"] = "";
    commands[role] = args;
    children[role] = std::make_unique<Child>(args, env, target / "stderr.log");
  };
  auto line = [&](const std::string &role, const std::string &prefix) {
    auto s = children.at(role)->line(end, cancel);
    controls[role] += s + "\n";
    if (!s.starts_with(prefix))
      throw std::runtime_error(role + ":expected_" + prefix + ":received_" + s);
    return s;
  };
  try {
    launch("server", 0);
    auto listen = line("server", "LISTEN ");
    auto port = std::stoul(listen.substr(7));
    if (port > 65535)
      throw std::runtime_error("invalid_listen_port");
    launch("client", static_cast<unsigned>(port));
    line("server", "READY");
    line("client", "READY");
    for (auto role : {"server", "client"}) {
      children.at(role)->send("START\n");
      children.at(role)->close_input();
    }
    for (auto &[role, p] : children) {
      codes[role] = p->wait(end, cancel);
      if (codes.at(role) != 0)
        error = "endpoint_failed";
    }
  } catch (const std::exception &e) {
    error = e.what();
  }
  for (auto &[role, p] : children) {
    codes[role] = p->stop();
    try {
      controls[role] += p->collect(deadline(2));
    } catch (const std::exception &e) {
      if (error.is_null())
        error = e.what();
    }
    artifact::write_text(root / role / "control.log", controls[role]);
    if (fs::exists(root / role / "profile.json"))
      profiling::finish(root / role, codes.at(role).get<int>());
  }
  Json result = {{"run_id", run_id},
                 {"error", error},
                 {"commands", commands},
                 {"measurement", measurement},
                 {"returncodes", codes}};
  artifact::save(root / "processes.json", result);
  return result;
}
namespace {
Json provenance(const Json &spec, const std::string &self) {
  utsname os{};
  if (uname(&os))
    throw std::runtime_error("uname_failed");
  Json p = {{"working_directory", fs::current_path().string()},
            {"kernel",
             {{"sysname", os.sysname},
              {"release", os.release},
              {"version", os.version},
              {"machine", os.machine}}},
            {"framework",
             {{"source_sha256", TURTLE_SOURCE_SHA256},
              {"compiler", TURTLE_COMPILER},
              {"sha256", digest(self)}}},
            {"binaries", Json::object()},
            {"inputs_sha256", Json::object()},
            {"tools", Json::array()},
            {"dependency_provenance",
             spec.value("dependency_provenance", Json::array())},
            {"inherited_environment", Json::object()}};
  for (const auto &c : spec.at("configurations")) {
    for (auto role : {"client", "server"}) {
      std::string path = c.at(role).at("binary");
      p["binaries"][path] = {{"sha256", digest(path)},
                             {"dynamic_libraries", command({"ldd", path})}};
    }
    for (const auto &path : c.value("inputs", Json::array()))
      p["inputs_sha256"][path.get<std::string>()] =
          digest(path.get<std::string>());
  }
  for (auto name : {"OPENSSL_CONF", "OPENSSL_MODULES", "LD_LIBRARY_PATH",
                    "LD_PRELOAD", "TZ"})
    if (auto v = std::getenv(name))
      p["inherited_environment"][name] = v;
  for (const Args &a :
       std::vector<Args>{{"ip", "-V"}, {"tc", "-V"}, {"ethtool", "--version"}})
    try {
      p["tools"].push_back(command(a, 15));
    } catch (const std::exception &e) {
      p["tools"].push_back(
          {{"argv", a}, {"availability", "missing"}, {"reason", e.what()}});
    }
  return p;
}
std::string utc() {
  auto now = std::time(nullptr);
  std::tm value{};
  gmtime_r(&now, &value);
  std::ostringstream out;
  out << std::put_time(&value, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}
std::uint64_t bounded(std::mt19937_64 &rng, std::uint64_t bound) {
  auto threshold = static_cast<std::uint64_t>(-bound) % bound;
  while (true) {
    auto x = rng();
    if (x >= threshold)
      return x % bound;
  }
}
} // namespace
int execute(const fs::path &spec_path, const fs::path &output,
            const std::string &self, int cancel) {
  auto spec = artifact::load(spec_path);
  auto &configs = spec.at("configurations");
  if (!configs.is_array() || configs.empty())
    throw std::runtime_error("configurations_required");
  std::set<std::string> ids;
  for (auto &c : configs) {
    auto id = c.at("id").get<std::string>();
    if (!ids.insert(id).second)
      throw std::runtime_error("configuration_ids_not_unique");
    for (auto role : {"client", "server"})
      c[role]["binary"] = executable(c.at(role).at("binary"));
    auto m = c.value("measurement", Json::object());
    if (!m.is_object() || !m.value("perf_counters", Json(false)).is_boolean())
      throw std::runtime_error("invalid_measurement_options");
    if (m.contains("cpu_samples")) {
      m["cpu_samples"] = profiling::settings(m.at("cpu_samples"));
      c["measurement"] = m;
    }
  }
  auto reps = artifact::integer(spec.value("repetitions", Json(30))),
       seed = artifact::integer(spec.value("seed", Json(0)));
  auto network = spec.value("network", std::string("netem")),
       baseline =
           spec.value("baseline", configs[0].at("id").get<std::string>());
  double timeout = spec.value("timeout_seconds", 30.0);
  if (!reps || !ids.contains(baseline) ||
      (network != "netem" && network != "loopback") || timeout <= 0 ||
      !std::isfinite(timeout))
    throw std::runtime_error("invalid_run_spec");
  spec.update({{"repetitions", reps},
               {"seed", seed},
               {"network", network},
               {"baseline", baseline}});
  auto root = fs::absolute(output);
  if (fs::exists(root))
    throw std::runtime_error("output_must_be_new");
  fs::create_directories(root);
  std::mt19937_64 rng(seed);
  Json order = Json::array();
  for (std::uint64_t repeat = 0; repeat < reps; ++repeat) {
    std::vector<std::string> block;
    for (const auto &c : configs)
      block.push_back(c.at("id"));
    for (std::size_t i = block.size(); i > 1; --i)
      std::swap(block[i - 1], block[bounded(rng, i)]);
    for (const auto &id : block)
      order.push_back({{"repeat", repeat}, {"configuration", id}});
  }
  auto execution_id = identifier();
  Json manifest = {{"schema", "turtle.manifest.v2"},
                   {"execution_id", execution_id},
                   {"started_utc", utc()},
                   {"spec", spec},
                   {"provenance", provenance(spec, self)},
                   {"order_algorithm", "mt19937_64_fisher_yates_rejection_v1"},
                   {"order", order},
                   {"attempts", Json::array()},
                   {"status", "running"}};
  artifact::save(root / "manifest.json", manifest);
  bool interrupted = false;
  for (std::size_t i = 0; i < order.size(); ++i) {
    pollfd stop{cancel, POLLIN, 0};
    if (cancel >= 0 && ::poll(&stop, 1, 0) > 0) {
      interrupted = true;
      break;
    }
    const auto &scheduled = order[i];
    auto it = std::find_if(configs.begin(), configs.end(), [&](const Json &c) {
      return c.at("id") == scheduled.at("configuration");
    });
    std::ostringstream suffix;
    suffix << std::setw(5) << std::setfill('0') << i;
    auto relative = "attempts/" + suffix.str();
    auto target = root / relative;
    fs::create_directories(target);
    auto a = scheduled;
    a.update({{"directory", relative},
              {"run_id", execution_id + ":" + suffix.str()},
              {"error", nullptr}});
    manifest["attempts"].push_back(a);
    artifact::save(root / "manifest.json", manifest);
    try {
      Json result;
      if (network == "netem") {
        Topology topology(target, it->value("netem", Json::object()), self,
                          cancel);
        topology.start();
        topology.start_capture();
        result = run_pair(*it, target, a.at("run_id"),
                          {{"client", topology.prefix("client")},
                           {"server", topology.prefix("server")}},
                          Topology::server_ip, timeout, cancel);
        topology.finish();
      } else {
        artifact::save(
            target / "network.json",
            {{"availability", "not_collected"}, {"topology", "loopback"}});
        result = run_pair(*it, target, a.at("run_id"), {}, "127.0.0.1", timeout,
                          cancel);
      }
      a["error"] = result.at("error");
    } catch (const std::exception &e) {
      a["error"] = e.what();
    }
    manifest["attempts"].back() = a;
    artifact::save(root / "manifest.json", manifest);
    std::cout << i + 1 << '/' << order.size() << ' '
              << scheduled.at("configuration").get<std::string>() << ": "
              << (a.at("error").is_null() ? "scenario complete"
                                          : a.at("error").dump())
              << '\n'
              << std::flush;
    if (a.at("error") == "interrupted") {
      interrupted = true;
      break;
    }
  }
  manifest["status"] = interrupted ? "interrupted" : "complete";
  manifest["finished_utc"] = utc();
  artifact::save(root / "manifest.json", manifest);
  return analysis::regenerate(root) ? 0 : 1;
}
} // namespace turtle::control
