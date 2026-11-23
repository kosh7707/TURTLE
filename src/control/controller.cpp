#include "control/controller.hpp"
#include "analysis/analysis.hpp"
#include "build_info.hpp"
#include "control/network.hpp"
#include "control/spec.hpp"
#include "profiling/profiling.hpp"
#include <algorithm>
#include <charconv>
#include <ctime>
#include <functional>
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
namespace {
unsigned parse_unsigned(std::string_view s, unsigned limit,
                        const char *reason) {
  unsigned n{};
  auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
  if (ec != std::errc{} || end != s.data() + s.size() || !n || n > limit)
    throw std::runtime_error(reason);
  return n;
}
Json run_pair(const Json &config, const fs::path &root, const Json &attempt,
              const std::map<std::string, Args> &prefixes,
              const std::string &host, double timeout, int cancel,
              const std::function<void(unsigned)> &before_connect) {
  std::map<std::string, std::unique_ptr<Child>> children;
  Json commands = Json::object(), codes = Json::object(), error = nullptr;
  std::map<std::string, std::string> controls;
  auto end = deadline(timeout);
  const auto &measurement = config.at("measurement");
  const std::string purpose = attempt.at("purpose");
  unsigned listen_port = 0;
  auto launch = [&](const std::string &role, unsigned port) {
    auto target = root / role;
    fs::create_directory(target);
    const auto &ep = config.at(role);
    bool measured = config.at("measured_role") == role;
    bool profile = measured && purpose == "profile";
    Args args = prefixes.contains(role) ? prefixes.at(role) : Args{};
    if (profile) {
      auto p = profiling::prepare(target, measurement.at("cpu_samples"));
      args.insert(args.end(), p.begin(), p.end());
    }
    Args flags = {"--host",
                  host,
                  "--port",
                  std::to_string(port),
                  "--output",
                  target.string(),
                  "--run-id",
                  attempt.at("run_id"),
                  "--controlled",
                  "--timeout",
                  std::to_string(static_cast<unsigned>(std::ceil(timeout)))};
    if (measured && purpose != "capability" && !profile &&
        measurement.at("perf_counters") == true &&
        !attempt.at("unavailable_metrics").contains("perf_counters"))
      flags.push_back("--perf-counters");
    if (profile)
      flags.push_back("--cpu-samples");
    auto rest = endpoint_args(config, role, purpose, std::move(flags));
    args.insert(args.end(), rest.begin(), rest.end());
    auto env = ep.value("env", Environment{});
    if (profile)
      for (const auto &[k, v] : profiling::environment(target))
        env[k] = v;
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
    listen_port = parse_unsigned(std::string_view(listen).substr(7), 65535,
                                 "invalid_listen_port");
    before_connect(listen_port);
    launch("client", listen_port);
    line("server", "READY");
    line("client", "READY");
    if (purpose == "capability") {
      // Both pauses belong exclusively to the capability connection. While
      // server is held after its first write, the client must decrypt helo.
      children.at("client")->send("START\n");
      line("client", "PAUSED");
      children.at("server")->send("START\n");
      auto s = line("server", "PRESEND ");
      auto count = parse_unsigned(std::string_view(s).substr(8), UINT_MAX,
                                  "invalid_presend_count");
      children.at("client")->send("RESUME " + std::to_string(count) + "\n");
      line("client", "GREETING");
      children.at("server")->send("CONTINUE\n");
    } else {
      for (auto role : {"server", "client"})
        children.at(role)->send("START\n");
    }
    for (auto &[role, p] : children)
      p->close_input();
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
  Json result = {{"run_id", attempt.at("run_id")},
                 {"purpose", purpose},
                 {"server_port", listen_port},
                 {"error", error},
                 {"commands", commands},
                 {"measurement", measurement},
                 {"returncodes", codes}};
  artifact::save(root / "processes.json", result);
  return result;
}
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
      if (!p["binaries"].contains(path)) {
        try {
          p["binaries"][path] = {{"sha256", digest(path)},
                                 {"dynamic_libraries", command({"ldd", path})}};
        } catch (const std::exception &e) {
          p["binaries"][path] = {{"reason", e.what()}};
        }
      }
    }
    for (const auto &input : c.value("inputs", Json::array())) {
      auto path = input.get<std::string>();
      if (!p["inputs_sha256"].contains(path)) {
        try {
          p["inputs_sha256"][path] = digest(path);
        } catch (const std::exception &) {
          p["inputs_sha256"][path] = nullptr;
        }
      }
    }
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
Json schedule(const Json &spec, const Json &checks) {
  Json order = Json::array();
  for (const auto &c : spec.at("configurations")) {
    auto add = [&](const char *purpose, std::uint64_t i) {
      order.push_back(
          {{"configuration", c.at("id")}, {"purpose", purpose}, {"repeat", i}});
    };
    if (server_first(c))
      add("capability", 0);
    for (std::uint64_t i = 0; i < artifact::integer(c.at("warmups")); ++i)
      add("warmup", i);
    const auto &features = checks.at("configurations")
                               .at(c.at("id").get<std::string>())
                               .at("features");
    if (requested(c, "cpu_samples") &&
        features.at("cpu_samples").at("availability") == "available")
      add("profile", 0);
  }
  std::mt19937_64 rng(artifact::integer(spec.at("seed")));
  for (std::uint64_t repeat = 0;
       repeat < artifact::integer(spec.at("repetitions")); ++repeat) {
    std::vector<std::string> block;
    for (const auto &c : spec.at("configurations"))
      block.push_back(c.at("id"));
    for (std::size_t i = block.size(); i > 1; --i)
      std::swap(block[i - 1], block[bounded(rng, i)]);
    for (const auto &id : block)
      order.push_back({{"configuration", id},
                       {"purpose", "measurement"},
                       {"repeat", repeat}});
  }
  return order;
}
// Record hashes after close; analysis outputs can be regenerated independently.
Json evidence(const fs::path &root) {
  Args args{"sha256sum", "--zero", "--"};
  for (const auto &entry : fs::recursive_directory_iterator(root)) {
    if (entry.is_regular_file() && !entry.is_symlink())
      args.push_back(entry.path().string());
  }
  Json files = Json::object();
  if (args.size() == 3)
    return files;
  auto r = command(args);
  if (r.at("returncode") != 0)
    throw std::runtime_error("artifact_hash_failed");
  const auto &rows = r.at("stdout").get_ref<const std::string &>();
  for (std::size_t pos = 0; pos < rows.size();) {
    auto end = rows.find('\0', pos);
    if (end == std::string::npos || end <= pos + 66)
      throw std::runtime_error("invalid_artifact_hash");
    files[fs::path(rows.substr(pos + 66, end - pos - 66))
              .lexically_relative(root)
              .generic_string()] = rows.substr(pos, 64);
    pos = end + 1;
  }
  return files;
}
Json perform(const fs::path &root, const Json &spec, const Json &c,
             const Json &a, const std::string &self, int cancel) {
  const bool netem = spec.at("network") == "netem";
  const std::string role = c.at("measured_role");
  std::map<std::string, Args> prefixes;
  std::unique_ptr<Topology> topology;
  Json network = {{"availability", "available"}, {"topology", "loopback"}};
  if (netem) {
    topology = std::make_unique<Topology>(
        root, c.value("netem", Json::object()), cancel);
    topology->start();
    for (auto r : {"client", "server"})
      prefixes[r] = topology->prefix(r);
  }
  Capture capture(root, role);
  const auto &unavailable = a.at("unavailable_metrics");
  bool enabled = requested(c, "capture") && !unavailable.contains("capture") &&
                 a.at("purpose") != "capability";
  auto collect = [&](unsigned port) {
    if (!enabled)
      return;
    try {
      capture.start(netem ? prefixes.at(role) : Args{}, self,
                    netem ? "eth0" : "lo", port, cancel);
    } catch (const std::exception &e) {
      const auto &req = c.at("required_metrics");
      if (std::find(req.begin(), req.end(), "capture") != req.end() ||
          std::string_view(e.what()) == "interrupted")
        throw;
    }
  };
  auto r =
      run_pair(c, root, a, prefixes, netem ? Topology::server_ip : "127.0.0.1",
               spec.at("timeout_seconds"), cancel, collect);
  auto health = capture.finish();
  if (unavailable.contains("capture"))
    health = {{"availability", "unsupported"},
              {"reason", unavailable.at("capture")}};
  if (topology) {
    topology->finish();
    network = artifact::load(root / "network.json");
  }
  network.update({{"client_ip", netem ? Topology::client_ip : "127.0.0.1"},
                  {"server_ip", netem ? Topology::server_ip : "127.0.0.1"},
                  {"capture", {{role, health}}}});
  artifact::save(root / "network.json", network);
  if (topology && (!network.contains("cleanup_errors") ||
                   !network.at("cleanup_errors").empty()))
    throw std::runtime_error("network_cleanup_failed");
  return r.at("error");
}
} // namespace

int check(const fs::path &path) {
  auto r = preflight(resolve_spec(artifact::load(path)));
  std::cout << r.dump(2) << '\n';
  return r.at("ready") == true ? 0 : 1;
}
int execute(const fs::path &spec_path, const fs::path &output,
            const std::string &self, int cancel) {
  auto spec = artifact::load(spec_path);
  if (spec.contains("retry_of"))
    throw std::runtime_error("use_retry_command_for_linked_attempts");
  return execute_spec(std::move(spec), output, self, cancel);
}
int execute_spec(Json spec, const fs::path &output, const std::string &self,
                 int cancel) {
  spec = resolve_spec(std::move(spec));
  auto root = fs::absolute(output);
  if (fs::exists(root) || !fs::create_directories(root))
    throw std::runtime_error("output_must_be_new");
  auto checks = preflight(spec, cancel);
  artifact::save(root / "check.json", checks);
  auto order = schedule(spec, checks);
  auto batch = identifier();
  Json manifest = {
      {"schema", "turtle.manifest.v3"},
      {"execution_id", batch},
      {"started_utc", utc()},
      {"spec", spec},
      {"provenance", provenance(spec, self)},
      {"preflight", "check.json"},
      {"order_algorithm", "diagnostics_then_seeded_measurement_blocks_v1"},
      {"order", order},
      {"attempts", Json::array()},
      {"blocked", Json::object()},
      {"status", "running"}};
  std::map<std::string, Json> configs;
  for (const auto &c : spec.at("configurations")) {
    auto id = c.at("id").get<std::string>();
    configs[id] = c;
    const auto &check = checks.at("configurations").at(id);
    if (check.at("ready") != true)
      manifest["blocked"][id] = {{"stage", "preflight"},
                                 {"reason", check.at("reasons")}};
  }
  artifact::save(root / "manifest.json", manifest);
  bool interrupted = false, failed = !manifest.at("blocked").empty();
  for (std::size_t i = 0; i < order.size(); ++i) {
    pollfd stop{cancel, POLLIN, 0};
    if (cancel >= 0 && ::poll(&stop, 1, 0) > 0) {
      interrupted = true;
      break;
    }
    auto a = order.at(i);
    auto id = a.at("configuration").get<std::string>();
    if (manifest.at("blocked").contains(id))
      continue;
    const auto &c = configs.at(id);
    std::ostringstream suffix;
    suffix << std::setw(5) << std::setfill('0') << i;
    auto relative = "attempts/" + suffix.str();
    auto dir = root / relative;
    a.update({{"run_id", batch + ":" + suffix.str()},
              {"directory", relative},
              {"error", nullptr},
              {"unavailable_metrics", Json::object()}});
    if (spec.contains("retry_of") && a.at("purpose") == "measurement")
      a["retry_of"] = spec.at("retry_of");
    for (const auto &[k, v] :
         checks.at("configurations").at(id).at("features").items())
      if (requested(c, k) && v.at("availability") != "available")
        a["unavailable_metrics"][k] = v.at("reason");
    manifest["attempts"].push_back(a);
    artifact::save(root / "manifest.json", manifest);
    try {
      fs::create_directories(dir);
      a["error"] = perform(dir, spec, c, a, self, cancel);
      a["artifacts_sha256"] = evidence(dir);
    } catch (const std::exception &e) {
      a["error"] = e.what();
    }
    Json diagnostic;
    try {
      diagnostic = analysis::assess(dir, c, a);
    } catch (const std::exception &e) {
      // A failed collector or unwritable assessment must not leave the
      // manifest at "running" or cause another connection to replace this ID.
      a["assessment_error"] = e.what();
      if (a.at("error").is_null())
        a["error"] = e.what();
      diagnostic = {{"eligible", false},
                    {"invalid_reasons", Json::array({e.what()})}};
    }
    bool eligible = diagnostic.at("eligible");
    bool diagnostic_required =
        a.at("purpose") != "profile" ||
        std::find(c.at("required_metrics").begin(),
                  c.at("required_metrics").end(),
                  "cpu_samples") != c.at("required_metrics").end();
    if (!eligible && diagnostic_required) {
      failed = true;
      if (a.at("purpose") != "measurement")
        manifest["blocked"][id] = {
            {"stage", a.at("purpose")},
            {"run_id", a.at("run_id")},
            {"reason", diagnostic.at("invalid_reasons")}};
    }
    manifest["attempts"].back() = a;
    artifact::save(root / "manifest.json", manifest);
    std::cout << i + 1 << '/' << order.size() << ' ' << id << ' '
              << a.at("purpose").get<std::string>() << ": "
              << (eligible ? "ok" : diagnostic.at("invalid_reasons").dump())
              << std::endl;
    if (a.at("error") == "interrupted") {
      interrupted = true;
      break;
    }
  }
  manifest["status"] = interrupted ? "interrupted"
                       : failed    ? "failed"
                                   : "complete";
  manifest["finished_utc"] = utc();
  artifact::save(root / "manifest.json", manifest);
  return analysis::regenerate(root) ? 0 : 1;
}
} // namespace turtle::control
