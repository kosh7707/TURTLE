#include "native/stream.hpp"
#include "artifact/network_evidence.hpp"
#include "native/evidence.hpp"
#include "native/network.hpp"
#include "native/pre_cf.hpp"
#include "native/stream_process.hpp"
#include "native/stream_profile.hpp"
#include "native/stream_start.hpp"
#include "native/stream_receipt.hpp"
#include "process/images.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <map>
#include <set>

namespace turtle::native {
using artifact::Json;
using namespace detail;
namespace fs = std::filesystem;
namespace {
void require(bool ok, const std::string &why) {
  if (!ok)
    throw std::runtime_error(why);
}
void fields(const Json &j, std::initializer_list<std::string_view> names) {
  require(j.is_object(), "object_required");
  for (auto &[key, v] : j.items())
    require(std::find(names.begin(), names.end(), key) != names.end(),
            "unknown_field:" + key);
}
bool has(const Json &arr, const std::string &value) {
  return std::find(arr.begin(), arr.end(), value) != arr.end();
}
std::string other(const std::string &role) {
  return role == "client" ? "server" : "client";
}
std::string metric_key(const std::string &k) {
  static const std::map<std::string, std::string> aliases = {
      {"scenario_wall_ns", "timing"},
      {"perf_counters", "pmu"},
      {"records", "record_layout"},
      {"headers", "header_layout"},
      {"public_io", "library_io"}};
  static const std::set<std::string> allowed = {"timing",
                                                "pmu",
                                                "task",
                                                "peer_task",
                                                "authentication",
                                                "profile",
                                                "message_timeline",
                                                "ordinary_server_first",
                                                "transport_counts",
                                                "ciphertext_bytes",
                                                "record_layout",
                                                "timed_records",
                                                "header_layout",
                                                "library_io",
                                                "tls_flights",
                                                "capture",
                                                "tcp_ack",
                                                "cpu_samples"};
  auto i = aliases.find(k);
  if (i != aliases.end())
    return i->second;
  require(allowed.contains(k), "unknown_metric:" + k);
  return k;
}
Json normalize(Json p, const fs::path &base, const fs::path &self) {
  fields(p, {"v", "target", "peer", "scenario", "auth", "timeout_seconds",
             "warmups", "repetitions", "application", "required_metrics",
             "optional_metrics", "network", "expected", "recording",
             "credentials", "measurement", "netem"});
  require(p.at("v") == 1, "native_profile_v1_required");
  fields(p.at("target"), {"role", "argv"});
  auto role = p.at("target").at("role");
  require(role == "client" || role == "server", "invalid_target_role");
  p["stock_peer"] = !p.contains("peer");
  auto stock = [&](std::string who) {
    return Json::array({(self.parent_path() / "turtle-reference").string(),
                        "--native-stream", who, p.value("auth", "mtls"),
                        "{host}", "{port}", p.value("scenario", "S3")});
  };
  if (access((self.parent_path() / "turtle-reference").c_str(), X_OK) == 0)
    p["probe_client"] = stock("client");
  if (p["stock_peer"] == true)
    p["peer"] = {{"argv", stock(other(role))}};
  else
    fields(p.at("peer"), {"argv"});
  for (auto key : {"target", "peer"}) {
    auto &av = p.at(key).at("argv");
    require(av.is_array() && !av.empty(), "argv_required");
    for (auto &a : av)
      require(a.is_string() && a.get_ref<const std::string &>().find('\0') ==
                                   std::string::npos,
              "invalid_argument");
    std::string exe = av.front();
    require(!exe.empty(), "empty_executable");
    if (exe.find('/') != exe.npos)
      exe = (base / exe).string();
    av.front() = process::executable(exe);
    require(access(av.front().get_ref<const std::string &>().c_str(), X_OK) ==
                0,
            "not_executable:" + exe);
  }
  std::error_code ec;
  require(!fs::equivalent(p["target"]["argv"][0].get<std::string>(),
                          self.parent_path() / "turtle-reference", ec),
          "stock_reference_cannot_be_measured_target");
  p["network"] = p.value("network", "loopback");
  require(p["network"] == "loopback" || p["network"] == "netem",
          "invalid_network");
  require(!p.contains("netem") || p["network"] == "netem",
          "netem_requires_isolated_network");
  if (p["network"] == "netem")
    p["netem"] = artifact::normalized_netem(p.value("netem", Json::object()));
  p["scenario"] = p.value("scenario", "S3");
  p["auth"] = p.value("auth", "mtls");
  require(has(Json({"S0", "S1", "S2", "S3", "S4"}), p["scenario"]),
          "invalid_scenario");
  require(p["auth"] == "server" || p["auth"] == "mtls", "invalid_auth");
  if (p.contains("credentials")) {
    auto &c = p.at("credentials");
    fields(c, {"ca", "client", "server", "client_name", "server_name"});
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
      fields(identity, {"cert", "key"});
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
  fields(app, {"request", "greeting", "response"});
  for (auto [key, def] : {std::pair{"request", "ping"},
                          {"greeting", "helo"},
                          {"response", "pong"}}) {
    std::string s = app.value(key, def);
    require(!s.empty() && s.size() <= 16384 && s.find('\0') == s.npos,
            "invalid_application_bytes");
    app[key] = s;
  }
  p["application"] = app;
  auto expected = p.value("expected", Json::object());
  fields(expected, {"group", "suite", "cipher"});
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
  p["expected"] = Json::object();
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
    require(!p["expected"].contains(canonical) ||
                p["expected"][canonical] == id,
            "contradictory_expected_negotiation");
    p["expected"][canonical] = id;
  }
  auto rec = p.value("recording", "basic");
  require(rec == "basic" || rec == "detailed", "invalid_recording");
  std::set<std::string> selected;
  for (auto key : {"required_metrics", "optional_metrics"}) {
    auto m = p.value(key, Json::array());
    require(m.is_array(), "metrics_array_required");
    for (auto &v : m) {
      require(v.is_string(), "invalid_metric");
      require(selected.insert(metric_key(v)).second,
              "duplicate_metric:" + v.get<std::string>());
    }
    p[key] = m;
  }
  auto measurement = p.value("measurement", Json::object());
  fields(measurement, {"cpu_samples", "capture"});
  if (measurement.contains("capture"))
    require(measurement["capture"].is_boolean(), "invalid_capture_flag");
  for (auto key : {"optional_metrics", "required_metrics"})
    if (has(p.at(key), "capture") || has(p.at(key), "tcp_ack"))
      measurement["capture"] = true;
  if (measurement.contains("cpu_samples") ||
      has(p.at("optional_metrics"), "cpu_samples") ||
      has(p.at("required_metrics"), "cpu_samples")) {
    auto options = measurement.value("cpu_samples", Json::object());
    fields(options, {"event", "frequency_hz", "perf"});
    profiling::validate_settings(options);
    measurement["cpu_samples"] = options;
  }
  p["measurement"] = measurement;
  return p;
}
struct Fixture {
  fs::path dir;
  Fixture() {
    auto s = (fs::temp_directory_path() / "turtle-native-XXXXXX").string();
    require(::mkdtemp(s.data()), "private_fixture_directory_failed");
    dir = s;
  }
  ~Fixture() {
    std::error_code e;
    fs::remove_all(dir, e);
  }
};
std::string random_id() {
  std::ifstream f("/proc/sys/kernel/random/uuid");
  std::string id;
  require(bool(f >> id), "uuid_failed");
  return id;
}
struct Messages {
  std::string cad, sad1, sad2;
  explicit Messages(const Json &p) {
    auto &s = p.at("scenario");
    auto &app = p.at("application");
    if (s == "S1" || s == "S3" || s == "S4")
      cad = app.at("request");
    if (s == "S2" || s == "S4")
      sad1 = app.at("greeting");
    if (s == "S3" || s == "S4")
      sad2 = app.at("response");
  }
};
std::string hex(const std::string &s) {
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s) {
    out += alphabet[c >> 4];
    out += alphabet[c & 15];
  }
  return out;
}
std::string peer_name(const Json &p, const std::string &role) {
  auto c = p.value("credentials", Json::object());
  return role == "client"         ? c.value("server_name", "localhost")
         : p.at("auth") == "mtls" ? c.value("client_name", "client.turtle.test")
                                  : "";
}
Json context(const Json &p, const Json &raw, std::string role, bool proof) {
  Messages m(p);
  Json j = {
      {"role", role},
      {"scenario", p["scenario"]},
      {"auth", p["auth"]},
      {"run_id", raw["run_id"]},
      {"connection_id", raw["connection_id"]},
      {"messages",
       {{"CAD", m.cad.size()},
        {"SAD1", m.sad1.size()},
        {"SAD2", m.sad2.size()}}},
      {"peer_name", peer_name(p, role)},
      {"probe", raw.at("purpose") == "capability"},
      {"capability_proof", proof ? Json(true) : Json(nullptr)},
      {"plaintext",
       {{"CAD", hex(m.cad)}, {"SAD1", hex(m.sad1)}, {"SAD2", hex(m.sad2)}}}};
  j["pid"] = 0; // absence cannot authorize a reporter-selected process
  if (raw.contains("pid") && raw.at("pid").contains(role))
    j["pid"] = raw.at("pid").at(role);
  if (p.contains("expected"))
    for (auto &[k, v] : p["expected"].items())
      j["expected_" + k] = v;
  return j;
}
process::Args expand(const Json &proto, const process::Environment &vars) {
  process::Args args;
  for (const std::string a : proto) {
    std::string out;
    for (size_t i = 0; i < a.size();) {
      bool replaced = false;
      for (auto &[token, value] : vars)
        if (a.compare(i, token.size(), token) == 0) {
          out += value;
          i += token.size();
          replaced = true;
          break;
        }
      if (!replaced)
        out += a[i++];
    }
    args.push_back(std::move(out));
  }
  return args;
}
struct Channels {
  std::unique_ptr<App> child;
  std::string sent, received, evidence, diagnostics;
};
Json gate_report(const Json &p, const Json &raw, const std::string &who,
                 const std::string &data) {
  const auto last = data.rfind('\n');
  return analyze_evidence(last == data.npos ? "" : data.substr(0, last + 1),
                          context(p, raw, who, false));
}
Json before_gate(const Json &p, const Json &raw, const std::string &client,
                 const std::string &server) {
  // The gated client is our reference executable. The same image running
  // its native server entry point uses the known direct socket BIO as well,
  // regardless of whether it was selected automatically or explicitly.
  const auto &hashes = raw.at("binary_sha256");
  const auto &argv = raw.at("argv").at("server");
  const bool direct_reference =
      hashes.contains("client") && hashes.contains("server") &&
      hashes.at("client") == hashes.at("server") && argv.size() == 7 &&
      argv[1] == "--native-stream" && argv[2] == "server";
  return pre_cf_extent(
      gate_report(p, raw, "client", client),
      gate_report(p, raw, "server", server), Messages(p).sad1.size(),
      direct_reference);
}
Json perform(const Json &p, const fs::path &dir, const fs::path &keys,
             std::string run, std::string purpose, int cancel) {
  fs::create_directory(dir);
  auto portnum = port();
  auto role = p.at("target").at("role").get<std::string>();
  bool probe = purpose == "capability";
  Json raw = {{"v", 1},
              {"run_id", run},
              {"connection_id", random_id()},
              {"purpose", purpose},
              {"port", portnum},
              {"time_namespaces",Json::object()},{"ranges", Json::array()},
              {"error", nullptr}};
  NetworkTrial network(p, dir, raw, cancel);
  std::map<std::string, Channels> ch;
  ch["server"];
  ch["client"];
  std::unique_ptr<FunctionProfile> profiler;
  auto launch = [&](std::string who, int gated = -1) {
    bool server = who == "server";
    std::string cert = (keys / (who + ".crt")).string(),
                key = (keys / (who + ".key")).string();
    if (!server && p["auth"] != "mtls") {
      cert.clear();
      key.clear();
    }
    std::string name = peer_name(p, who);
    std::string ca = (keys / "ca.crt").string();
    process::Environment vars = {{"{host}", network.host()},
                                 {"{port}", std::to_string(portnum)},
                                 {"{ca}", ca},
                                 {"{cert}", cert},
                                 {"{key}", key},
                                 {"{peer_name}", name}};
    auto args = expand(probe && !server
                           ? p.at("probe_client")
                           : p.at(who == role ? "target" : "peer").at("argv"),
                       vars);
    process::Environment env = {
        {"TURTLE_CA", ca},
        {"TURTLE_CERT", cert},
        {"TURTLE_KEY", key},
        {"TURTLE_PEER_NAME", name},
        {"TURTLE_ROLE", who},
        {"TURTLE_RUN_ID", run},
        {"TURTLE_CONNECTION_ID", raw["connection_id"]},
        {"TURTLE_ATTEMPT_ID", raw["connection_id"]},
        {"TURTLE_REQUEST", p["application"]["request"]},
        {"TURTLE_GREETING", p["application"]["greeting"]},
        {"TURTLE_RESPONSE", p["application"]["response"]}};
    if ((p.at("stock_peer") == true && who != role) || (probe && !server)) {
      for (auto [key, variable] :
           {std::pair{"group", "TURTLE_EXPECTED_GROUP_ID"},
            {"suite", "TURTLE_EXPECTED_SUITE_ID"}})
        if (p.at("expected").contains(key))
          env[variable] = p.at("expected").at(key).dump();
    }
    if (server && (p.at("scenario") == "S2" || p.at("scenario") == "S4")) {
      raw["server_bindings"] = vars;
      for (auto name : {"ca.crt", "server.crt", "client.crt"})
        if (fs::exists(keys / name))
          raw["fixture_sha256"][name] = process::digest(keys / name);
    }
    if (who == role && !(probe && !server))
      env["TURTLE_PMU"] = "1";
    raw["argv"][who] = args;
    raw["binary_sha256"][who] = process::digest(args.front());
    bool diagnostic = purpose == "diagnostic" && who == role;
    ch[who].child =
        std::make_unique<App>(args, env, gated, diagnostic, network.netns(who));
    if (diagnostic) {
      profiler = std::make_unique<FunctionProfile>(dir);
      profiler->attach(*ch[who].child, p.at("measurement").at("cpu_samples"),
                       cancel, process::deadline(p.at("timeout_seconds")));
    }
    raw["pid"][who] = ch[who].child->pid;
  };
  auto end = process::deadline(p.at("timeout_seconds"));
  Messages m(p);
  const auto clock_check = [&]() {
    require(Clock::now() < end, "attempt_timeout");
    pollfd f{cancel, POLLIN, 0};
    if (cancel >= 0 && ::poll(&f, 1, 0) > 0)
      throw std::runtime_error("interrupted");
  };
  try {
    network.start(p);
    launch("server");
    while (
        !socket_queue(ch["server"].child->pid, portnum, true, network.host())) {
      clock_check();
      require(!ch["server"].child->done(), "server_exited_before_listen");
      poll(nullptr, 0, 5);
    }
    network.listen(ch["server"].child->pid, portnum);
    raw["images"]["server"] = process::image_inventory(ch["server"].child->pid,
                                                       ch["server"].child->pid);
    std::unique_ptr<Pipe> gate;
    if (probe)
      gate = std::make_unique<Pipe>();
    launch("client", gate ? gate->r.fd : -1);
    if (gate)
      gate->r.reset();
    auto release_by = Clock::now() + (end - Clock::now()) / 2;
    const auto thaw_by=release_by+(end-release_by)/2;
    PreparedStart startup(raw, end, p.at("network") == "netem");
    bool changed = false, frozen = false;
    while (true) {
      clock_check();
      bool finished = true;
      std::vector<pollfd> fds = {{cancel, POLLIN, 0}};
      startup.service(*ch.at("client").child,*ch.at("server").child,fds);
      for (auto &[who, c] : ch) {
        auto &app = *c.child;
        network.sample(who, app.pid, portnum);
        const bool client = who == "client";
        const auto want = client ? m.sad1 + m.sad2 : m.cad;
        std::string supply = client ? m.cad : m.sad1;
        if (!client && c.received == m.cad)
          supply += m.sad2;
        if (c.sent.size() < supply.size()) {
          auto start = ns();
          auto n = ::write(app.in.fd, supply.data() + c.sent.size(),
                           supply.size() - c.sent.size());
          if (n > 0) {
            auto from = c.sent.size();
            c.sent += supply.substr(from, n);
            raw["ranges"].push_back({{"role", who},
                                     {"channel", "stdin"},
                                     {"begin", from},
                                     {"end", c.sent.size()},
                                     {"host_begin_ns", start},
                                     {"host_end_ns", ns()}});
          } else if (n < 0 && errno != EAGAIN && errno != EINTR)
            throw std::runtime_error(who + "_stdin_failed");
          fds.push_back({app.in.fd, POLLOUT, 0});
        }
        auto drain = [&](FD &fd, std::string &dest, const char *kind,
                         size_t limit) {
          if (fd.fd < 0)
            return;
          std::array<char, 8192> b{};
          auto start = ns();
          auto n = ::read(fd.fd, b.data(), b.size());
          if (n > 0) {
            auto from = dest.size();
            require(from + size_t(n) <= limit, std::string(kind) + "_limit");
            dest.append(b.data(), n);
            changed = true;
            if (std::string_view(kind) == "stdout")
              raw["ranges"].push_back({{"role", who},
                                       {"channel", kind},
                                       {"begin", from},
                                       {"end", dest.size()},
                                       {"host_begin_ns", start},
                                       {"host_end_ns", ns()}});
          } else if (!n)
            fd.reset();
          else if (errno != EAGAIN && errno != EINTR)
            throw std::runtime_error(std::string(kind) + "_read_failed");
          fds.push_back({fd.fd, POLLIN, 0});
        };
        drain(app.out, c.received, "stdout", 1024 * 1024);
        drain(app.err, c.diagnostics, "stderr", 1024 * 1024);
        drain(app.ev, c.evidence, "evidence", 16 * 1024 * 1024);
        if(!c.evidence.empty()&&!raw["time_namespaces"].contains(who)){
          auto domain=PreparedStart::time_namespace(app.pid);
          if(!domain.empty())raw["time_namespaces"][who]=domain;
        }
        require(want.compare(0, c.received.size(), c.received) == 0,
                who + "_unexpected_plaintext");
        if (client && !raw["images"].contains("client") &&
            (!c.evidence.empty() || !c.received.empty()))
          raw["images"]["client"] = process::image_inventory(app.pid, app.pid);
        if (!app.done() || app.out.fd >= 0 || app.err.fd >= 0 || app.ev.fd >= 0)
          finished = false;
      }
      if (gate && gate->w.fd >= 0 && (changed || Clock::now() >= release_by)) {
        Json extent =
            before_gate(p, raw, ch["client"].evidence, ch["server"].evidence);
        if (!extent.is_null() || Clock::now() >= release_by) {
          auto server = ch["server"].child->pid;
          Json queue = nullptr;
          uint64_t stopped_ns = 0, queue_ns = 0;
          if (!extent.is_null() && ::kill(-server, SIGSTOP) == 0) {
            for (;;) {
              clock_check();
              siginfo_t status{};
              auto w = waitid(P_PID, server, &status,
                              WSTOPPED | WEXITED | WNOHANG | WNOWAIT);
              if (w == 0 && status.si_pid == server) {
                require(status.si_code == CLD_STOPPED, "server_not_stopped");
                frozen = true;
                stopped_ns = ns();
                break;
              }
              require(w >= 0 || errno == EINTR, "server_stop_failed");
              ::poll(nullptr, 0, 1);
            }
            // Account for events already written between the positive prefix
            // and SIGSTOP. A partial final evidence line isn't a stable
            // boundary.
            auto &server_channel = ch["server"];
            std::array<char, 8192> buffer;
            for (;;) {
              auto n = read(server_channel.child->ev.fd, buffer.data(),
                            buffer.size());
              if (n > 0) {
                require(server_channel.evidence.size() + size_t(n) <=
                            16 * 1024 * 1024,
                        "evidence_limit");
                server_channel.evidence.append(buffer.data(), n);
              } else if (n < 0 && errno == EINTR)
                continue;
              else
                break;
            }
            extent = server_channel.evidence.ends_with('\n')
                         ? before_gate(p, raw, ch["client"].evidence,
                                       server_channel.evidence)
                         : Json(nullptr);
            // TCP may still deliver in-flight bytes after the server stops.
            // Wait for complete coverage, not merely the first readable byte.
            while (!extent.is_null()) {
              clock_check();
              queue = owned_socket(ch["client"].child->pid, network.host(),
                                   portnum, false, false);
              queue_ns = ns();
              if (!queue.is_null() &&
                  (extent.at("server_source").is_null()
                       ? artifact::integer(queue.at("recv_queue")) > 0
                       : pre_cf_arrived(extent, artifact::integer(
                                                    queue.at("recv_queue")))))
                break;
              if (Clock::now() >= release_by)
                break;
              ::poll(nullptr, 0, 1);
            }
            if (queue.is_null() || extent.is_null() ||
                (!extent.at("server_source").is_null() &&
                 !pre_cf_arrived(extent,
                                 artifact::integer(queue.at("recv_queue"))))) {
              require(::kill(-server, SIGCONT) == 0, "server_resume_failed");
              frozen = false;
            }
          }
          raw["gate"] = {{"client_bytes", ch["client"].evidence.size()},
                         {"server_bytes", ch["server"].evidence.size()},
                         {"client_recv_queue",
                          queue.is_null() ? Json(0) : queue.at("recv_queue")},
                         {"queue_socket", queue},
                         {"pre_cf", extent},
                         {"host_server_stopped_ns", stopped_ns},
                         {"host_queue_sample_ns", queue_ns},
                         {"server_stopped", frozen},
                         {"host_before_release_ns", ns()}};
          require(::write(gate->w.fd, "G", 1) == 1, "probe_gate_failed");
          gate->w.reset();
        }
      }
      if (frozen) {
        const auto &log = ch["client"].evidence;
        auto last = log.rfind('\n');
        auto prefix = last == log.npos ? "" : log.substr(0, last + 1);
        auto result =
            analyze_evidence(prefix, context(p, raw, "client", false));
        if (result["status"] != "invalid" &&
            !result.at("timeline").at("SAD1").at("validated").is_null()) {
          const auto &g = raw.at("gate");
          raw["gate"]["delivery"] = pre_cf_delivery(
              result,
              gate_report(p, raw, "server",
                          ch["server"].evidence.substr(
                              0, artifact::integer(g.at("server_bytes")))),
              g.at("pre_cf"), artifact::integer(g.at("client_recv_queue")));
          raw["gate"]["before_server_resume_client_bytes"] = prefix.size();
          raw["gate"]["host_before_server_resume_ns"] = ns();
          require(::kill(-ch["server"].child->pid, SIGCONT) == 0,
                  "server_resume_failed");
          frozen = false;
        } else if (Clock::now() >= thaw_by) {
          // In particular, a sender may have accepted plaintext only into an
          // application buffer. Resume without proof; retain the ordinary
          // completion/failure instead of deadlocking this probe.
          raw["gate"]["delivery"] = nullptr;
          require(::kill(-ch["server"].child->pid, SIGCONT) == 0,
                  "server_resume_failed");
          frozen = false;
        }
      }
      const bool exchanged = ch["client"].received == m.sad1 + m.sad2 &&
                             ch["server"].received == m.cad &&
                             ch["server"].sent == m.sad1 + m.sad2 &&
                             ch["client"].sent == m.cad;
      if (exchanged &&
          (p["scenario"] != "S0" || !p.at("stock_peer").get<bool>() ||
           ch[other(role)].child->done())) {
        for (auto &[who, c] : ch)
          c.child->in.reset();
      }
      if (finished) {
        require(exchanged, "incomplete_plaintext");
        break;
      }
      if (!changed && ::poll(fds.data(), fds.size(), 10) < 0 && errno != EINTR)
        throw std::runtime_error("poll_failed");
      changed = false;
    }
  } catch (const std::exception &e) {
    raw["error"] = e.what();
  }
  for (auto &[who, c] : ch) {
    raw["exit"][who] =
        c.child && c.child->done() ? Json(c.child->status) : Json(nullptr);
    if (c.child && !raw.at("error").is_null()) {
      // Preserve diagnostics/evidence already in the pipes on setup failure;
      // do not wait for or trust output produced after forced cleanup.
      auto pending = [&](FD &fd, std::string &dest, size_t cap) {
        std::array<char, 8192> b{};
        while (fd.fd >= 0 && dest.size() < cap) {
          auto n =
              ::read(fd.fd, b.data(), std::min(b.size(), cap - dest.size()));
          if (n > 0)
            dest.append(b.data(), n);
          else if (n < 0 && errno == EINTR)
            continue;
          else
            break;
        }
      };
      pending(c.child->err, c.diagnostics, 1024 * 1024);
      pending(c.child->ev, c.evidence, 16 * 1024 * 1024);
    }
    c.child.reset();
    for (auto [suffix, data] : {std::pair{".stdin", &c.sent},
                                {".stdout", &c.received},
                                {".stderr", &c.diagnostics},
                                {".ndjson", &c.evidence}})
      artifact::write_text(dir / (who + suffix), *data);
  }
  if (profiler) {
    try {
      profiler->finish();
    } catch (const std::exception &e) {
      raw["profile_error"] = e.what();
    }
    profiler.reset();
  }
  network.finish(raw.value("pid", Json::object()));
  artifact::save(dir / "attempt.json", raw);
  return raw;
}
const std::array<std::string, 9> files = {
    "attempt.json",  "client.stdin",  "client.stdout",
    "client.stderr", "client.ndjson", "server.stdin",
    "server.stdout", "server.stderr", "server.ndjson"};
Json inventory(const fs::path &dir) {
  process::Args a = {"sha256sum", "--zero", "--"};
  std::vector<std::string> names(files.begin(), files.end());
  for (auto sub : {"profile", "network"}) {
    auto profile = dir / sub;
    if (!fs::exists(profile))
      continue;
    require(fs::is_directory(fs::symlink_status(profile)),
            "invalid_profile_directory");
    for (auto &e : fs::recursive_directory_iterator(profile)) {
      require(!e.is_symlink(), "profile_artifact_symlink");
      if (!e.is_directory()) {
        require(e.is_regular_file(), "invalid_profile_artifact");
        names.push_back(e.path().lexically_relative(dir).string());
      }
    }
  }
  std::sort(names.begin(), names.end());
  for (auto &name : names) {
    auto path = dir / name;
    require(fs::is_regular_file(fs::symlink_status(path)) &&
                fs::file_size(path) <=
                    (name.starts_with("profile/") ? 1024ULL : 64ULL) * 1024 *
                        1024,
            "invalid_raw_artifact:" + name);
    a.push_back(path.string());
  }
  auto r = process::command(a);
  require(r.at("returncode") == 0, "raw_artifact_digest_failed");
  auto hashes = r.at("stdout").get<std::string>();
  size_t pos = 0;
  Json result;
  for (auto &name : names) {
    size_t end = hashes.find('\0', pos);
    require(end != hashes.npos && end - pos >= 66, "invalid_digest_output");
    result[name] = hashes.substr(pos, 64);
    pos = end + 1;
  }
  return result;
}
bool metric(const Json &e, const std::string &k) {
  return e.at("metrics").value(k, Json(nullptr)) == true;
}
Json assess(const Json &p, const Json &raw, const fs::path &dir, bool proof) {
  std::string role = p.at("target").at("role");
  Messages m(p);
  Json participants = Json::object();
  std::map<std::string, std::string> logs;
  bool observed = true, valid = true;
  for (auto who : {"client", "server"}) {
    bool client = std::string_view(who) == "client";
    auto input = artifact::read_text(dir / (std::string(who) + ".stdin")),
         output = artifact::read_text(dir / (std::string(who) + ".stdout"));
    observed = observed && input == (client ? m.cad : m.sad1 + m.sad2) &&
               output == (client ? m.sad1 + m.sad2 : m.cad);
    for (auto [channel, bytes] :
         {std::pair{"stdin", input.size()}, {"stdout", output.size()}}) {
      size_t offset = 0;
      for (auto &r : raw.at("ranges"))
        if (r.at("role") == who && r.at("channel") == channel) {
          require(r.at("begin") == offset &&
                      artifact::integer(r.at("end")) > offset &&
                      artifact::integer(r.at("host_begin_ns")) <=
                          artifact::integer(r.at("host_end_ns")),
                  "invalid_host_range");
          offset = artifact::integer(r.at("end"));
        }
      require(offset == bytes, "incomplete_host_ranges");
    }
    logs[who] = artifact::read_text(dir / (std::string(who) + ".ndjson"));
    auto ctx = context(p, raw, who, proof);
    participants[who] = analyze_evidence(logs[who], ctx);
    if (raw.at("exit").at(who) != 0)
      valid = false;
  }
  const auto first = participants;
  for (auto who : {"client", "server"}) {
    auto ctx = context(p, raw, who, proof);
    const auto &peer = first.at(other(who));
    if (peer.at("status") != "invalid" && peer.at("status") != "contradicted") {
      ctx["peer_negotiated"] = peer.at("negotiated");
      if (peer.contains("wire"))
        ctx["peer_sender_extent"] =
            peer.at("wire").value("sender_extent", Json(nullptr));
      for (auto k : {"sender_unpadded", "application_only_tail"})
        ctx["peer_" + std::string(k)] =
            peer.at("facts").value(k, Json(nullptr));
    }
    participants[who] = analyze_evidence(logs[who], ctx);
  }
  // The peer's profile may itself depend on corroborated numeric IDs. Only
  // publish semantic flight names after both reports have settled.
  for (auto who : {"client", "server"})
    qualify_flights(participants.at(who), p.at("auth") == "mtls",
                    participants.at(other(who)).at("metrics").at("full_handshake_auth"));
  const auto &dut = participants.at(role);
  const auto &peer = participants.at(other(role));
  bool contradiction = dut.at("status") == "contradicted" ||
                       peer.at("status") == "contradicted",
       invalid =
           dut.at("status") == "invalid" || peer.at("status") == "invalid";
  if (dut.contains("negotiated") && peer.contains("negotiated"))
    for (auto key : {"suite", "group", "version"}) {
      auto left = dut.at("negotiated").value(key, Json(nullptr)),
           right = peer.at("negotiated").value(key, Json(nullptr));
      if (!left.is_null() && !right.is_null() && left != right)
        contradiction = true;
    }
  valid = valid && raw.at("error").is_null() && observed;
  const auto network = assess_network(p, raw, dir, participants);
  bool network_ok = network.value("verified", Json(nullptr)) != false &&
                    network.value("capture_verified", Json(nullptr)) != false;
  bool required = network_ok, other_required = network_ok;
  bool early = p.at("scenario") == "S2" || p.at("scenario") == "S4";
  bool unsupported = early && participants.at("server").at("facts").value(
                                  "server_first", Json(nullptr)) == false;
  Json requested_metrics = Json::object();
  const auto start_proof=prepared_start_proof(raw,participants);
  const bool synchronized=start_proof.at("verified")==true;
  const auto &time = dut.at("timing");
  auto pmu = time.value("pmu_status", "unobserved");
  bool partial = pmu == "partial" || pmu == "multiplexed";
  for (auto kind : {"required_metrics", "optional_metrics"}) {
    const bool mandatory = std::string_view(kind) == "required_metrics";
    for (const auto &k : p.at(kind)) {
      auto metric_name = metric_key(k);
      const auto &owner =
          metric_name == "ordinary_server_first" ? participants.at("server")
          : metric_name == "peer_task"           ? peer
                                                 : dut;
      Json value = owner.at("metrics").value(metric_name, Json(nullptr));
      if (metric_name == "capture" || metric_name == "tcp_ack")
        value = network.value(metric_name == "capture" ? "capture_verified"
                                                       : "tcp_ack",
                              Json(nullptr));
      const bool strict_boundary=metric_name=="pmu"||metric_name=="timing";
      if(strict_boundary&&!synchronized)value=start_proof.at("verified");
      bool diag = metric_name == "cpu_samples";
      auto reason = value == true ? Json(nullptr)
                    : strict_boundary && !synchronized
                        ? start_proof.at("reason")
                    : diag                 ? Json("separate_diagnostic")
                    : metric_name == "pmu" ? Json(pmu)
                    : value == false       ? Json("contrary_evidence")
                                           : Json("positive_evidence_missing");
      requested_metrics[k.get<std::string>()] = {{"metric", metric_name},
                                                 {"required", mandatory},
                                                 {"available", value},
                                                 {"reason", reason}};
      if (!diag && mandatory &&
          (value != true || (metric_name == "pmu" && partial))) {
        required = false;
        if (metric_name != "pmu")
          other_required = false;
      }
    }
  }
  bool task_success = valid && !invalid && !contradiction &&
                      metric(dut, "peer_task") && metric(peer, "peer_task") &&
                      (!early || proof);
  bool otherwise_qualified =
      task_success && synchronized && dut.at("status") == "verified";
  bool qualified =
      otherwise_qualified && required && !partial && metric(dut, "pmu");
  bool gate = false;
  if (raw.contains("gate")) {
    auto &g = raw.at("gate");
    auto ci = artifact::integer(g.at("client_bytes")),
         si = artifact::integer(g.at("server_bytes"));
    require(ci <= logs["client"].size() && si <= logs["server"].size(),
            "invalid_gate_watermark");
    bool barrier = false;
    const auto client_cut = logs["client"].substr(0, ci),
               server_cut = logs["server"].substr(0, si);
    const auto extent = before_gate(p, raw, client_cut, server_cut);
    const auto socket = g.value("queue_socket", Json(nullptr));
    const auto queued = artifact::integer(g.at("client_recv_queue"));
    if (g.at("server_stopped") == true && !extent.is_null() &&
        extent == g.value("pre_cf", Json(nullptr)) &&
        (extent.at("server_source").is_null() ||
         pre_cf_arrived(extent, queued)) &&
        socket.is_object() && socket.at("pid") == raw.at("pid").at("client") &&
        socket.at("remote_port") == raw.at("port") &&
        socket.at("remote_ip") == (p.value("network", "loopback") == "netem"
                                       ? control::Topology::server_ip
                                       : "127.0.0.1") &&
        artifact::integer(socket.at("inode")) > 0 &&
        artifact::integer(socket.at("recv_queue")) == queued &&
        g.value("host_server_stopped_ns", uint64_t(0)) >=
            artifact::integer(extent.at("pause_ns")) &&
        g.value("host_queue_sample_ns", uint64_t(0)) >=
            g.value("host_server_stopped_ns", uint64_t(0)) &&
        g.value("host_queue_sample_ns", uint64_t(0)) <=
            artifact::integer(g.at("host_before_release_ns")) &&
        g.contains("before_server_resume_client_bytes")) {
      auto cut = artifact::integer(g.at("before_server_resume_client_bytes"));
      require(ci <= cut && cut <= logs["client"].size() &&
                  artifact::integer(g.at("host_before_release_ns")) <=
                      artifact::integer(g.at("host_before_server_resume_ns")),
              "invalid_resume_watermark");
      auto resumed =
          gate_report(p, raw, "client", logs["client"].substr(0, cut));
      const auto delivered = pre_cf_delivery(
          resumed, gate_report(p, raw, "server", server_cut), extent, queued);
      barrier =
          !delivered.is_null() &&
          delivered == g.value("delivery", Json(nullptr)) &&
          artifact::integer(
              resumed.at("lifecycle").at("probe_resumed").at("ns")) >=
              artifact::integer(g.at("host_before_release_ns")) &&
          artifact::integer(
              resumed.at("timeline").at("SAD1").at("validated").at("ns")) <=
              artifact::integer(g.at("host_before_server_resume_ns"));
    }
    gate = barrier && valid && !invalid && !contradiction &&
           metric(participants.at("client"), "peer_task") &&
           metric(participants.at("server"), "peer_task");
  }
  const char *qualification = "unknown";
  if (invalid)
    qualification = "invalid";
  else if (unsupported)
    qualification = "unsupported";
  else if (contradiction)
    qualification = "contradicted";
  else if (!valid)
    qualification = "failed";
  else if(start_proof.at("verified")==false)
    qualification="unprepared_start";
  else if (partial && otherwise_qualified && other_required)
    qualification = "decision_required";
  else if (qualified)
    qualification = "qualified";

  return {{"purpose", raw.at("purpose")},
          {"connection_id", raw.at("connection_id")},
          {"error", raw.at("error")},
          {"application_exchange", !valid                     ? "failed"
                                   : p.at("scenario") == "S0" ? "not_applicable"
                                                              : "verified"},
          {"app_observation_scope",
           "stdin/stdout byte ranges; host monotonic clock only"},
          {"participants", participants},
          {"prepared_start",start_proof},{"benchmark_timing_ns",synchronized?time.at("wall_ns"):Json(nullptr)},{"benchmark_pmu_available",synchronized?dut.at("metrics").at("pmu"):Json(nullptr)},
          {"network", network},
          {"capability_proof", gate ? Json(true) : Json(nullptr)},
          {"separate_capability_proof", proof ? Json(true) : Json(nullptr)},
          {"scenario_support", invalid        ? "unconfirmed"
                               : unsupported  ? "unsupported"
                               : task_success ? "supported"
                                              : "unconfirmed"},
          {"task_success", task_success},
          {"pmu_status", pmu},
          {"eligible", qualified},
          {"qualification", qualification},
          {"qualified", qualified},
          {"requested_metrics", requested_metrics},
          {"required_metrics_available", required},
          {"operation_ok", valid && !invalid && !contradiction && required}};
}
bool needs_probe(const Json &p) {
  return (p.at("scenario") == "S2" || p.at("scenario") == "S4") &&
         p.contains("probe_client");
}
// Only a successful probe of this same running server/profile can stand in for
// a separate CF barrier. Arrival ordering in the ordinary connection remains
// a separate question. Missing identity is never a wildcard.
Json server_proof_key(const Json &manifest, const Json &raw, const Json &row) {
  const auto &p = manifest.at("profile");
  auto ep = p.at("target").at("role") == "server" ? "target" : "peer";
  const auto &spec = p.at(ep).at("argv");
  if (raw.at("run_id") != manifest.at("run_id") ||
      !raw.contains("server_bindings") || !raw.contains("fixture_sha256") ||
      raw.at("fixture_sha256") != manifest.at("certificate_sha256") ||
      !raw.contains("images") || !raw.at("images").contains("server") ||
      !raw.at("images").at("server").value("available", false))
    return nullptr;
  auto vars = raw.at("server_bindings").get<process::Environment>();
  const auto &img = raw.at("images").at("server");
  auto pid = raw.at("pid").at("server").get<pid_t>();
  if (vars["{peer_name}"] != peer_name(p, "server") ||
      vars["{host}"] != (p.value("network", "loopback") == "netem"
                             ? control::Topology::server_ip
                             : "127.0.0.1") ||
      img.at("launcher_pid") != pid || img.at("pid") != pid ||
      vars["{port}"] != raw.at("port").dump() ||
      Json(expand(spec, vars)) != raw.at("argv").at("server"))
    return nullptr;
  auto image = process::image_key(img, pid);
  auto exe = spec.at(0).get<std::string>();
  if (image.at("exe") != exe ||
      image.at("mapped").at(exe) != raw.at("binary_sha256").at("server") ||
      image.at("mapped").at(exe) != manifest.at("program_sha256").at(ep))
    return nullptr;
  const auto &server = row.at("participants").at("server");
  auto failed = [](const Json &r) {
    return r.at("status") == "invalid" || r.at("status") == "contradicted";
  };
  if (row.at("qualification") == "contradicted" || failed(server) ||
      failed(row.at("participants").at("client")) ||
      !metric(server, "authentication") || !metric(server, "profile") ||
      !metric(server, "ordinary_server_first"))
    return nullptr;
  const auto &neg = server.at("negotiated");
  auto mutual = p.at("auth") == "mtls";
  if (neg.value("version", Json(nullptr)) != 0x304 ||
      !neg.value("group", Json(nullptr)).is_number_integer() ||
      !neg.value("suite", Json(nullptr)).is_number_integer() ||
      (mutual &&
       neg.value("peer_name", Json(nullptr)) != Json(peer_name(p, "server"))))
    return nullptr;
  if (row.at("network").is_object() &&
      row.at("network").value("verified", Json(nullptr)) == false)
    return nullptr;
  vars.erase("{port}"); // each new test binds a fresh ephemeral port
  return {{"run_id", raw.at("run_id")},
          {"image", image},
          {"server_spec", spec},
          {"bindings", vars},
          {"certificates", raw.at("fixture_sha256")},
          {"scenario", p.at("scenario")},
          {"application", p.at("application")},
          {"auth", p.at("auth")},
          {"expected", p.at("expected")},
          {"network", p.value("network", "loopback")},
          {"netem", p.value("netem", Json(nullptr))},
          {"verify_peer", server.at("facts").at("verify_peer")},
          {"peer_name", neg.value("peer_name", Json(nullptr))},
          {"version", neg.at("version")},
          {"suite", neg.at("suite")},
          {"group", neg.at("group")}};
}
// One entry point for live warmups, replay, retry and diagnostics. First
// establish this connection's own facts without assuming a successful probe.
Json assess_bound(const Json &manifest, const Json &raw, const fs::path &dir,
                  Json &proof) {
  const auto &p = manifest.at("profile");
  for (const std::string who : {"client", "server"}) {
    if (raw.at("exit").at(who) != 0)
      continue; // retain unlaunched/failed evidence
    const bool probe_client =
        raw.at("purpose") == "capability" && who == "client";
    const auto ep =
        who == p.at("target").at("role").get<std::string>() ? "target" : "peer";
    const auto &proto =
        probe_client ? p.at("probe_client") : p.at(ep).at("argv");
    require(raw.contains("pid") && raw.at("pid").contains(who) &&
                artifact::integer(raw.at("pid").at(who)) > 0 &&
                raw.at("argv").at(who).at(0) == proto.at(0),
            "unbound_completed_participant:" + who);
    const auto &hash = raw.at("binary_sha256").at(who);
    if (probe_client) {
      if (manifest.contains("probe_client_sha256"))
        require(hash == manifest.at("probe_client_sha256"),
                "probe_launch_image_mismatch");
    } else if (manifest.contains("program_sha256"))
      require(hash == manifest.at("program_sha256").at(ep),
              "participant_launch_image_mismatch:" + who);
  }
  auto row = assess(p, raw, dir, false);
  if (raw.at("purpose") == "capability" && row.at("capability_proof") == true) {
    proof = {{"connection_id", raw.at("connection_id")},
             {"key", server_proof_key(manifest, raw, row)}};
  } else if (!proof.is_null() && raw.at("purpose") != "capability") {
    auto current = server_proof_key(manifest, raw, row);
    auto &previous = proof.at("key");
    const bool bound = !current.is_null() && !previous.is_null(),
               matched = bound && current == previous;
    if (matched)
      row = assess(p, raw, dir, true);
    Json different = Json::array();
    if (bound)
      for (auto &[k, v] : current.items())
        if (v != previous.at(k))
          different.push_back(k);
    row["capability_binding"] = {
        {"probe_connection_id", proof.at("connection_id")},
        {"status", matched ? "matched"
                   : bound ? "profile_mismatch"
                           : "unconfirmed_identity"},
        {"differing_fields", different}};
  }
  return row;
}
void export_certificate(const fs::path &src, const fs::path &dest) {
  // A combined cert+private-key PEM must never be copied into a report.
  require(fs::file_size(src) <= 4 * 1024 * 1024, "oversize_public_certificate");
  auto contents = artifact::read_text(src);
  std::istringstream lines(contents);
  std::string line;
  bool cert = false;
  size_t blocks = 0;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty())
      continue;
    if (line == "-----BEGIN CERTIFICATE-----" && !cert) {
      cert = true;
      continue;
    }
    if (line == "-----END CERTIFICATE-----" && cert) {
      cert = false;
      ++blocks;
      continue;
    }
    require(cert && line.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
                                           "jklmnopqrstuvwxyz0123456789+/=") ==
                        line.npos,
            "public_certificate_must_contain_only_CERTIFICATE_blocks");
  }
  require(!cert && blocks > 0, "invalid_public_certificate");
  artifact::write_text(dest, contents);
}
void check_certificates(const fs::path &root, const Json &m) {
  const auto &hashes = m.at("certificate_sha256");
  fields(hashes, {"ca.crt", "client.crt", "server.crt"});
  require(hashes.contains("ca.crt") && hashes.contains("server.crt") &&
              (m.at("profile").at("auth") != "mtls" ||
               hashes.contains("client.crt")),
          "certificate_inventory_incomplete");
  require(fs::is_directory(fs::symlink_status(root / "certificates")),
          "invalid_certificate_directory");
  for (const auto &[name, hash] : hashes.items()) {
    auto path = root / "certificates" / name;
    require(fs::is_regular_file(fs::symlink_status(path)) &&
                hash == process::digest(path),
            "certificate_inventory_mismatch");
  }
}
} // namespace

// Compute from inventory-checked inputs without writing derived files. Retry
// must see the same finalized sample as run/analyze, without changing its source.
static Json verified_report(const fs::path &root, const Json &manifest) {
  const auto &p = manifest.at("profile");
  const auto &list = manifest.at("attempts");
  require(list.is_array() && !list.empty(), "no_native_attempts");
  check_certificates(root, manifest);
  if (manifest.at("status") == "complete") {
    const auto d = manifest.value("diagnostic_probe", Json::object());
    auto count = artifact::integer(p.at("warmups")) +
                 artifact::integer(p.at("repetitions")) + needs_probe(p) +
                 (d.value("availability", "") == "available");
    require(list.size() == count, "incomplete_attempt_schedule");
  }
  Json rows = Json::array(), proof_image = nullptr,
       diagnostic = manifest.value("diagnostic_probe", Json(nullptr));
  bool require_profile = has(p.at("required_metrics"), "cpu_samples");
  bool ok = manifest.at("status") == "complete";
  size_t count = 0, samples = 0, warmups = 0, successful = 0;
  std::set<std::string> ids;
  for (size_t i = 0; i < list.size(); ++i) {
    auto name = "attempt-" + std::to_string(i + 1);
    const auto &entry = list.at(i);
    require(entry.at("directory") == name, "invalid_attempt_directory");
    auto dir = root / name;
    require(fs::is_directory(fs::symlink_status(dir)) &&
                entry.at("sha256") == inventory(dir),
            "invalid_attempt_inventory");
    auto raw = artifact::load(dir / "attempt.json");
    require(raw.at("run_id") == manifest.at("run_id") &&
                ids.insert(raw.at("connection_id")).second &&
                raw.at("purpose") == entry.at("purpose"),
            "invalid_attempt_identity");
    const auto start = needs_probe(p) ? 1U : 0U;
    const auto warm = p.at("warmups").get<size_t>(),
               total = warm + p.at("repetitions").get<size_t>();
    std::string expected = i < start           ? "capability"
                           : i - start < warm  ? "warmup"
                           : i - start < total ? "sample"
                                               : "diagnostic";
    require(raw.at("purpose") == expected && i <= start + total,
            "unscheduled_attempt");
    if (expected == "diagnostic")
      require(manifest.at("diagnostic_probe").at("availability") == "available",
              "unscheduled_diagnostic");
    auto row = assess_bound(manifest, raw, dir, proof_image);
    if (raw.at("purpose") == "capability") {
      require(i == 0 && p.contains("probe_client"), "invalid_probe_source");
      row["eligible"] = false;
      row["qualified"] = false;
      row["qualification"] = "capability_only";
    } else if (raw.at("purpose") == "diagnostic") {
      std::string role = p.at("target").at("role");
      diagnostic =
          function_report(dir, raw, row.at("participants").at(role), role);
      if (raw.at("error") != nullptr || row.at("operation_ok") != true)
        diagnostic = {{"availability", "missing"},
                      {"reason", "diagnostic_task_failed"}};
      diagnostic["prepared_start"] = row.at("prepared_start").at("verified");
      diagnostic["scope"] = diagnostic.at("prepared_start") == true
                                ? "prepared_scenario" : "local_diagnostic_only";
      row["cpu_samples"] = diagnostic;
      row["eligible"] = false;
      row["qualified"] = false;
      row["qualification"] = "diagnostic_only";
    } else {
      if (raw.at("purpose") == "sample") {
        ++samples;
        if (row.at("task_success") == true)
          ++successful;
        if (row["qualified"] == true)
          ++count;
      } else {
        require(raw.at("purpose") == "warmup", "invalid_attempt_purpose");
        ++warmups;
        row["warmup_allows_measurement"] = warmup_allows_measurement(row);
        row["warmup_assessment"] = row.at("qualification");
        row["eligible"] = false;
        row["qualified"] = false;
        row["qualification"] = "warmup_only";
      }
      ok = ok && (raw.at("purpose") == "warmup"
                     ? row.at("warmup_allows_measurement") == true
                     : row.at("operation_ok") == true);
    }
    row["directory"] = name;
    rows.push_back(std::move(row));
  }
  ok = ok && p.at("repetitions") == samples && p.at("warmups") == warmups;
  const bool profile_available =
      diagnostic.is_object() &&
      diagnostic.value("availability", "missing") == "available" &&
      diagnostic.contains("sample_count") &&
      diagnostic.value("prepared_start", Json(nullptr)) == true;
  Json profile_reason = nullptr;
  if (!profile_available) {
    profile_reason = "separate_diagnostic_missing";
    if (diagnostic.is_object())
      profile_reason = diagnostic.value("scope", "") == "local_diagnostic_only"
                           ? Json("unverified_diagnostic_start")
                           : diagnostic.value("reason", profile_reason);
  }
  if (require_profile && !profile_available) {
    ok = false;
    count = 0;
  }
  for (auto &row : rows)
    if (row.at("purpose") == "sample" &&
        row.at("requested_metrics").contains("cpu_samples")) {
      auto &request = row["requested_metrics"]["cpu_samples"];
      request["available"] = profile_available ? Json(true) : Json(nullptr);
      request["reason"] = profile_reason;
      if (require_profile && !profile_available) {
        row["ordinary_qualified_without_diagnostic"] = row.at("eligible");
        if (row.at("eligible") == true)
          row["qualification"] = "required_diagnostic_missing";
        row["eligible"] = false;
        row["qualified"] = false;
        row["operation_ok"] = false;
        row["required_metrics_available"] = false;
      }
    }
  return {{"cpu_samples", diagnostic},
          {"schema", "turtle.native-run.v1"},
          {"measured_role", p.at("target").at("role")},
          {"attempts", std::move(rows)},
          {"qualified_samples", count},
          {"eligible_measurements", count},
          {"measurement_count", samples},
          {"successful_measurements", successful},
          {"collection_complete", manifest.at("status") == "complete"},
          {"samples", samples},
          {"complete", ok}};
}
static int regenerate_verified(const fs::path &root, const Json &manifest) {
  const auto out = verified_report(root, manifest);
  for (const auto &row : out.at("attempts"))
    artifact::save(root / row.at("directory").get<std::string>() / "analysis.json",
                   row);
  artifact::save(root / "analysis.json", out);
  std::cout << "native-stream: " << out.at("samples") << " sample(s); "
            << out.at("qualified_samples")
            << " benchmark-qualified; see " << (root / "analysis.json") << "\n";
  return out.at("complete") == true ? 0 : 1;
}
int regenerate(const fs::path &root) {
  const auto manifest = artifact::load(root / "manifest.json");
  require(manifest.at("schema") == "turtle.native-manifest.v1",
          "unsupported_native_manifest");
  try {
    return regenerate_verified(root, manifest);
  } catch (const std::exception &e) {
    // Fail closed when a previously eligible archive no longer verifies.
    artifact::save(root / "analysis.json", {{"schema", "turtle.native-run.v1"},
                                            {"complete", false},
                                            {"collection_complete", false},
                                            {"eligible_measurements", 0},
                                            {"qualified_samples", 0},
                                            {"attempts", Json::array()},
                                            {"error", e.what()}});
    throw;
  }
}
int check(const fs::path &profile) {
  auto p =
      normalize(artifact::load(profile), fs::absolute(profile).parent_path(),
                fs::canonical("/proc/self/exe"));
  std::cout << Json{{"schema", "turtle.native-check.v1"},
                    {"launch_configuration", "valid"},
                    {"measured_role", p["target"]["role"]},
                    {"capability", nullptr},
                    {"peer", p["stock_peer"] == true ? "stock" : "specified"}}
                   .dump(2)
            << '\n';
  return 0;
}
int execute(Json p, const fs::path &root, const fs::path &self, int cancel,
            Json retry_of) {
  auto base = fs::current_path();
  if (p.is_string()) {
    auto specfile = fs::absolute(p.get<std::string>());
    base = specfile.parent_path();
    p = artifact::load(specfile);
  }
  p = normalize(p, base, self);
  require(fs::create_directory(root), "output_must_be_new");
  Fixture f;
  auto keys = f.dir / "leaves";
  if (p.contains("credentials")) {
    const auto &c = p.at("credentials");
    fs::create_directory(keys);
    fs::copy_file(c.at("ca").get<std::string>(), keys / "ca.crt");
    for (auto who : {"client", "server"})
      if (c.contains(who)) {
        fs::copy_file(c.at(who).at("cert").get<std::string>(),
                      keys / (std::string(who) + ".crt"));
        fs::copy_file(c.at(who).at("key").get<std::string>(),
                      keys / (std::string(who) + ".key"));
      }
  } else {
    auto cmd = process::command(
        {"/bin/sh",
         (self.parent_path() / "turtle-issue-test-leaves.sh").string(),
         keys.string()},
        30, {}, cancel);
    require(cmd.at("returncode") == 0, "local_test_identity_issuance_failed");
  }
  fs::create_directory(root / "certificates");
  for (auto name : {"ca.crt", "server.crt", "client.crt"})
    if (fs::exists(keys / name))
      export_certificate(keys / name, root / "certificates" / name);
  Json manifest = {{"schema", "turtle.native-manifest.v1"},
                   {"run_id", random_id()},
                   {"profile", p},
                   {"status", "running"},
                   {"attempts", Json::array()}};
  manifest["working_directory"] = fs::current_path().string();
  if (!retry_of.is_null())
    manifest["retry_of"] = retry_of;
  manifest["controller_sha256"] = process::digest(self);
  if (needs_probe(p))
    manifest["probe_client_sha256"] =
        process::digest(p.at("probe_client").at(0).get<std::string>());
  for (auto ep : {"target", "peer"})
    manifest["program_sha256"][ep] =
        process::digest(p.at(ep).at("argv").at(0).get<std::string>());
  if (!p.contains("credentials"))
    manifest["fixture_issuer_sha256"] =
        process::digest(self.parent_path() / "turtle-issue-test-leaves.sh");
  for (auto name : {"ca.crt", "server.crt", "client.crt"})
    if (fs::exists(root / "certificates" / name))
      manifest["certificate_sha256"][name] =
          process::digest(root / "certificates" / name);
  artifact::save(root / "manifest.json", manifest);
  Json positive = nullptr;
  auto run = [&](std::string purpose) {
    auto name = "attempt-" + std::to_string(manifest["attempts"].size() + 1);
    auto raw =
        perform(p, root / name, keys, manifest.at("run_id"), purpose, cancel);
    manifest["attempts"].push_back({{"purpose", purpose},
                                    {"directory", name},
                                    {"sha256", inventory(root / name)}});
    if (raw["error"] == "interrupted")
      manifest["status"] = "interrupted";
    artifact::save(root / "manifest.json", manifest);
    if (raw["error"] == "interrupted")
      throw std::runtime_error("interrupted");
    if (purpose == "capability" || purpose == "warmup") {
      auto row = assess_bound(manifest, raw, root / name, positive);
      return purpose == "capability" || warmup_allows_measurement(row);
    }
    return true;
  };
  if ((p["scenario"] == "S2" || p["scenario"] == "S4") &&
      p.contains("probe_client"))
    run("capability");
  for (size_t i = 0; i < p["warmups"].get<size_t>(); ++i)
    if (!run("warmup")) {
      manifest["status"] = "warmup_failed";
      artifact::save(root / "manifest.json", manifest);
      return regenerate(root);
    }
  for (size_t i = 0; i < p["repetitions"].get<size_t>(); ++i)
    run("sample");
  if (p.at("measurement").contains("cpu_samples")) {
    auto probe =
        profiling::probe(p.at("measurement").at("cpu_samples"), cancel);
    manifest["diagnostic_probe"] = probe;
    if (probe.at("availability") == "available")
      run("diagnostic");
  }
  manifest["status"] = "complete";
  artifact::save(root / "manifest.json", manifest);
  if (!Receipts().verify_or_store(root, manifest, true))
    std::cerr << "turtle: local retry receipt unavailable; offline analysis "
                 "remains available\n";
  return regenerate(root);
}
int retry(const fs::path &source, const std::string &failed,
          const fs::path &out, const fs::path &self, int cancel) {
  auto root = fs::canonical(source),
       dest = fs::weakly_canonical(fs::absolute(out));
  auto rel = dest.lexically_relative(root);
  require(!rel.empty() && *rel.begin() == "..",
          "retry_output_must_be_outside_source");
  require(fs::is_regular_file(fs::symlink_status(root / "manifest.json")),
          "invalid_retry_manifest");
  auto m = artifact::load(root / "manifest.json");
  require(m.at("schema") == "turtle.native-manifest.v1" &&
              m.at("status") == "complete",
          "retry_requires_final_native_run");
  require(Receipts().verify_or_store(root, m, false), "untrusted_retry_source");
  require(m.at("controller_sha256") == process::digest(self),
          "retry_controller_changed");
  auto p = m.at("profile");
  std::string role = p.at("target").at("role");
  const auto report = verified_report(root, m);
  const auto &rows = report.at("attempts");
  const auto sample =
      std::find_if(rows.begin(), rows.end(), [&](const Json &r) {
        return r.at("connection_id") == failed;
      });
  require(sample != rows.end(), "missing_or_unscheduled_retry");
  require(sample->at("purpose") == "sample", "retry_requires_unique_sample");
  require(sample->at("operation_ok") == false,
          "retry_requires_failed_measurement");
  const auto raw = artifact::load(
      root / sample->at("directory").get<std::string>() / "attempt.json");
  for (auto who : {"client", "server"}) {
    const auto key = who == role ? "target" : "peer";
    const auto exe = p.at(key).at("argv").at(0).get<std::string>();
    const auto &hash = m.at("program_sha256").at(key);
    require(hash == process::digest(exe) &&
                (!raw.contains("binary_sha256") ||
                 !raw.at("binary_sha256").contains(who) ||
                 raw.at("binary_sha256").at(who) == hash),
            "retry_program_changed");
  }
  if (p.contains("credentials")) {
    const auto &c = p.at("credentials");
    require(m.at("certificate_sha256").at("ca.crt") ==
                process::digest(c.at("ca").get<std::string>()),
            "retry_ca_changed");
    for (auto who : {"client", "server"})
      if (c.contains(who))
        require(m.at("certificate_sha256").at(std::string(who) + ".crt") ==
                    process::digest(c.at(who).at("cert").get<std::string>()),
                "retry_public_identity_changed");
  }
  if (p.at("stock_peer") == true)
    p.erase("peer");
  p.erase("stock_peer");
  p.erase("probe_client");
  p["repetitions"] = 1;
  struct Restore {
    fs::path path = fs::current_path();
    ~Restore() {
      std::error_code ec;
      fs::current_path(path, ec);
    }
  } restore;
  fs::current_path(m.at("working_directory").get<std::string>());
  return execute(
      p, dest, self, cancel,
      {{"run_id", m.at("run_id")},
       {"connection_id", failed},
       {"manifest_sha256", process::digest(root / "manifest.json")}});
}
} // namespace turtle::native
