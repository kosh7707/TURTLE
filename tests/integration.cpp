#include "artifact/json.hpp"
#include "process/process.hpp"
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <thread>
using turtle::artifact::Json;
using turtle::process::Args;
namespace fs = std::filesystem;
namespace {
void require(bool ok, const std::string &reason) {
  if (!ok)
    throw std::runtime_error(reason);
}
Json run(const Args &args, double timeout = 90) {
  auto r = turtle::process::command(args, timeout);
  if (r.at("returncode") != 0) {
    std::cerr << r.dump(2) << '\n';
    throw std::runtime_error("command_failed");
  }
  return r;
}
Json certificates(const std::string &openssl, const fs::path &root,
                  const std::string &kind) {
  fs::create_directories(root);
  Args key = kind == "classical" || kind == "hybrid" || kind == "partial"
                 ? Args{"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"}
                 : Args{"-newkey", "ML-DSA-65"};
  Json commands = Json::array();
  auto invoke = [&](Args a) {
    a.insert(a.begin(), openssl);
    commands.push_back(run(a));
  };
  Args a = {"req", "-x509"};
  a.insert(a.end(), key.begin(), key.end());
  Args rest = {"-noenc",
               "-days",
               "2",
               "-config",
               "/dev/null",
               "-subj",
               "/CN=TURTLE root",
               "-addext",
               "basicConstraints=critical,CA:TRUE,pathlen:4",
               "-addext",
               "keyUsage=critical,keyCertSign,cRLSign",
               "-out",
               (root / "root.crt").string(),
               "-keyout",
               (root / "root.key").string()};
  a.insert(a.end(), rest.begin(), rest.end());
  invoke(a);
  auto parent = root / "root.crt", parent_key = root / "root.key";
  std::string chain;
  int count = kind == "chain" ? 4 : 1;
  for (int i = 0; i < count; ++i) {
    bool leaf = i == count - 1;
    auto base = root / ("cert-" + std::to_string(i)),
         cert = fs::path(base.string() + ".crt"),
         keyfile = fs::path(base.string() + ".key"),
         csr = fs::path(base.string() + ".csr"), ext = root / "extensions.cnf";
    turtle::artifact::write_text(
        ext, leaf ? "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,"
                    "digitalSignature\nextendedKeyUsage="
                    "serverAuth\nsubjectAltName=DNS:localhost\n"
                  : "basicConstraints=critical,CA:TRUE,pathlen:3\nkeyUsage="
                    "critical,keyCertSign,cRLSign\n");
    a = {"req", "-new"};
    a.insert(a.end(), key.begin(), key.end());
    rest = {"-noenc",
            "-config",
            "/dev/null",
            "-subj",
            leaf ? "/CN=localhost"
                 : "/CN=TURTLE intermediate " + std::to_string(i),
            "-out",
            csr.string(),
            "-keyout",
            keyfile.string()};
    a.insert(a.end(), rest.begin(), rest.end());
    invoke(a);
    invoke({"x509", "-req", "-in", csr.string(), "-CA", parent.string(),
            "-CAkey", parent_key.string(), "-set_serial", std::to_string(i + 2),
            "-days", "2", "-extfile", ext.string(), "-out", cert.string()});
    chain = turtle::artifact::read_text(cert) + chain;
    parent = cert;
    parent_key = keyfile;
  }
  // The client's leaf has a distinct key and EKU; both leaves are directly
  // issued by this test CA in the representative classical S3 configuration.
  Args req{"req", "-new"};
  req.insert(req.end(), key.begin(), key.end());
  req.insert(req.end(),
             {"-noenc", "-config", "/dev/null", "-subj", "/CN=TURTLE client",
              "-keyout", (root / "client.key").string(), "-out",
              (root / "client.csr").string()});
  invoke(req);
  turtle::artifact::write_text(
      root / "client.ext",
      "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,"
      "digitalSignature\nextendedKeyUsage=clientAuth\n");
  invoke({"x509", "-req", "-in", (root / "client.csr").string(), "-CA",
          (root / "root.crt").string(), "-CAkey", (root / "root.key").string(),
          "-set_serial", "27", "-days", "2", "-extfile",
          (root / "client.ext").string(), "-out",
          (root / "client.crt").string()});
  turtle::artifact::write_text(root / "server-chain.pem", chain);
  turtle::artifact::save(root / "generation.json", commands);
  return {{"cert", (root / "server-chain.pem").string()},
          {"key", parent_key.string()},
          {"client_cert", (root / "client.crt").string()},
          {"client_key", (root / "client.key").string()},
          {"ca", (root / "root.crt").string()}};
}
} // namespace
int main(int argc, char **argv) {
  try {
    require(argc >= 8, "mode cli openssl client server profile output [perf]");
    std::string mode = argv[1], cli = fs::absolute(argv[2]).string(),
                openssl = fs::absolute(argv[3]).string(),
                client = fs::absolute(argv[4]).string(),
                server = fs::absolute(argv[5]).string(), profile = argv[6];
    auto root = fs::absolute(argv[7]);
    fs::remove_all(root);
    fs::create_directories(root);
    auto cert = certificates(openssl, root / "certificates", profile);
    std::string group = profile == "hybrid" || profile == "chain"
                            ? "X25519MLKEM768"
                        : profile == "mldsa" ? "MLKEM768"
                                             : "X25519";
    Json config = {
        {"id", "test"},
        {"client",
         {{"binary", client},
          {"args",
           {"--ca", cert.at("ca"), "--peer", "localhost", "--groups", group}}}},
        {"server",
         {{"binary", server},
          {"args",
           {"--cert", cert.at("cert"), "--key", cert.at("key"), "--groups",
            group}}}},
        {"inputs", {cert.at("ca"), cert.at("cert"), cert.at("key")}}};
    config.update({{"scenario", "S3"},
                   {"recording", "detailed"},
                   {"measured_role", "client"},
                   {"expected", {{"group", group}}},
                   {"required_metrics", {"public_io", "records"}}});
    if (profile == "partial") {
      config["io_chunk"] = 17;
      config["app_chunk"] = 2;
    }
    if (mode == "counter")
      config["required_metrics"].push_back("perf_counters");
    if (mode == "sample" || mode == "cycles") {
      require(argc == 9, "perf executable required");
      config["required_metrics"].push_back("cpu_samples");
      config["measurement"] = {
          {"cpu_samples",
           {{"perf", fs::absolute(argv[8]).string()},
            {"event", mode == "sample" ? "cpu-clock:u" : "cycles:u"},
            {"frequency_hz", 3997}}}};
    }
    auto mutual = [&](Json c) {
      c["auth"] = "mtls";
      auto &client_args = c["client"]["args"];
      client_args.insert(client_args.end(), {"--cert", cert.at("client_cert"),
                                             "--key", cert.at("client_key")});
      c["server"]["args"].push_back("--ca");
      c["server"]["args"].push_back(cert.at("ca"));
      c["inputs"].push_back(cert.at("client_cert"));
      c["inputs"].push_back(cert.at("client_key"));
      return c;
    };
    Json configs = Json::array({mutual(config)});
    bool netem = mode == "netem",
         matrix = mode == "loopback" && profile == "classical";
    if (matrix) {
      configs = Json::array();
      for (auto scenario : {"S3", "S0", "S1", "S2", "S4"})
        for (auto auth : {"mtls", "server"})
          for (auto role : {"client", "server"}) {
            auto c = std::string(auth) == "mtls" ? mutual(config) : config;
            c.update({{"id", std::string(scenario) + "-" + auth + "-" + role},
                      {"scenario", scenario},
                      {"auth", auth},
                      {"measured_role", role},
                      {"app_chunk", 2}});
            configs.push_back(c);
          }
    }
    if (netem) {
      // Use S4 for the per-copy, presend ACK comparison, not just a byte total.
      configs[0]["scenario"] = "S4";
      configs[0]["measured_role"] = "server";
      configs[0]["required_metrics"].push_back("capture");
      auto impaired = configs.front();
      impaired["id"] = "impaired";
      impaired["scenario"] = "S3";
      impaired["application"] = {{"response", std::string(12000, 'X')}};
      impaired["netem"] = {
          {"mtu", 1000},
          {"client_to_server", {{"delay_ms", 8}, {"loss_pct", 0}}},
          {"server_to_client",
           {{"delay_ms", 8}, {"loss_pct", 20}, {"seed", 99}}}};
      configs.push_back(impaired);
    }
    if (mode == "overhead") {
      configs = Json::array();
      for (auto level : {"off", "basic", "detailed"}) {
        auto c = mutual(config);
        c.update({{"id", level},
                  {"recording", level},
                  {"required_metrics", {"scenario_wall_ns"}}});
        configs.push_back(c);
      }
    }
    if (mode == "gates") {
      // Preflight cannot know the negotiated group. A bad warmup blocks only
      // that configuration, even while unrelated optional hooks are absent.
      configs[0]["id"] = "control";
      configs[0]["recording"] = "basic";
      configs[0]["required_metrics"] = Json::array();
      configs[0]["optional_metrics"] = {"capture"};
      auto wrong = configs[0];
      wrong["id"] = "wrong";
      wrong["expected"]["group"] = "not-the-negotiated-group";
      auto missing = configs[0];
      missing["id"] = "missing";
      missing["required_metrics"] = {"headers"};
      configs.push_back(wrong);
      configs.push_back(missing);
    }
    Json spec = {{"configurations", configs},
                 {"repetitions", mode == "overhead"         ? 5
                                 : netem || mode == "gates" ? 2
                                                            : 1},
                 {"seed", 0},
                 {"network", netem ? "netem" : "loopback"},
                 {"timeout_seconds", 60},
                 {"baseline", configs.front().at("id")}};
    auto spec_path = root / "spec.json", output = root / "run";
    turtle::artifact::save(spec_path, spec);
    if (mode == "retry") {
      // A transient launch failure after a valid warmup. Both batches use
      // exactly the same executable and credentials.
      auto shim = root / "server.sh", flag = root / "simulate-outage";
      turtle::artifact::write_text(shim, R"(#!/bin/sh
run=false
purpose=
previous=
for a in "$@"; do
  [ "$a" != "--" ] || break
  [ "$a" != "--controlled" ] || run=true
  [ "$previous" != "--purpose" ] || purpose=$a
  previous=$a
done
if [ "$run" = true ] && [ "$purpose" = measurement ] && [ -f "$OUTAGE" ]; then exit 17; fi
exec "$ENDPOINT" "$@"
)");
      fs::permissions(shim, fs::perms::owner_all);
      turtle::artifact::write_text(flag, "");
      auto &ep = spec["configurations"][0]["server"];
      ep["env"] = {{"OUTAGE", flag.string()}, {"ENDPOINT", ep.at("binary")}};
      ep["binary"] = shim.string();
      turtle::artifact::save(spec_path, spec);
      auto rc = turtle::process::command(
          {cli, "run", spec_path.string(), output.string()});
      require(rc.at("returncode") != 0, "expected simulated failure");
      auto manifest = turtle::artifact::load(output / "manifest.json");
      require(manifest.at("status") == "failed" &&
                  manifest.at("attempts").size() == 2,
              "failure was not finalized");
      auto id = manifest.at("attempts").back().at("run_id").get<std::string>();
      auto hash = turtle::process::digest(output / "manifest.json");
      fs::remove(flag);
      auto fresh = root / "retry";
      run({cli, "retry", output.string(), id, fresh.string()});
      auto retried = turtle::artifact::load(fresh / "manifest.json");
      auto &measurement = retried.at("attempts").back();
      require(retried.at("status") == "complete" &&
                  measurement.at("run_id") != id &&
                  measurement.at("retry_of").at("run_id") == id &&
                  retried.at("attempts").size() == 2 &&
                  turtle::process::digest(output / "manifest.json") == hash,
              "retry overwrote or pooled source");
      require(turtle::process::command({cli, "retry", fresh.string(),
                                        measurement.at("run_id"),
                                        (root / "invalid").string()})
                          .at("returncode") != 0 &&
                  !fs::exists(root / "invalid"),
              "successful trial cannot be resampled as failure");
      return 0;
    }
    if (mode == "interrupt") {
      spec["network"] = "netem";
      spec["repetitions"] = 10;
      spec["configurations"][0]["netem"] = {
          {"client_to_server", {{"delay_ms", 200}}},
          {"server_to_client", {{"delay_ms", 200}}}};
      turtle::artifact::save(spec_path, spec);
      turtle::process::Child child(
          {cli, "run", spec_path.string(), output.string()});
      auto until = turtle::process::deadline(15);
      bool active = false;
      auto state_path = output / "attempts/00000/network.json";
      while (std::chrono::steady_clock::now() < until) {
        if (fs::exists(state_path)) {
          auto state = turtle::artifact::load(state_path);
          if (state.value("availability", "") == "available") {
            active = true;
            break;
          }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      require(active, "interruption must occur after network setup");
      child.signal(SIGTERM);
      require(child.wait(turtle::process::deadline(20)) != 0,
              "interrupted exit status");
      auto stopped = turtle::artifact::load(output / "manifest.json");
      require(stopped.at("status") == "interrupted" &&
                  stopped.at("attempts").size() == 1,
              "interrupted attempt retained without replacement");
      auto state = turtle::artifact::load(state_path);
      require(state.at("cleanup_errors").empty(), "interrupted cleanup errors");
      auto namespaces =
          run({"ip", "netns", "list"}).at("stdout").get<std::string>();
      for (const auto &name : state.at("names"))
        require(namespaces.find(name.get<std::string>()) == std::string::npos,
                "namespace left behind");
      std::cout
          << "Interruption preserved attempt and removed owned resources\n";
      return 0;
    }
    auto check = turtle::process::command({cli, "check", spec_path.string()});
    auto report = Json::parse(check.at("stdout").get<std::string>());
    require(report.at("connection_verified") == false,
            "check is not a connection test");
    if (mode == "gates") {
      require(check.at("returncode") != 0 &&
                  report.at("configurations").at("wrong").at("ready") == true &&
                  report.at("configurations").at("missing").at("ready") ==
                      false,
              "preflight scope");
      require(turtle::process::command(
                  {cli, "run", spec_path.string(), output.string()})
                      .at("returncode") != 0,
              "failed warmup must be reported");
      auto manifest = turtle::artifact::load(output / "manifest.json");
      auto aggregate = turtle::artifact::load(output / "analysis.json");
      require(manifest.at("blocked").at("wrong").at("stage") == "warmup" &&
                  manifest.at("blocked").at("missing").at("stage") ==
                      "preflight" &&
                  aggregate.at("measurement_count") == 2 &&
                  aggregate.at("successful_measurements") == 2,
              "blocked configurations must not contaminate other samples");
      for (const auto &a : aggregate.at("attempts"))
        require(a.at("configuration") == "control", "blocked measurement ran");
      return 0;
    }
    require(check.at("returncode") == 0, check.dump());
    auto execution = run({cli, "run", spec_path.string(), output.string()},
                         netem ? 240 : 150);
    turtle::artifact::save(root / "execution.json", execution);
    auto manifest = turtle::artifact::load(output / "manifest.json"),
         aggregate = turtle::artifact::load(output / "analysis.json");
    std::size_t n = configs.size() *
                    turtle::artifact::integer(spec.at("repetitions")),
                warmups = 0, probes = 0, profiles = 0;
    require(aggregate.at("measurement_count") == n &&
                aggregate.at("successful_measurements") == n &&
                aggregate.at("eligible_measurements") == n,
            "only genuine repetitions count");
    std::uint64_t repeated = 0;
    for (const auto &a : manifest.at("attempts")) {
      auto dir = output / a.at("directory").get<std::string>();
      auto analysis = turtle::artifact::load(dir / "analysis.json");
      require(analysis.at("eligible") == true,
              analysis.at("invalid_reasons").dump());
      auto c = turtle::artifact::load(dir / "client/endpoint.json"),
           s = turtle::artifact::load(dir / "server/endpoint.json");
      require(c.at("negotiated").at("peer_verified") == true &&
                  s.at("negotiated").at("peer_verified") ==
                      (s.at("auth") == "mtls"),
              "authentication evidence");
      std::string measured = c.at("measured_role").get<std::string>(),
                  peer = measured == "client" ? "server" : "client";
      require(!fs::exists(dir / peer / "events.jsonl") &&
                  !fs::exists(dir / peer / "wire_send.bin"),
              "peer was instrumented");
      const auto &data = analysis.at("roles").at(measured);
      auto purpose = a.at("purpose");
      if (purpose == "warmup")
        ++warmups;
      if (purpose == "capability")
        ++probes;
      if (purpose == "profile")
        ++profiles;
      for (const auto &m : analysis.at("measurements"))
        if (purpose != "measurement" ||
            (mode == "counter" && m.at("group") == "metrics"))
          require(!m.at("valid_sample").get<bool>(),
                  "diagnostic timing leaked into performance samples");
      if (purpose == "capability")
        continue;
      if (mode == "overhead") {
        auto level = c.at("recording");
        require(fs::exists(dir / measured / "events.jsonl") ==
                        (level != "off") &&
                    fs::exists(dir / measured / "wire_send.bin") ==
                        (level == "detailed"),
                "recording selection");
        if (purpose == "measurement")
          require(
              data.at("metrics").at("scenario_wall_ns").at("availability") ==
                  "available",
              "missing common minimum timer");
        if (level != "detailed")
          continue;
      }
      require(analysis.at("observations").at("records").at("value") == true &&
                  analysis.at("observations").at("public_io").at("value") ==
                      true,
              "byte-range coverage");
      if (netem) {
        require(analysis.at("network_complete") == true,
                "live capture incomplete");
        repeated += turtle::artifact::integer(
            data.at("metrics").at("retransmitted_send_bytes").at("value"));
      }
      if (mode == "counter")
        require(analysis.at("observations").at("perf_counters").at("value") ==
                    true,
                "actual target-thread counters");
      if (purpose == "profile")
        require(analysis.at("observations").at("cpu_samples").at("value") ==
                    true,
                "actual function samples");
    }
    require(warmups == configs.size(), "one warmup per configuration");
    if (matrix)
      require(probes == 8, "distinct stopped-client probes");
    if (mode == "sample" || mode == "cycles")
      require(profiles == 1, "dedicated non-timing perf trial");
    if (netem)
      require(repeated > 0, "no repeated bytes measured in loss configuration");
    auto before =
        turtle::process::digest(output / "attempts/00000/analysis.json");
    run({cli, "analyze", output.string()});
    require(before == turtle::process::digest(output /
                                              "attempts/00000/analysis.json"),
            "deterministic regeneration");
    require(turtle::process::command(
                {cli, "run", spec_path.string(), output.string()})
                    .at("returncode") != 0,
            "existing results must not be overwritten");
    std::cout << "Actual TLS " << profile << " / " << mode
              << " passed: " << output << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
