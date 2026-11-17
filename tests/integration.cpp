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
  turtle::artifact::write_text(root / "server-chain.pem", chain);
  turtle::artifact::save(root / "generation.json", commands);
  return {{"cert", (root / "server-chain.pem").string()},
          {"key", parent_key.string()},
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
    if (profile == "partial")
      config["io_chunk"] = 17;
    if (mode == "counter")
      config["measurement"] = {{"perf_counters", true}};
    if (mode == "sample" || mode == "cycles") {
      require(argc == 9, "perf executable required");
      config["measurement"] = {
          {"cpu_samples",
           {{"perf", fs::absolute(argv[8]).string()},
            {"event", mode == "sample" ? "cpu-clock:u" : "cycles:u"},
            {"frequency_hz", 997}}}};
    }
    Json configs = Json::array({config});
    bool netem = mode == "netem";
    if (netem) {
      config["id"] = "impaired";
      config["netem"] = {
          {"client_to_server",
           {{"delay_ms", 5}, {"loss_pct", 10}, {"rate_mbit", 10}, {"seed", 7}}},
          {"server_to_client",
           {{"delay_ms", 5},
            {"loss_pct", 10},
            {"rate_mbit", 10},
            {"seed", 7}}}};
      configs.push_back(config);
    }
    Json spec = {{"configurations", configs},
                 {"repetitions", netem ? 3 : 1},
                 {"seed", 0},
                 {"network", netem ? "netem" : "loopback"},
                 {"timeout_seconds", 60},
                 {"baseline", "test"}};
    auto spec_path = root / "spec.json", output = root / "run";
    turtle::artifact::save(spec_path, spec);
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
    auto execution = run({cli, "run", spec_path.string(), output.string()},
                         netem ? 240 : 150);
    turtle::artifact::save(root / "execution.json", execution);
    auto manifest = turtle::artifact::load(output / "manifest.json");
    std::uint64_t repeated = 0;
    for (const auto &a : manifest.at("attempts")) {
      auto path = output / a.at("directory").get<std::string>();
      auto analysis = turtle::artifact::load(path / "analysis.json");
      require(analysis.at("success") == true &&
                  analysis.at("phase_complete") == true,
              "TLS and phase success required");
      require(analysis.at("perf_complete") == true, "perf complete required");
      for (auto role : {"client", "server"}) {
        const auto &data = analysis.at("roles").at(role);
        require(data.at("phases").at("rows").size() == 4, "four phases");
        if (profile == "chain")
          require(turtle::artifact::integer(data.at("phases")
                                                .at("rows")[2]
                                                .at("metrics")
                                                .at("record_count")
                                                .at("value")) > 1,
                  "certificate chain must span records");
        if (netem) {
          require(analysis.at("network_complete") == true, "network complete");
          repeated += turtle::artifact::integer(
              data.at("metrics").at("retransmitted_send_bytes").at("value"));
        }
        if (mode == "counter")
          require(data.at("counters").at("complete") == true,
                  "hardware counters");
        if (mode == "sample" || mode == "cycles")
          require(data.at("cpu_profile").at("availability") == "available",
                  "actual CPU samples");
      }
      if (mode == "counter" || mode == "sample" || mode == "cycles")
        for (const auto &m : analysis.at("measurements"))
          if (m.at("group") == "metrics" || m.at("group") == "phase_metrics")
            require(m.at("valid_sample") == false,
                    "profiling excluded from ordinary timings");
    }
    if (netem)
      require(repeated > 0, "actual retransmission evidence required");
    auto before =
        turtle::process::digest(output / "attempts/00000/analysis.json");
    run({cli, "analyze", output.string()}, 150);
    require(before == turtle::process::digest(output /
                                              "attempts/00000/analysis.json"),
            "deterministic regeneration");
    require(turtle::process::command(
                {cli, "run", spec_path.string(), output.string()})
                    .at("returncode") != 0,
            "existing run must not be overwritten");
    std::cout << "Actual TLS " << profile << " / " << mode
              << " passed: " << output << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
