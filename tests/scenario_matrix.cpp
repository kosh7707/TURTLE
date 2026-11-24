// Black-box exercise of the compact profile, including negative replay.
// Each cell runs a fresh TLS connection; none of the tests compare performance.
#include "artifact/json.hpp"
#include "process/process.hpp"
#include <filesystem>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
using turtle::artifact::Json;
using turtle::artifact::load;
using turtle::artifact::read_text;
using turtle::artifact::save;
namespace fs = std::filesystem;
namespace {
void require(bool ok, const std::string &why) {
  if (!ok)
    throw std::runtime_error(why);
}
Json invoke(const turtle::process::Args &args) {
  return turtle::process::command(args, 45);
}
struct NoCounters {};
void check_host(const fs::path &out) {
  const auto reasons =
      load(out / "check.json").at("configurations").at("target").at("reasons");
  if (reasons == Json::array({"required_metric_unavailable:perf_counters"}))
    throw NoCounters{};
}
struct Cell {
  std::string scenario, auth, role;
  bool presend() const { return scenario == "S2" || scenario == "S4"; }
};
Json profile(const Cell &c, const Json &args) {
  return {{"v", 1},
          {"target", {{"role", c.role}, {"argv", args}}},
          {"scenario", c.scenario},
          {"auth", c.auth},
          {"warmups", 0},
          {"repetitions", 1},
          {"app_chunk", 2},
          {"timeout_seconds", 30}};
}
void inspect(const Cell &c, const fs::path &out) {
  const auto report = load(out / "analysis.json");
  require(report.at("complete") == true &&
              report.at("eligible_measurements") == 1,
          "missing eligible cell: " + out.string());
  require(report.at("scenario_support").at("target") == "supported",
          "support not established");
  const auto m = load(out / "manifest.json");
  const auto &cfg = m.at("spec").at("configurations").at(0);
  const auto &slots = m.at("attempts"), &pins = cfg.at("build_sha256");
  require(slots.size() == (c.presend() ? 2u : 1u),
          "unexpected connection count");
  std::set<std::string> ids;
  for (const auto &slot : slots) {
    const auto dir = out / slot.at("directory").get<std::string>();
    const bool probe = slot.at("purpose") == "capability";
    const auto b = load(dir / "binding.json"), a = load(dir / "analysis.json");
    require(ids.insert(slot.at("run_id")).second, "reused connection id");
    require(b.at("server_sha256") == pins.at("server") &&
                b.at("client_sha256") ==
                    pins.at(probe ? "probe_client" : "client") &&
                b.at("probe_client_substituted") == probe,
            "wrong participant binding");
    require(a.at("ordinary_timing_sample") == !probe &&
                a.at("eligible") == true,
            "probe/measurement confusion");
    for (const auto &row : a.at("measurements"))
      if (probe)
        require(row.at("valid_sample") == false, "probe contributed a sample");
    auto client = load(dir / "client/endpoint.json"),
         server = load(dir / "server/endpoint.json");
    require(client.at("negotiated").at("peer_verified") == true &&
                server.at("negotiated").at("peer_verified") ==
                    (c.auth == "mtls"),
            "wrong authentication");
    const auto cl = read_text(dir / "client/control.log"),
               sl = read_text(dir / "server/control.log");
    if (probe) {
      require(cl.starts_with("READY\nPAUSED\nGREETING\n") &&
                  sl.find("\nPRESEND ") != std::string::npos,
              "capability connection lacks frozen greeting proof");
    } else {
      require(cl.starts_with("READY\n") &&
                  cl.find("PAUSED") == std::string::npos &&
                  cl.find("GREETING") == std::string::npos &&
                  sl.find("PRESEND") == std::string::npos,
              "barrier leaked into measurement");
      require(client.at("scenario").at("content_verified") == true &&
                  server.at("scenario").at("content_verified") == true,
              "incomplete content evidence");
    }
  }
}
void reject_corrupt_proof(const std::string &cli, const fs::path &source,
                          const fs::path &dest) {
  fs::copy(source, dest, fs::copy_options::recursive);
  auto m = load(dest / "manifest.json");
  auto dir = [&](size_t i) {
    return dest / m.at("attempts").at(i).at("directory").get<std::string>();
  };
  fs::remove(dir(0) / "server/control.log");
  require(invoke({cli, "analyze", dest.string()}).at("returncode") != 0,
          "missing probe accepted");
  auto run = load(dest / "analysis.json"),
       sample = load(dir(1) / "analysis.json");
  require(run.at("eligible_measurements") == 0 &&
              run.at("scenario_support").at("target") == "unconfirmed",
          "missing evidence mislabeled as supported/unsupported");
  require(sample.at("eligible") == false &&
              sample.at("ordinary_timing_sample") == false,
          "measurement retained despite missing probe");
  for (const auto &row : sample.at("measurements"))
    require(row.at("valid_sample") == false, "ungated row");
}
void reject_fault(const std::string &cli, const fs::path &root,
                  const std::string &fault, const std::string &name) {
  const auto file = root / (name + ".json"), out = root / name;
  save(file, profile({"S4", "mtls", "server"}, Json::array({fault, name})));
  require(invoke({cli, "run", file.string(), out.string()}).at("returncode") !=
              0,
          "fault accepted");
  if (name == "late")
    check_host(out);
  auto result = load(out / "analysis.json");
  require(result.at("eligible_measurements") == 0 &&
              result.at("scenario_support").at("target") ==
                  (name == "late" ? "unconfirmed" : "unsupported"),
          "failed capability classified incorrectly: " + name);
  if (name == "late") {
    const auto &m = load(out / "manifest.json");
    require(m.at("attempts").size() == 1 &&
                m.at("attempts").front().at("purpose") == "capability",
            "unproven capability advanced to measurement");
    auto dir =
        out / m.at("attempts").front().at("directory").get<std::string>();
    require(load(dir / "server/endpoint.json").at("invalid_reason") ==
                "probe_handshake_completed_before_presend",
            "late server wasn't rejected at the advertised operation");
  }
}
void duplex(const std::string &cli, const std::string &target,
            const fs::path &root) {
  auto p = profile({"S4", "mtls", "client"}, Json::array({target}));
  p["application"] = {{"request", std::string(16384, 'Q')},
                      {"greeting", std::string(16384, 'G')},
                      {"response", "pong"}};
  p["app_chunk"] = 256;
  p["timeout_seconds"] = 30;
  save(root / "profile.json", p);
  auto out = root / "run";
  auto command =
      invoke({cli, "run", (root / "profile.json").string(), out.string()});
  if (command.at("returncode") != 0)
    check_host(out);
  require(command.at("returncode") == 0, root.string() + ": " + command.dump());
  inspect({"S4", "mtls", "client"}, out);
  auto m = load(out / "manifest.json");
  auto d = out / m.at("attempts").back().at("directory").get<std::string>() /
           "client";
  require(read_text(d / "stderr.log").find("stress TCP socket buffers:") !=
              std::string::npos,
          "missing kernel buffer witness");
  std::istringstream input(read_text(d / "events.jsonl"));
  unsigned first_write = 0, last_write = 0, first_read_attempt = 0,
           first_read = 0;
  for (std::string line; std::getline(input, line);) {
    auto e = Json::parse(line);
    if (e.at("kind") != "call")
      continue;
    unsigned id = e.at("id");
    if (e.at("operation") == "application_write") {
      if (!first_write)
        first_write = id;
      if (e.at("success") == true)
        last_write = id;
    }
    if (!first_read_attempt && e.at("operation") == "application_read")
      first_read_attempt = id;
    if (!first_read && e.at("operation") == "application_read" &&
        e.at("success") == true)
      first_read = id;
  }
  require(first_write && first_write < first_read_attempt && first_read &&
              first_read < last_write,
          "client did not initiate CAD before greeting and drain greeting "
          "while CAD remained");
}
} // namespace
int main(int argc, char **argv) {
  try {
    if (argc != 6 && argc != 8)
      return 2;
    const std::string cli = argv[1], target = argv[2], fault = argv[3];
    fs::create_directories(argv[4]);
    auto templ = (fs::path(argv[4]) / "cell-XXXXXX").string();
    require(::mkdtemp(templ.data()) != nullptr, "mkdtemp");
    const fs::path root = templ;
    if (argc == 6 && std::string_view(argv[5]) == "duplex") {
      duplex(cli, target, root);
      return 0;
    }
    if (argc == 6 && std::string_view(argv[5]) != "tamper") {
      reject_fault(cli, root, fault, argv[5]);
      return 0;
    }
    Cell c = argc == 6 ? Cell{"S4", "mtls", "client"}
                       : Cell{argv[5], argv[6], argv[7]};
    auto file = root / "profile.json", out = root / "run";
    save(file, profile(c, Json::array({target})));
    auto run = invoke({cli, "run", file.string(), out.string()});
    if (run.at("returncode") != 0)
      check_host(out);
    require(run.at("returncode") == 0, out.string() + ":" + run.dump());
    inspect(c, out);
    if (argc == 6)
      reject_corrupt_proof(cli, out, root / "corrupt");
    std::cout << "Verified: " << root << '\n';
  } catch (const NoCounters &) {
    std::cerr << "Cannot validate a measured TLS cell: no hardware counters\n";
    return 77;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
