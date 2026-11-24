#include "artifact/json.hpp"
#include "process/process.hpp"
#include <filesystem>
#include <iostream>
#include <set>
using namespace turtle;
using artifact::Json;
namespace fs = std::filesystem;
static void expect(bool condition, const char *reason) {
  if (!condition)
    throw std::runtime_error(reason);
}
static void ok(const process::Args &args) {
  auto p = process::command(args, 90);
  if (p.at("returncode") != 0)
    throw std::runtime_error(p.dump());
}
int main(int argc, char **argv) {
  try {
    expect(argc == 5, "usage: one_side CONTROLLER TARGET WORK FAULT_CLIENT");
    auto cli = fs::absolute(argv[1]).string(),
         target = fs::absolute(argv[2]).string();
    fs::path root = fs::absolute(argv[3]);
    fs::create_directories(root);
    for (unsigned i = 0;; ++i) {
      auto p = root / ("run-" + std::to_string(i));
      if (fs::create_directory(p)) {
        root = p;
        break;
      }
    }
    auto spec = root / "benchmark.json", out = root / "results";
    // The target is deliberately relative to a spec outside the invoking cwd.
    auto name = "target with spaces;not shell";
    fs::create_symlink(target, root / name);
    artifact::save(spec, {{"v", 1},
                          {"target", {{"role", "client"}, {"argv", {name}}}},
                          {"scenario", "S3"},
                          {"auth", "mtls"},
                          {"repetitions", 2}});
    auto pre = process::command({cli, "check", spec.string()});
    if (pre.at("returncode") != 0) {
      auto text = pre.at("stdout").get<std::string>();
      if (text.find("required_metric_unavailable:perf_counters") !=
              std::string::npos &&
          text.find("endpoint_check_failed") == std::string::npos)
        return 77;
      throw std::runtime_error(pre.dump());
    }
    ok({cli, "run", spec.string(), out.string()});
    auto summary = artifact::load(out / "analysis.json"),
         m = artifact::load(out / "manifest.json");
    expect(summary.at("measurement_count") == 2 &&
               summary.at("eligible_measurements") == 2 &&
               summary.at("diagnostics").size() == 1,
           "warmup or missing measurements");
    auto &c = m.at("spec").at("configurations").at(0);
    expect(c.at("measurement_contract") == "counts-enough.v1" &&
               c.at("measured_role") == "client",
           "wrong contract");
    std::set<std::string> ids;
    unsigned measures = 0;
    for (const auto &s : m.at("attempts")) {
      auto dir = out / s.at("directory").get<std::string>();
      expect(ids.insert(s.at("run_id")).second, "duplicate run_id");
      auto client = artifact::load(dir / "client/endpoint.json"),
           server = artifact::load(dir / "server/endpoint.json");
      expect(client.at("negotiated").at("peer_verified") == true &&
                 server.at("negotiated").at("peer_verified") == true,
             "mTLS authentication not proven");
      expect(client.at("scenario").at("content_verified") == true &&
                 server.at("scenario").at("content_verified") == true,
             "payload validation missing");
      auto report = artifact::load(dir / "analysis.json");
      if (s.at("purpose") == "warmup") {
        expect(report.at("ordinary_timing_sample") == false, "warmup leaked");
        continue;
      }
      ++measures;
      auto &r = report.at("roles").at("client");
      auto ctr = artifact::load(dir / "client/counters.json");
      auto &b = ctr.at("scenario").at("begin"),
           &e = ctr.at("scenario").at("end");
      expect(b.at("tid") == e.at("tid") && b.at("tid") == ctr.at("owner_tid"),
             "counter thread mismatch");
      for (auto k : {"cycles", "instructions"}) {
        auto delta = artifact::integer(e.at(k)) - artifact::integer(b.at(k));
        expect(delta > 0 && r.at("counters")
                                    .at("operations")
                                    .at("scenario")
                                    .at(k)
                                    .at("value") == delta,
               "counter replay mismatch");
      }
      const auto &sc = client.at("scenario");
      auto wall = artifact::integer(sc.at("end").at("wall_ns")) -
                  artifact::integer(sc.at("begin").at("wall_ns"));
      auto &point = r.at("metrics").at("first_response_wall_ns");
      expect(point.at("value") == wall &&
                 point.at("end_event") == sc.at("end_event") &&
                 r.at("metrics").at("scenario_wall_ns").at("value") == wall,
             "first response replay mismatch");
      expect(server.at("collection").at("perf_counters") == false,
             "peer PMU leakage");
    }
    expect(measures == 2 && ids.size() == 3, "attempt accounting");
    ok({cli, "analyze", out.string()});
    expect(artifact::load(out / "analysis.json") == summary,
           "offline summary unequal");
    // Changing source bytes after collection must invalidate that attempt.
    auto tampered = root / "tamper";
    fs::copy(out, tampered, fs::copy_options::recursive);
    auto dir =
        tampered / m.at("attempts").back().at("directory").get<std::string>();
    artifact::write_text(dir / "client/events.jsonl", "{}\n");
    expect(process::command({cli, "analyze", tampered.string()})
                       .at("returncode") != 0 &&
               artifact::load(tampered / "analysis.json")
                       .at("eligible_measurements") == 1,
           "tampering silently accepted");
    for (auto fault : {"missing-client-certificate", "partial"}) {
      auto bad = artifact::load(spec);
      bad["target"]["argv"] = {fs::absolute(argv[4]).string(), target, fault};
      bad["timeout_seconds"] = 6;
      auto p = root / (std::string(fault) + ".json"), result = root / fault;
      artifact::save(p, bad);
      expect(process::command({cli, "run", p.string(), result.string()})
                     .at("returncode") != 0,
             "fault accepted");
      expect(artifact::load(result / "analysis.json")
                     .at("eligible_measurements") == 0,
             "invalid sample counted");
      auto endpoint =
          artifact::load(result / "attempts/00000/server/endpoint.json");
      auto &task = endpoint.at("scenario");
      expect(task.at("complete") == false && task.at("plaintext_sent") == 0,
             "premature response");
      if (std::string_view(fault) == "partial")
        expect(task.at("plaintext_received") == 2 &&
                   endpoint.at("negotiated").at("peer_verified") == true,
               "partial bytes not authenticated and received");
    }
    std::cout << "Verified one-sided S3 mTLS, 1 warmup + 2 independent "
                 "raw-count measurements\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
