#include "artifact/network_evidence.hpp"
#include "control/spec.hpp"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
using turtle::artifact::Json;
namespace {
void expect(bool ok) {
  if (!ok)
    throw std::runtime_error("network evidence assertion failed");
}
template <class F> void rejects(F f) {
  try {
    f();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error("invalid network accepted");
}
Json link(const char *dev) {
  return {{"ifname", dev},   {"ifindex", 2},
          {"link_index", 2}, {"mtu", 1500},
          {"flags", {"UP"}}, {"linkinfo", {{"info_kind", "veth"}}}};
}
Json queue(const char *dev, double loss) {
  return {{"dev", dev},
          {"root", true},
          {"kind", "netem"},
          {"handle", std::string(dev) + ":"},
          {"packets", 1},
          {"bytes", 100},
          {"drops", 0},
          {"options",
           {{"limit", 10000},
            {"delay", {{"delay", .008}}},
            {"loss-random", {{"loss", loss}}}}}};
}
void preflight_policy(const char *self, const char *failure,
                      const char *category) {
  const Json endpoint = {{"binary", std::filesystem::absolute(self).string()},
                         {"env", {{"TURTLE_TEST_PMU_FAILURE", failure}}}};
  const Json cfg = {{"id", "test"},
                    {"client", endpoint},
                    {"server", endpoint},
                    {"measurement_contract", "counts-enough.v1"},
                    {"required_metrics", {"perf_counters"}}};
  const auto spec = turtle::control::resolve_spec({{"configurations", {cfg}}});
  const auto report =
      turtle::control::preflight(spec).at("configurations").at("test");
  expect(report.at("ready") == false &&
         report.at("features").at("perf_counters").at("availability") ==
             category);
  const bool undecided =
      report.at("reasons") == Json::array({"partial_pmu_policy_undecided"});
  expect(undecided == (std::string_view(category) == "decision_required"));
}
void test() {
  using namespace turtle::artifact;
  const Json req = normalized_netem(
      {{"additional_rtt_ms", 16}, {"client_to_server", {{"loss_pct", 20}}}});
  expect(req["client_to_server"]["delay_ms"] == 8 &&
         req["server_to_client"]["delay_ms"] == 8);
  for (const Json &bad : std::vector<Json>{
           {{"rtt_ms", 4}},
           {{"client_to_server", {{"los_pct", 15}}}},
           {{"additional_rtt_ms", 1}, {"server_to_client", {{"delay_ms", 3}}}},
           {{"additional_rtt_ms", -1}},
           {{"client_to_server", {{"loss_pct", 20.1}}}},
           {{"mtu", false}}})
    rejects([&] { normalized_netem(bad); });
  Json st = {{"client", {{"links", {link("eth0")}}}},
             {"server", {{"links", {link("eth0")}}}},
             {"middle",
              {{"links", {link("mc"), link("ms")}},
               {"qdisc", {queue("mc", 0), queue("ms", .2)}}}}};
  Json actual = {{"availability", "available"},
                 {"requested", req},
                 {"topology", "client-middle-server"},
                 {"before", st},
                 {"after", st},
                 {"cleanup_errors", Json::array()}};
  for (auto &q : actual["after"]["middle"]["qdisc"]) {
    q["packets"] = 8;
    q["bytes"] = 450;
  }
  verify_netem(req, actual); // No observed drops is possible even with positive
                             // configured loss.
  auto bad = [&](auto change) {
    auto a = actual;
    change(a);
    rejects([&] { verify_netem(req, a); });
  };
  bad([](Json &a) {
    a["before"]["middle"]["qdisc"][0]["options"]["loss-random"]["loss"] = .2;
  });
  bad([](Json &a) { a["after"]["server"]["links"][0]["mtu"] = 1400; });
  bad([](Json &a) { a["after"]["server"]["links"][0]["link_index"] = 99; });
  bad([](Json &a) { a["after"]["middle"]["qdisc"][0].erase("drops"); });
  bad([](Json &a) { a["after"]["middle"]["qdisc"][1]["packets"] = 0; });
  bad([](Json &a) {
    a["after"]["middle"]["qdisc"][1]["options"]["delay"]["delay"] = 8;
  });
  bad([](Json &a) { a["snapshot_error"] = "failed"; });
  bad([](Json &a) { a["topology"] = "loopback"; });
}

void live(const char *cli, const char *target, std::filesystem::path base) {
  using namespace turtle::artifact;
  using turtle::process::command;
  namespace fs = std::filesystem;
  fs::create_directories(base);
  auto temp = (base / "trial-XXXXXX").string();
  expect(::mkdtemp(temp.data()) != nullptr);
  fs::path root(temp), run = root / "result";
  Json profile = {{"v", 1},
                  {"target", {{"role", "client"}, {"argv", {target}}}},
                  {"auth", "mtls"},
                  {"scenario", "S3"},
                  {"warmups", 0},
                  {"repetitions", 1},
                  {"netem",
                   {{"additional_rtt_ms", 16},
                    {"mtu", 1000},
                    {"client_to_server",
                     {{"loss_pct", 20}, {"seed", 77}, {"rate_mbit", 10}}},
                    {"server_to_client", {{"loss_pct", 0}, {"seed", 19}}}}}};
  save(root / "profile.json", profile);
  expect(
      command({cli, "run", (root / "profile.json").string(), run.string()}, 120)
          .at("returncode") == 0);
  expect(load(run / "analysis.json").at("eligible_measurements") == 1);
  expect(command({cli, "analyze", run.string()}).at("returncode") == 0);
  const auto copy = root / "contradictory";
  fs::copy(run, copy, fs::copy_options::recursive);
  const auto raw = copy / "attempts/00000/network.json";
  auto witness = load(raw);
  for (auto &q : witness.at("after").at("middle").at("qdisc"))
    if (q.at("dev") == "ms" && q.at("kind") == "netem")
      q.at("options").erase("loss-random");
  save(raw, witness);
  auto manifest = load(copy / "manifest.json");
  manifest.at("attempts").at(0).at("artifacts_sha256").at("network.json") =
      turtle::process::digest(raw);
  save(copy / "manifest.json", manifest);
  expect(command({cli, "analyze", copy.string()}).at("returncode") != 0);
  expect(load(copy / "analysis.json").at("eligible_measurements") == 0);
  auto attempt = load(copy / "attempts/00000/analysis.json");
  expect(attempt.at("success") == true &&
         attempt.at("ordinary_timing_sample") == false &&
         attempt.at("configuration_invalid_reasons") ==
             Json::array({"netem_evidence_unverified:netem_setting_mismatch"}));
}
} // namespace
int main(int argc, char **argv) {
  try {
    if (argc == 5 && std::string_view(argv[1]) == "--live") {
      live(argv[2], argv[3], argv[4]);
      return 0;
    }
    if (argc > 1 && std::string_view(argv[1]) == "--role") {
      Json reply = {{"ready", true},
                    {"headers", false},
                    {"public_io", false},
                    {"monotonic_clock", true},
                    {"perf_counters", false},
                    {"perf_reason", std::getenv("TURTLE_TEST_PMU_FAILURE")}};
      std::cout << reply.dump() << '\n';
      return 0;
    }
    test();
    preflight_policy(argv[0], "instructions_open_failed", "decision_required");
    preflight_policy(argv[0], "cycles_open_failed", "unsupported");
    if (argc == 2) {
      auto n = turtle::artifact::load(argv[1]);
      turtle::artifact::verify_netem(n.at("requested"), n);
    }
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
