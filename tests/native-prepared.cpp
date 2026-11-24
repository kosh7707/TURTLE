// Cross-role timing decisions use only comparable clocks or causal release.
#include "native/stream_start.hpp"
#include <iostream>
using namespace turtle::native::detail;
int main() try {
  Json raw = {{"run_id", "r"},
              {"connection_id", "c"},
              {"pid", {{"client", 10}, {"server", 11}}}};
  Json reports;
  for (auto r : {"client", "server"}) {
    auto pid = raw.at("pid").at(r);
    reports[r] = {{"status", "verified"},
                  {"lifecycle",
                   {{"ready", {{"pid", pid}, {"seq", 1}, {"ns", 10}}},
                    {"hs_begin", {{"pid", pid}, {"seq", 2}, {"ns", 22}}}}}};
  }
  auto proof = [&](Json expected) {
    if (prepared_start_proof(raw, reports).at("verified") != expected)
      throw std::runtime_error("prepared_start_verdict");
  };
  proof(nullptr);
  raw["time_namespaces"] = {{"client", "time:[1]"}, {"server", "time:[2]"}};
  proof(nullptr);
  raw["time_namespaces"]["server"] = "time:[1]";
  proof(true);
  reports["server"]["lifecycle"]["ready"]["ns"] = 30;
  proof(false);
  reports["server"]["lifecycle"]["ready"]["ns"] = 22;
  proof(nullptr); // coarse equality is not ordering
  reports["server"]["lifecycle"]["ready"] = nullptr;
  proof(nullptr);
  raw["time_namespaces"]["server"] = "time:[2]";
  auto &rendezvous = raw["prepared_start"];
  rendezvous = {{"v", 1},
                {"run_id", "r"},
                {"connection_id", "c"},
                {"outcome", "joint_release"}};
  for (auto r : {"client", "server"}) {
    auto pid = raw.at("pid").at(r);
    rendezvous["roles"][r] = {{"pid", pid},
                              {"sender_pid", pid},
                              {"ack_sender_pid", pid},
                              {"ready_received_ns", 120},
                              {"release_begin_ns", 130},
                              {"ack_received_ns", 140},
                              {"release", "G"},
                              {"release_token", pid},
                              {"ack_token", pid},
                              {"participant_ready_ns", 10},
                              {"participant_ack_ns", 20}};
  }
  proof(true); // no dependence on aligned host/participant clock origins
  reports["client"]["lifecycle"]["hs_begin"]["ns"] = 19;
  proof(false);
  reports["client"]["lifecycle"]["hs_begin"]["ns"] = 22;
  rendezvous["outcome"] = "unsynchronized_fallback";
  proof(nullptr);
  rendezvous["outcome"] = "joint_release";
  rendezvous["roles"]["server"]["sender_pid"] = 20;
  try {
    proof(true);
  } catch (const std::runtime_error &e) {
    if (std::string(e.what()) == "invalid_prepared_release")
      return 0;
    throw;
  }
  return 1;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
