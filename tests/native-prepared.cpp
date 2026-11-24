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
  {
    auto host = raw;
    auto anchors = reports;
    host["prepared_start"]["host_time_namespace"] = "time:[1]";
    auto &c = host["prepared_start"]["roles"]["client"];
    c["participant_ready_ns"] = 110;
    c["participant_ack_ns"] = 135;
    anchors["client"]["lifecycle"]["hs_begin"]["ns"] = 150;
    auto check = [&](const char *error = nullptr) {
      try {
        if (prepared_start_proof(host, anchors).at("basis") != "prepared_rendezvous")
          throw std::runtime_error("missing_causal_start");
      } catch (const std::runtime_error &e) {
        if (error && std::string_view(e.what()) == error)
          return;
        throw;
      }
      if (error)
        throw std::runtime_error("accepted_impossible_causal_order");
    };
    check();
    host["time_namespaces"].erase("server"); // role/host comparison is independent
    check();
    c["participant_ready_ns"] = 121;
    check("invalid_prepared_release_time");
    c["participant_ready_ns"] = 110;
    c["participant_ack_ns"] = 129;
    check("invalid_prepared_release_time");
    for (auto unavailable : {"", "unknown"}) {
      c["time_namespace"] = unavailable;
      check("invalid_prepared_release_time"); // launch clock remains known
    }
    host["time_namespaces"].erase("client");
    c["time_namespace"] = "time:[1]";
    check("invalid_prepared_release_time"); // packet alone identifies host clock
    host["time_namespaces"]["client"] = "time:[1]";
    c.erase("time_namespace");
    c["participant_ack_ns"] = 141;
    check("invalid_prepared_release_time");
    c["participant_ack_ns"] = 135;
    c["time_namespace"] = "time:[8]";
    check("participant_start_clock_domain_conflict");
    c.erase("time_namespace");
    host["prepared_start"]["host_time_namespace"] = "time:[8]";
    host["time_namespaces"]["server"] = "time:[1]";
    check("invalid_participant_start_order"); // client READY after server ACK
    auto &sr = host["prepared_start"]["roles"]["server"];
    sr["participant_ready_ns"] = 110;
    sr["participant_ack_ns"] = 135;
    anchors["server"]["lifecycle"]["hs_begin"]["ns"] = 150;
    check(); // comparable participants, independent supervisor clock
  }
  reports["client"]["lifecycle"]["hs_begin"]["ns"] = 19;
  proof(false);
  reports["client"]["lifecycle"]["hs_begin"]["ns"] = 22;
  rendezvous["outcome"] = "unsynchronized_fallback";
  proof(nullptr);
  rendezvous["outcome"] = "joint_release";
  auto reject_release = [&] {
    try {
      (void)prepared_start_proof(raw, reports);
    } catch (const std::runtime_error &e) {
      if (std::string(e.what()) == "invalid_prepared_release")
        return;
      throw;
    }
    throw std::runtime_error("accepted_invalid_prepared_release");
  };
  auto &server = rendezvous["roles"]["server"];
  server["ack_token"] = 10;
  reject_release(); // ACK from opposite participant
  server["release_token"] = 10;
  reject_release(); // matching ACKs, but no distinct participant challenges
  server["release_token"] = server["ack_token"] = 11;
  server["sender_pid"] = 20;
  reject_release();
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
