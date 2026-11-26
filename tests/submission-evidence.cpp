#include "submission/connection_evidence.hpp"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using turtle::artifact::Json;
using turtle::submission::app_evidence;
using turtle::submission::read_transport;

void check(bool test, const char *why) {
  if (!test)
    throw std::runtime_error(why);
}
Json event(const char *name, unsigned ns, unsigned seq, unsigned len = 0) {
  return {{"name", name}, {"ns", ns}, {"seq", seq}, {"length", len}};
}
Json send(unsigned start, unsigned end, unsigned length) {
  return {{"complete", true},
          {"content_consistent", true},
          {"write_offer_pairs", true},
          {"first_write_attempt", event("write_attempt", start, start, length)},
          {"final_write_accept", event("write_accepted", end, end, length)}};
}
Json recv(unsigned first, unsigned last, unsigned validated) {
  return {{"complete", true},
          {"content_consistent", true},
          {"first_read_return", event("read_return", first, first, 1)},
          {"last_read_return", event("read_return", last, last, 3)},
          {"validated", event("validated", validated, validated, 4)}};
}
Json participant(bool client) {
  auto complete = client ? 24u : 36u;
  return {{"lifecycle",
           {{"hs_complete", event("hs_complete", complete, complete)},
            {"auth_accepted", event("auth_accepted", complete - 1, complete - 1)},
            {"local_finished_message",
             event("local_finished_message", 22, 22)},
            {"peer_finished_message", event("peer_finished_message", 34, 34)}}},
          {"timeline", {{"CAD", nullptr}, {"SAD1", nullptr}, {"SAD2", nullptr}}},
          {"message_events", Json::array()},
          {"metrics", {{"authentication", true}, {"peer_task", true}}},
          {"negotiated", {{"version", 0x304}}},
          {"facts", {{"resumed", false},
                     {"early_data", false},
                     {"verify_peer", true},
                     {"peer_verified", true},
                     {"peer_cert_present", true}}}};
}

int main() try {
  // Values are analyzer-derived, not controller times. The two clocks must
  // never be compared against one another, even if a fixture uses small ns.
  const Json application{{"request", "ping"}, {"greeting", "helo"},
                         {"response", "pong"}};
  auto client = participant(true), server = participant(false);
  client["timeline"]["CAD"] = send(27, 28, 4);
  server["timeline"]["CAD"] = recv(38, 39, 41);
  server["timeline"]["SAD1"] = send(28, 29, 4);
  client["timeline"]["SAD1"] = recv(32, 33, 34);
  server["timeline"]["SAD2"] = send(42, 45, 4);
  client["timeline"]["SAD2"] = recv(33, 48, 49); // one boundary shares a read
  server["facts"]["server_first"] = true;
  const Json pair{{"client", client}, {"server", server}};
  auto run = [&](const Json &p, const char *scenario = "S4") {
    return app_evidence(p, scenario, "mtls", application, "server");
  };
  const auto good = run(pair);
  check(good.at("state") == "passed", "complete exchange rejected");
  check(good.at("messages").at("SAD1").at("expected_hex") == "68656c6f",
        "distinct greeting content missing");
  check(good.at("messages").at("SAD2").at("first_read_return").at("monotonic_ns") ==
            33 &&
            good.at("messages").at("SAD2").at("full_read_return").at("monotonic_ns") ==
                48 &&
            good.at("messages").at("SAD2").at("first_to_full_read_span").at("delta_ns") == 15,
        "response first byte/full-byte evidence conflated");
  check(good.at("client_order").at("tls_message_vs_app_read") ==
            "local_finished_message_before_greeting_full_read" &&
            good.at("client_order").at("transport_order").is_null(),
        "TLS callback was promoted into a wire event");
  auto bad = pair;
  bad["server"]["lifecycle"]["hs_complete"] = event("hs_complete", 43, 43);
  check(run(bad).at("state") == "failed", "response preceded handshake");
  bad = pair;
  bad["server"]["timeline"]["CAD"]["validated"] = event("validated", 44, 44, 4);
  check(run(bad).at("state") == "failed", "response preceded CAD validation");
  bad = pair;
  bad["server"]["timeline"]["SAD2"]["first_write_attempt"] = nullptr;
  check(run(bad).at("state") == "insufficient_evidence",
        "missing response write timestamp qualified");
  bad = pair;
  bad["client"]["timeline"]["SAD2"]["content_consistent"] = false;
  check(run(bad).at("state") == "failed", "wrong response content qualified");
  bad = pair;
  bad["client"]["facts"].erase("resumed");
  check(run(bad).at("state") == "insufficient_evidence",
        "missing runtime check became false fact");
  bad = pair;
  bad["server"]["facts"]["resumed"] = true;
  check(run(bad).at("state") == "failed", "resumption qualified");
  bad = pair;
  bad["server"]["lifecycle"]["peer_finished_message"] = nullptr;
  check(run(bad).at("state") == "insufficient_evidence",
        "greeting without pre-Finished proof qualified");
  bad["server"]["lifecycle"]["local_finished_message"] = nullptr;
  const auto peer_evidence = app_evidence(bad, "S4", "mtls", application, "client");
  check(peer_evidence.at("state") == "passed" &&
            peer_evidence.at("server_first").at("basis") == "peer_greeting_path_and_app_io",
        "peer accepted greeting path must not require TLS callbacks");
  bad = pair;
  bad["server"]["lifecycle"]["peer_finished_message"] =
      event("peer_finished_message", 27, 27);
  check(run(bad).at("state") == "failed", "late greeting qualified");
  bad = pair;
  bad["client"]["lifecycle"]["local_finished_message"] = nullptr;
  check(run(bad).at("state") == "passed" &&
            run(bad).at("client_order").at("tls_message_vs_app_read").is_null(),
        "unresolvable client event order invalidated a valid exchange");
  Json no_app{{"client", participant(true)}, {"server", participant(false)}};
  const auto s0 = run(no_app, "S0");
  check(s0.at("state") == "passed" &&
            s0.at("application_bytes").at("server").at("sent") == 0 &&
            s0.at("application_bytes").at("client").at("received") == 0,
        "zero app exchange not verified");
  no_app["client"]["message_events"].push_back(
      event("write_accepted", 28, 28, 1));
  check(run(no_app, "S0").at("state") == "failed",
        "unexpected S0 application bytes qualified");

  const Json native_timing{{"begin", event("hs_begin", 5, 1)},
                           {"end", event("write_accepted", 17, 4, 4)},
                           {"wall_ns", 12}};
  auto timing = native_timing;
  timing["end"]["message"] = "SAD1";
  const auto sdk = turtle::submission::sdk_application_interval(timing, "server");
  check(sdk.at("clock") == "CLOCK_MONOTONIC" && sdk.at("delta_ns") == 12 &&
            sdk.at("start").at("event") == "hs_begin" &&
            sdk.at("end").at("layer") == "application" &&
            sdk.at("end").at("role") == "server" &&
            sdk.at("end").at("message") == "SAD1",
        "SDK application interval loses the actual role-local endpoint");
  timing["wall_ns"] = nullptr;
  check(turtle::submission::sdk_application_interval(timing, "server").is_null(),
        "invented SDK wall interval with unavailable timing");

  const std::string prefix = "event,monotonic_ns,bytes\nbefore_send_offer,10,20\nafter_recv,20,7\n";
  const std::string full = prefix + "after_recv,30,120\n";
  std::istringstream stream(full), count("3\n");
  const auto hooks = read_transport(stream, count, "server", event("hs_complete", 23, 23),
                                    event("read_return", 33, 33));
  check(hooks.at("coverage_span").at("start").at("direction") == "send" &&
            hooks.at("coverage_span").at("end").at("bytes") == 120 &&
            hooks.at("coverage_span").at("delta_ns") == 20,
        "scope/ends of ciphertext hook span lost");
  check(hooks.at("cad_receive_boundary").at("candidate").at("monotonic_ns") == 30 &&
            hooks.at("cad_receive_boundary").at("identified").is_null(),
        "unattributed cipher record was identified as CAD");
  const auto rejected = [](const std::string &rows, const std::string &size) {
    std::istringstream invalid(rows), receipt(size);
    try {
      (void)read_transport(invalid, receipt, "server", nullptr, nullptr);
    } catch (...) {
      return true;
    }
    return false;
  };
  check(rejected(prefix, "3\n"), "valid shorter CSV yielded a counterfeit last hook");
  for (auto size : {"", "3", "3\n\n", "2\n", "03\n", "0\n", "3x\n", " 3\n",
                    "18446744073709551616\n"})
    check(rejected(full, size), "invalid or mismatched producer count accepted");
  for (auto row : {"after_recv,5,7\n", "after_recv,20,-7\n",
                   "after_recv,20,0\n", "after_recv,20,7,9\n", "after_recv,20,7"}) {
    check(rejected(prefix + row, "3\n"),
          "reversed, zero, negative, incomplete or extra-column hook accepted");
  }
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
