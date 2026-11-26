#include "native/evidence.hpp"
#include <cstring>
#include "native/stream.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <turtle/observe.h>
#include <unistd.h>

using J = turtle::artifact::Json;
namespace {
void ck(bool p, const char *reason) {
  if (!p)
    throw std::runtime_error(reason);
}
J context() {
  return {{"run_id", "r"},
          {"connection_id", "c"},
          {"role", "server"},
          {"scenario", "S4"},
          {"auth", "mtls"},
          {"messages", {{"CAD", 4}, {"SAD1", 4}, {"SAD2", 4}}},
          {"plaintext",
           {{"CAD", "70696e67"}, {"SAD1", "68656c6f"}, {"SAD2", "706f6e67"}}},
          {"peer_name", "client.turtle.test"},
          {"peer_full_handshake_auth", true},
          {"capability_proof", true}};
}
void event(const char *n) { turtle_observe_event(n); }
void plain(const char *n, const char *s) {
  turtle_observe_plain(n, s, std::strlen(s));
}
void produce() {
  event("ready");
  event("hs_begin");
  event("hs_progress");
  plain("write_attempt", "helo");
  plain("write_accepted", "he");
  plain("write_attempt", "lo");
  plain("write_accepted", "lo");
  event("hs_complete");
  event("auth_accepted");
  turtle_observe_fact("verify_peer", 1);
  turtle_observe_fact("peer_verified", 1);
  turtle_observe_fact("hrr", 0);
  turtle_observe_fact("early_data", 0);
  turtle_observe_fact("resumed", 0);
  turtle_observe_fact("server_first", 1);
  turtle_observe_identity(0x304, 0x1301, 0x1d, "client.turtle.test");
  plain("read_return", "pi");
  plain("read_return", "ng");
  plain("validated", "ping");
  plain("write_attempt", "pong");
  plain("write_accepted", "pong");
  event("end");
}
J capture_legacy_fixture(const char *self, const char *mode = "produce") {
  char path[] = "/tmp/turtle-evidence-XXXXXX";
  int fd = mkstemp(path);
  ck(fd > 2, "mkstemp");
  pid_t pid = fork();
  ck(pid >= 0, "fork");
  if (!pid) {
    setenv("TURTLE_EVIDENCE_FD", std::to_string(fd).c_str(), 1);
    setenv("TURTLE_RUN_ID", "r", 1);
    setenv("TURTLE_CONNECTION_ID", "c", 1);
    setenv("TURTLE_ROLE", "server", 1);
    setenv("TURTLE_PMU", std::string_view(mode) == "produce" ? "0" : "1", 1);
    execl(self, self, mode, nullptr);
    _exit(1);
  }
  int status;
  ck(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
         !WEXITSTATUS(status),
     "observer_failed");
  close(fd);
  std::ifstream f(path);
  unlink(path);
  const std::string raw((std::istreambuf_iterator<char>(f)), {});
  auto observed = turtle::native::analyze_evidence(raw, context());
  ck(observed.at("status") == "verified" &&
         observed.at("observer_stream") == "complete",
     "live observer did not produce a complete stream");
  // These fixtures deliberately edit/delete/reorder events to test record
  // semantics independently of the writer's seal and sequence.
  auto events = observed.at("events");
  for (auto &e : events)
    e["v"] = 1;
  return events;
}
J local_report(J events, const J &c) {
  std::string s;
  uint64_t seq = 0;
  for (auto &e : events) {
    e["seq"] = ++seq;
    s += e.dump() + "\n";
  }
  return turtle::native::analyze_evidence(s, c);
}
// Isolated endpoint tests supply the final opposite-role proof explicitly.
J run(J events, J c = context()) {
  auto report = local_report(std::move(events), c);
  turtle::native::qualify_flights(report, c.at("auth") == "mtls",
                                  c.at("peer_full_handshake_auth"));
  return report;
}
auto find(auto &es, const std::string &n) {
  auto it = std::find_if(es.begin(), es.end(),
                         [&](auto &e) { return e.value("name", "") == n; });
  ck(it != es.end(), "missing fixture event");
  return it;
}
void lifecycle_tests(const J &events) {
  auto r = run(events);
  ck(r["status"] == "verified" && r["observer_stream"] == "legacy_unsealed",
     "historical evidence remains readable without claiming completeness");
  ck(r["metrics"]["pmu"].is_null(), "no counterfeit PMU");
  ck(r["metrics"]["transport_counts"].is_null(), "absent hooks not counts");
  ck(r["timeline"]["SAD1"]["final_write_accept"]["offset"] == 2,
     "partial write");
  J es = events;
  auto offer = find(es, "write_attempt");
  (*offer)["length"] = 1;
  (*offer)["hex"] = "68";
  auto too_long = run(es);
  ck(too_long["metrics"]["task"] == false &&
         too_long["timeline"]["SAD1"]["complete"] == false &&
         too_long["timeline"]["SAD2"]["complete"] == true,
     "acceptance exceeded the actual native offer");
  es = events;
  auto complete = *find(es, "hs_complete");
  es.erase(find(es, "hs_complete"));
  complete["ns"] = find(es, "write_attempt")->at("ns");
  es.insert(find(es, "write_attempt"), complete);
  ck(run(es)["metrics"]["ordinary_server_first"] == false, "late greeting");
  es = events;
  find(es, "hrr")->at("value") = true;
  ck(run(es)["status"] == "contradicted", "HRR");
  es = events;
  find(es, "server_first")->at("value") = nullptr;
  J c = context();
  c["capability_proof"] = nullptr;
  ck(run(es, c)["status"] == "unknown", "absent proof");
  find(es, "server_first")->at("value") = false;
  ck(run(es, c)["status"] == "contradicted", "capability false");
  find(es, "server_first")->at("value") = "false";
  ck(run(es, c)["status"] == "invalid", "malformed fact");
  es = events;
  find(es, "read_return")->at("hex") = "0000";
  ck(run(es)["status"] == "contradicted", "wrong native bytes");
  es = events;
  es.erase(find(es, "validated"));
  ck(run(es)["timeline"]["CAD"]["complete"].is_null(),
     "isolated missing validation");
  ck(run(es)["timeline"]["SAD2"]["complete"] == true,
     "unrelated message survives");
  c = context();
  c["connection_id"] = "other";
  ck(run(events, c)["status"] == "invalid", "foreign connection");
  ck(run(J::array())["status"] == "unknown", "stock evidence missing");
}
// The new runner's ordinary TLS operations qualify tasks, not independent
// security assertions. An unmarked archive must still use its original rules.
void endpoint_contract_tests(const J &events) {
  auto c = context();
  c["capability_proof"] = nullptr;
  J plain = J::array();
  for (const auto &e : events) {
    if (e.at("kind") == "identity" ||
        (e.at("kind") == "fact" && e.value("name", "") != "server_first") ||
        e.value("name", "") == "auth_accepted")
      continue;
    plain.push_back(e);
  }
  ck(run(plain, c)["status"] == "unknown", "historical evidence stays unknown");
  c["scenario_contract"] = "endpoint.v1";
  auto r = run(plain, c);
  ck(r["status"] == "verified" && r["metrics"]["peer_task"] == true &&
         r["metrics"]["ordinary_server_first"] == true &&
         r["metrics"]["authentication"].is_null() &&
         r["metrics"]["profile"].is_null() &&
         r["metrics"]["full_handshake_auth"].is_null() &&
         r["metrics"]["tls_flights"].is_null(),
     "ordinary task without security queries or a CF delivery proof");
  auto changed = plain;
  changed.erase(find(changed, "server_first"));
  ck(run(changed, c)["metrics"]["ordinary_server_first"].is_null() &&
         run(changed, c)["status"] == "unknown",
     "a delayed handshake confirmation alone does not prove early write");
  changed = plain;
  changed.erase(find(changed, "read_return"));
  ck(run(changed, c)["metrics"]["peer_task"] != true,
     "cannot validate a request missing actual returned bytes");
  changed = plain;
  find(changed, "validated")->at("hex") = "00000000";
  ck(run(changed, c)["status"] == "contradicted", "wrong compared contents");
  auto denied = *find(events, "peer_verified");
  denied["value"] = false;
  changed = plain;
  changed.push_back(denied);
  ck(run(changed, c)["status"] == "contradicted", "explicit failed authentication");
  changed = plain;
  auto resumed = *find(events, "resumed");
  resumed["value"] = true;
  changed.push_back(resumed);
  ck(run(changed, c)["status"] == "contradicted", "resumption is not full TLS");
  c["expected_group"] = 29;
  ck(run(plain, c)["status"] == "unknown", "requested group not observed");
  c["peer_negotiated"] = {{"group", 29}};
  ck(run(plain, c)["status"] == "verified", "known matching requested group");
  c["peer_negotiated"]["group"] = 23;
  ck(run(plain, c)["status"] == "contradicted", "known wrong requested group");
  c["scenario_contract"] = "future";
  ck(run(plain, c)["status"] == "invalid", "unknown rules cannot qualify");
}
void submission_composite_greeting_test(const J &events) {
  auto c = context();
  c["scenario_contract"] = "endpoint.v1";
  J trace = J::array();
  bool complete = false;
  for (const auto &e : events) {
    const auto name = e.value("name", "");
    complete |= name == "hs_complete";
    if ((!complete && name != "ready" && name != "hs_begin") ||
        name == "server_first")
      continue;
    trace.push_back(e);
  }
  auto report = run(trace, c);
  ck(report["metrics"]["peer_task"] != true,
     "an unobserved greeting alone does not prove a completed exchange");
  auto fact = *find(events, "server_first");
  fact["name"] = "submission_greeting_accepted";
  fact["ns"] = find(trace, "hs_complete")->at("ns");
  trace.insert(find(trace, "auth_accepted"), fact);
  report = run(trace, c);
  ck(report["metrics"]["peer_task"] == true &&
         report["metrics"]["ordinary_server_first"].is_null() &&
         report["timeline"]["SAD1"]["first_write_attempt"].is_null() &&
         report["timeline"]["SAD1"]["final_write_accept"].is_null() &&
         report["timeline"]["SAD1"]["complete"].is_null() &&
         report["timeline"]["SAD2"]["final_write_accept"] ==
             report["timing"]["end"] &&
         report["metrics"]["message_timeline"].is_null(),
     "composite S4 confirms task without synthesizing an early send boundary");
  auto repeated = trace;
  repeated.insert(find(repeated, "auth_accepted"), fact);
  ck(run(repeated, c)["status"] == "invalid",
     "the composite sender can account for its greeting only once");
  auto premature = trace;
  premature.erase(find(premature, "submission_greeting_accepted"));
  premature.insert(find(premature, "hs_complete"), fact);
  ck(run(premature, c)["status"] == "invalid",
     "the composite sender can confirm its greeting only after accept returns");
  // A submission may expose real short I/O for the greeting, in addition
  // to confirming the whole composite operation on return.
  auto observed = events;
  observed.insert(find(observed, "auth_accepted"), fact);
  auto sf = *find(observed, "hs_progress");
  sf["name"] = "local_finished_message";
  observed.insert(find(observed, "hs_progress"), sf);
  auto cf = *find(observed, "hs_complete");
  cf["name"] = "peer_finished_message";
  observed.insert(find(observed, "hs_complete"), cf);
  report = run(observed, c);
  ck(report["metrics"]["peer_task"] == true &&
         report["metrics"]["ordinary_server_first"] == true &&
         report["timeline"]["SAD1"]["complete"] == true &&
         report["timeline"]["SAD2"]["complete"] == true &&
         report["lifecycle"]["local_finished_message"]["kind"] == "event" &&
         report["lifecycle"]["peer_finished_message"]["kind"] == "event",
     "observed greetings retain actual timing without double counting");
  auto partial = observed;
  partial.erase(find(partial, "peer_finished_message") - 1);
  ck(run(partial, c)["status"] == "invalid",
     "opaque acceptance must not fill a partially observed greeting");
  c["scenario"] = "S2";
  c["messages"] = {{"CAD", 0}, {"SAD1", 4}, {"SAD2", 0}};
  const auto end = *find(trace, "end");
  trace.erase(find(trace, "read_return"), trace.end());
  trace.push_back(end);
  report = run(trace, c);
  ck(report["metrics"]["peer_task"] == true &&
         report["metrics"]["ordinary_server_first"].is_null() &&
         report["metrics"]["timing"].is_null() &&
         report["timing"]["end"].is_null(),
     "composite S2 does not substitute the accept return for greeting timing");
  observed.erase(find(observed, "read_return"), observed.end());
  observed.push_back(end);
  const auto measured = run(observed, c);
  ck(measured["metrics"]["peer_task"] == true &&
         measured["timing"]["end"].is_null() &&
         measured["timing"]["unavailable_reason"] == "cf_transport_receive_unobserved" &&
         measured["timing"]["greeting_write_accept_ns"].is_number_unsigned() &&
         measured["lifecycle"]["peer_finished_message"].is_object(),
     "S2 server: greeting acceptance and a processed CF do not prove transport arrival");
}
void endpoint_first_read_test(const J &events) {
  auto c = context();
  c.update(J{{"role", "client"}, {"scenario", "S2"},
             {"scenario_contract", "endpoint.v1"},
             {"messages", {{"CAD", 0}, {"SAD1", 4}, {"SAD2", 0}}}});
  J es = J::array();
  auto add = [&](const char *name, const char *bytes = nullptr) {
    J row = *find(events, name);
    row["role"] = "client";
    // Delay only the second greeting fragment; first-byte time cannot move.
    row["ns"] = es.size() + 100 + (es.size() >= 3 ? 20'000'000 : 0);
    if (bytes) {
      row["hex"] = bytes;
      row["length"] = std::strlen(bytes) / 2;
    }
    es.push_back(row);
  };
  add("ready");
  add("hs_begin");
  es.back()["first_operation"] = "read_plain";
  add("read_return", "6865");
  auto partial = run(es, c);
  ck(partial["timing"]["end"].is_null() && partial["metrics"]["timing"].is_null() &&
         partial["timing"]["first_greeting_read_ns"] == 1 &&
         partial["metrics"]["task"].is_null() &&
         partial["timeline"]["SAD1"]["validated"].is_null(),
     "first usable bytes survive even an incomplete greeting");
  add("read_return", "6c6f");
  add("validated", "68656c6f");
  add("hs_complete");
  es.back()["confirmed_by"] = "handshake_until_local_complete";
  add("end");
  auto r = run(es, c);
  ck(r["status"] == "verified" && r["metrics"]["s2_read_first"] == true &&
         r["timing"]["end"]["seq"] == 4 &&
         r["timing"]["wall_ns"] == 20'000'002 &&
         r["timing"]["first_greeting_read_ns"] == 1 &&
         r["timeline"]["SAD1"]["validated"]["seq"] == 5 &&
         r["lifecycle"]["hs_complete"]["seq"] == 6 &&
         r["metrics"]["ordinary_server_first"].is_null(),
     "S2: first ordinary read, validation, and local confirmation are separate");
  auto late_tag = es;
  late_tag[1].erase("first_operation");
  late_tag[2]["first_operation"] = "read_plain"; // not first TLS entry
  auto unproven = run(late_tag, c);
  ck(unproven["metrics"]["s2_read_first"].is_null() &&
         unproven["metrics"]["task"].is_null() &&
         unproven["timing"]["end"]["seq"] == 4,
     "a later reported read cannot identify the first TLS operation");
  auto unconfirmed = es;
  unconfirmed[5].erase("confirmed_by");
  ck(run(unconfirmed, c)["metrics"]["s2_read_first"].is_null(),
     "an ordinary TLS finish is not the SDK local completion confirmation");

  auto reordered = es;
  auto confirmation = reordered[5];
  reordered.erase(5);
  reordered.insert(reordered.begin() + 2, confirmation);
  for (std::size_t i = 0; i < reordered.size(); ++i)
    reordered[i]["ns"] = 100 + i;
  ck(run(reordered, c)["metrics"]["s2_read_first"] == false &&
         run(reordered, c)["timing"]["end"]["seq"] == 5,
     "confirmation before first bytes contradicts read-first sequencing");
  reordered[1].erase("first_operation");
  reordered[2].erase("confirmed_by");
  for (auto e : events)
    if (e["kind"] == "identity" || e["kind"] == "fact" ||
        e.value("name", "") == "auth_accepted") {
      e["role"] = "client";
      reordered.insert(reordered.end() - 1, e);
    }
  for (std::size_t i = 0; i < reordered.size(); ++i)
    reordered[i]["ns"] = 100 + i;
  auto historical = c;
  historical.erase("scenario_contract");
  ck(run(reordered, historical)["status"] == "verified" &&
         run(reordered, c)["status"] == "unknown",
     "historical H-then-read remains valid only under historical rules");
  auto within = es;
  auto accepted = *find(events, "auth_accepted");
  accepted["role"] = "client";
  accepted["ns"] = within[2]["ns"];
  within.insert(within.begin() + 2, accepted);
  ck(run(within, c)["metrics"]["s2_read_first"] == true,
     "TLS may finish processing or accept policy within the ordinary read");
  es[3]["hex"] = "0000"; // corrupt only the later fragment
  auto wrong_tail = run(es, c);
  ck(wrong_tail["timing"]["end"].is_null() &&
         wrong_tail["timing"]["first_greeting_read_ns"] == 1 &&
         wrong_tail["timeline"]["SAD1"]["validated"].is_null() &&
         wrong_tail["metrics"]["task"] == false,
     "wrong later bytes cannot erase a known matching first return or validate SAD");
  es[2]["hex"] = "0000";
  ck(run(es, c)["timing"]["first_greeting_read_ns"].is_null(),
     "a mismatching first chunk cannot qualify as first SAD");
}
void write_pair_tests(const J &base) {
  auto rows = base;
  auto at = find(rows, "write_attempt");
  // An unanswered offer was retried with another buffer/length.
  J shorter = *at;
  shorter["hex"] = "68";
  shorter["length"] = 1;
  rows.insert(at, shorter);
  ck(run(rows)["status"] == "verified",
     "orphaned offer should not shadow retry");
  rows = base;
  at = find(rows, "write_attempt");
  rows.insert(at + 1, shorter);
  auto retry = run(rows);
  ck(retry["status"] == "contradicted" &&
         retry["timeline"]["SAD1"]["write_offer_pairs"] == false,
     "latest offer supersedes older buffer");
  rows = base;
  auto accepted = find(rows, "write_accepted");
  (*accepted)["tid"] = uint64_t(1) + (*accepted)["tid"].get<uint64_t>();
  auto foreign = run(rows);
  ck(foreign["status"] != "verified" &&
         foreign["timeline"]["SAD1"]["write_offer_pairs"].is_null(),
     "cannot match across native threads");
  rows = base;
  auto first = find(rows, "write_accepted");
  rows.erase(first + 1); // second return has no offer
  auto reused = run(rows);
  ck(reused["timeline"]["SAD1"]["complete"].is_null() &&
         reused["metrics"]["peer_task"] == true,
     "consumed offer cannot qualify a second return, but honest unpaired peer "
     "outcome remains");
  rows = base;
  accepted = find(rows, "write_accepted");
  (*accepted)["ns"] = find(rows, "write_attempt")->at("ns").get<uint64_t>() - 1;
  ck(run(rows)["timeline"]["SAD1"]["write_offer_pairs"] == false,
     "return predates its offer");
  rows = base;
  accepted = find(rows, "write_accepted");
  (*accepted)["hex"] = "6866";
  auto mismatch = run(rows);
  ck(mismatch["errors"][0]["reason"] == "write_return_contradicts_offer" &&
         mismatch["status"] == "contradicted",
     "return bytes differ from offered prefix");
}
J wire(J events, bool interrupt = false) {
  auto sample = events.front();
  auto obs = [&](J f) {
    auto e = sample;
    e.erase("name");
    e.erase("message");
    e.erase("offset");
    e.erase("length");
    e.update(f);
    return e;
  };
  events.insert(
      events.begin(),
      obs({{"kind", "coverage"}, {"source", "socket"}, {"active", true}}));
  auto io = [&](bool sent, bool peek, const char *data) {
    auto n = std::strlen(data) / 2;
    auto x = obs({{"kind", "io"},
                  {"source", "socket"},
                  {"sent", sent},
                  {"peek", peek},
                  {"requested", n},
                  {"result", n},
                  {"hex", data},
                  {"begin_tid", sample["tid"]},
                  {"begin_ns", sample["ns"]}});
    events.insert(events.end() - 1, x);
  };
  io(false, true, "16");
  io(false, false, "1603030003010203");
  io(true, false, "170303000101");
  if (interrupt)
    events.insert(
        events.end() - 1,
        obs({{"kind", "coverage"}, {"source", "socket"}, {"active", false}}));
  return events;
}
void wire_tests(const J &events) {
  auto r = run(wire(events));
  ck(r["metrics"]["transport_counts"] == true, "continuous coverage");
  ck(r["wire"]["counts"]["positive_receives"] == 2 &&
         r["wire"]["counts"]["consumed_bytes"] == 8,
     "peek is nonconsuming");
  ck(r["metrics"]["record_layout"] == true &&
         r["metrics"]["tls_flights"].is_null(),
     "layout not flights");
  ck(run(wire(events, true))["metrics"]["transport_counts"] == false,
     "interrupted counts");
  auto cycled = wire(events);
  auto on = cycled.front(), off = on;
  off["active"] = false;
  cycled.insert(cycled.begin() + 1, off);
  cycled.insert(cycled.begin() + 2, on);
  ck(run(cycled)["metrics"]["transport_counts"] == true,
     "pre-ready rebind preserves complete coverage");
  auto late = wire(events, true);
  late.insert(late.end() - 1, on);
  ck(run(late)["metrics"]["transport_counts"] == false,
     "in-task rebind cannot restore continuity");
  auto detached = wire(events);
  detached.insert(detached.begin() + 1, off);
  detached.insert(find(detached, "ready") + 1, on);
  ck(run(detached)["metrics"]["transport_counts"] != true,
     "inactive at ready is incomplete");
  auto outside = wire(events);
  outside.push_back(off);
  ck(run(outside)["metrics"]["transport_counts"] == true,
     "detach after end is outside coverage");
}
void endpoint_transport_tests(const J &events) {
  auto c = context();
  c["scenario_contract"] = "endpoint.v1";
  auto hook = [&](const J &trace) { return run(trace, c)["wire"]["transport_hook"]; };
  auto witnessed = wire(events);
  ck(hook(events)["reason"] == "hook_unobserved" &&
         hook(events)["verified"].is_null(), "plaintext without measured hook");
  ck(hook(witnessed)["verified"] == true && hook(witnessed)["source"] == "socket",
     "continuous socket sends and consuming receives");
  ck(hook(wire(events, true))["verified"] == false &&
         hook(wire(events, true))["reason"] == "coverage_interrupted",
     "interrupted measured hook cannot qualify");
  for (auto &e : witnessed)
    if (e.value("source", "") == "socket") {
      e["source"] = "library_io";
      if (e["kind"] == "io") e["hex"] = nullptr; // counts alone are sufficient
    }
  ck(hook(witnessed)["source"] == "library_io" && hook(witnessed)["verified"] == true,
     "real bidirectional BIO call intervals; no ciphertext collection necessary");
  auto declaration = events;
  declaration.insert(declaration.begin(), witnessed.front());
  ck(hook(declaration)["verified"].is_null() &&
         hook(declaration)["reason"] == "no_bidirectional_transfer",
     "coverage declaration alone is not an observed call");
  for (auto &e : witnessed)
    if (e["kind"] == "io" && e["sent"] == false) e["peek"] = true;
  ck(hook(witnessed)["verified"].is_null(), "peek alone is not received data");
  auto split = wire(events);
  auto lib_on = split.front();
  lib_on["source"] = "library_io";
  split.insert(split.begin(), lib_on);
  for (auto &e : split)
    if (e["kind"] == "io" && e["sent"] == true) e["source"] = "library_io";
  ck(hook(split)["reason"] == "no_bidirectional_transfer",
     "one-sided observations at different layers do not form one continuous hook");
  auto failed = wire(events);
  for (auto &e : failed)
    if (e["kind"] == "io" && e["sent"] == true) e["result"] = -1;
  ck(hook(failed)["verified"].is_null(),
     "failed send attempt and positive read do not count as a bidirectional transfer");
  ck(!run(wire(events))["wire"].contains("transport_hook"),
     "do not rewrite the archived qualification contract");
}
std::string octet(unsigned x) {
  constexpr char alphabet[] = "0123456789abcdef";
  return {alphabet[(x >> 4) & 15], alphabet[x & 15]};
}
std::string word(unsigned n) { return octet(n >> 8) + octet(n); }
std::string record(unsigned type, const std::string &payload) {
  return octet(type) + "0303" + word(payload.size() / 2) + payload;
}
std::string hello(bool client, bool retry = false) {
  auto random =
      retry ? "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
            : std::string(64, '0');
  std::string body = "0303" + random + "00";
  body += client  ? "0002130101000000"
          : retry ? "130100000c002b0002030400330002001d"
                  : "130100000f002b0002030400330005001d000101";
  return record(22,
                octet(client ? 1 : 2) + "00" + word(body.size() / 2) + body);
}
J fully_framed(const J &es, bool retry = false) {
  auto result = wire(es);
  for (auto &e : result)
    if (e["kind"] == "io" && !e["peek"].get<bool>()) {
      bool client = !e["sent"].get<bool>();
      auto bytes = hello(client, retry && !client) +
                   record(23, std::string(48, 'a')) +
                   record(23, std::string(42, 'b'));
      if (!client)
        bytes += record(23, std::string(42, 'c'));
      e["hex"] = bytes;
      e["result"] = e["requested"] = bytes.size() / 2;
    }
  auto fact = *find(result, "early_data");
  fact["value"] = true;
  for (auto name : {"sender_unpadded", "application_only_tail"}) {
    fact["name"] = name;
    result.insert(result.end() - 1, fact);
  }
  return result;
}
J sender_extent(const J &data) {
  // The fixture's opposite sender captured this same contiguous wire prefix.
  for (const auto &e : data)
    if (e.at("kind") == "io" && e.at("sent") == false && e.at("peek") == false)
      return J{{"run_id", "r"},          {"connection_id", "c"},
               {"role", "client"},       {"end_seq", 44},
               {"source", "library_io"}, {"bytes", e.at("result")},
               {"hex", e.at("hex")}};
  throw std::runtime_error("missing fixture extent");
}
void named_tests(const J &es) {
  auto c = context();
  auto data = fully_framed(es);
  // No native group/suite declaration: use the observed SH standard IDs.
  for (auto &e : data)
    if (e["kind"] == "identity")
      e["suite"] = e["group"] = e["version"] = 0;
  auto r = run(data, c);
  ck(r["status"] == "verified" && r["negotiated"]["group"] == 29,
     "derive numeric negotiated group");
  ck(r["wire"]["flights"].contains("server_protected_flight") &&
         !r["wire"]["flights"].contains("client_protected_flight"),
     "unilateral sender policy");
  c["peer_sender_unpadded"] = c["peer_application_only_tail"] = true;
  ck(run(data, c)["metrics"]["tls_flights"].is_null(),
     "sender policy alone has no received extent");
  c["peer_sender_extent"] = sender_extent(data);
  r = run(data, c);
  ck(r["metrics"]["tls_flights"] == true &&
         r["wire"]["flights"]["client_protected_flight"]["inner_message_times"]
             .is_null(),
     "four unsplit native anchored flights");
  ck(r["wire"]["flights"]["client_protected_flight"]["conceptual_members"] ==
         J{"CC", "CCV", "CF"}, "confirmed mutual authentication");
  for (auto peer : {J(nullptr), J(false)}) {
    c["peer_full_handshake_auth"] = peer;
    auto report = run(data, c);
    auto &group = report["wire"]["flights"]["server_protected_flight"];
    ck(report["metrics"]["tls_flights"] == peer && group["end"].get<uint64_t>() > group["begin"].get<uint64_t>() &&
           group["anchor"].is_object() && !group.contains("conceptual_members") &&
           report["metrics"]["timed_records"] == true,
       "unproven peer handshake cannot name protected members");
  }
  c["peer_full_handshake_auth"] = true;
  auto unauth = data;
  (*find(unauth, "verify_peer"))["value"] = false;
  auto bad = run(unauth, c);
  ck(bad["metrics"]["full_handshake_auth"] == false &&
         bad["metrics"]["tls_flights"] == false &&
         !bad["wire"]["flights"]["client_protected_flight"].contains("conceptual_members"),
     "server did not authenticate client in requested mutual handshake");
  auto incomplete_profile = data;
  incomplete_profile.erase(find(incomplete_profile, "resumed"));
  ck(run(incomplete_profile, c)["metrics"]["tls_flights"].is_null(),
     "missing full handshake proof cannot name protected members");
  c["auth"] = "server";
  auto server_only = run(unauth, c);
  ck(server_only["metrics"]["tls_flights"] == true &&
         server_only["wire"]["flights"]["client_protected_flight"]["conceptual_members"] ==
             J{"CF"}, "confirmed server-only authentication");
  c["auth"] = "mtls";
  for (auto &e : data)
    if (e["kind"] == "identity")
      e["suite"] = 0x1302;
  ck(run(data, c)["status"] == "contradicted", "SH disagrees with endpoint");
  auto retry = run(fully_framed(es, true), c);
  ck(retry["facts"]["hrr"] == true && retry["status"] == "contradicted",
     "raw HRR overrides contradictory native claim");
  auto incomplete = fully_framed(es, true);
  incomplete.erase(find(incomplete, "end"));
  ck(run(incomplete, c)["facts"]["hrr"] == true,
     "HRR survives missing end/completeness");
}
void settled_auth_test(const J &es) {
  auto server_ctx = context();
  auto server_bytes = fully_framed(es);
  server_ctx["peer_sender_unpadded"] = server_ctx["peer_application_only_tail"] = true;
  server_ctx["peer_sender_extent"] = sender_extent(server_bytes);
  auto server = local_report(server_bytes, server_ctx);
  auto client_ctx = context();
  client_ctx["role"] = "client";
  J client_events = J::array();
  for (auto e : es) {
    if (e.at("kind") == "plain")
      continue;
    e["role"] = "client";
    if (e.at("kind") == "identity")
      e["group"] = 0;
    client_events.push_back(e);
  }
  auto client = local_report(client_events, client_ctx);
  ck(client["metrics"]["full_handshake_auth"].is_null() &&
         server["metrics"]["full_handshake_auth"] == true &&
         server["metrics"]["tls_flights"].is_null() &&
         !server["wire"]["flights"]["client_protected_flight"].contains("conceptual_members"),
     "one participant alone cannot establish both endpoint authentications");
  client_ctx["peer_negotiated"] = server.at("negotiated");
  client = local_report(client_events, client_ctx);
  ck(client["metrics"]["full_handshake_auth"] == true, "peer numeric ID settles full profile");
  turtle::native::qualify_flights(server, true, client.at("metrics").at("full_handshake_auth"));
  ck(server["metrics"]["tls_flights"] == true &&
         server["wire"]["flights"]["client_protected_flight"]["conceptual_members"] ==
             J{"CC", "CCV", "CF"}, "settled peer proof authorizes timed encrypted groups");
}
void close_notify_test(const J &es) {
  J s0 = J::array();
  auto c = context();
  c["scenario"] = "S0";
  c["messages"] = {{"CAD", 0}, {"SAD1", 0}, {"SAD2", 0}};
  for (auto e : fully_framed(es)) {
    if (e.at("kind") == "plain")
      continue;
    if (e.at("kind") == "io" && e.at("peek") == false) {
      auto hex =
          hello(!e.at("sent").get<bool>()) + record(23, std::string(48, 'a'));
      e["hex"] = hex;
      e["result"] = e["requested"] = hex.size() / 2;
    }
    s0.push_back(e);
  }
  auto ext = sender_extent(s0);
  for (auto &e : s0)
    if (e.at("kind") == "io" && e.at("sent") == false &&
        e.at("peek") == false) {
      auto hex =
          e.at("hex").get<std::string>() + record(23, std::string(38, 'e'));
      e["hex"] = hex;
      e["result"] = e["requested"] = hex.size() / 2;
    }
  c["peer_sender_unpadded"] = c["peer_application_only_tail"] = true;
  ck(run(s0, c)["metrics"]["tls_flights"].is_null(),
     "no extent for encrypted close_notify");
  c["peer_sender_extent"] = ext;
  auto r = run(s0, c);
  ck(r["metrics"]["tls_flights"] == true &&
         r["wire"]["flights"]["client_protected_flight"]["end"] == ext["bytes"],
     "S0 close_notify excluded by exact sender terminal prefix");
  c["peer_sender_extent"]["hex"].get_ref<std::string &>()[0] = '0';
  ck(run(s0, c)["status"] == "invalid", "wrong sender wire prefix");
}
void source_tests(const J &es) {
  auto c = context();
  c["peer_sender_unpadded"] = c["peer_application_only_tail"] = true;
  c["peer_sender_extent"] = sender_extent(fully_framed(es));
  J bytes = J::array(), headers = J::array(), pub = J::array();
  for (auto e : fully_framed(es)) {
    if (e.at("kind") == "coverage") {
      e["source"] = "stream";
      bytes.push_back(e);
      e["source"] = "header";
      headers.push_back(e);
      e["source"] = "library_io";
      pub.push_back(e);
      continue;
    }
    if (e.at("kind") == "io") {
      if (e.at("peek") == true)
        continue;
      e["source"] = "library_io";
      pub.push_back(e);
      e["kind"] = "bytes";
      e["source"] = "stream";
      e["length"] = e["result"];
      e.erase("begin_ns");
      e.erase("begin_tid");
      bytes.push_back(e);
      size_t i = 0;
      auto hex = e.at("hex").get<std::string>();
      while (i < hex.size()) {
        auto hdr = hex.substr(i, 10);
        e.update(J{{"kind", "header"}, {"offset", i / 2}, {"hex", hdr}});
        headers.push_back(e);
        i += 10 + 2 * std::stoul(hdr.substr(6), nullptr, 16);
      }
      continue;
    }
    bytes.push_back(e);
    headers.push_back(e);
    pub.push_back(e);
  }
  auto r = run(bytes, c);
  ck(r["metrics"]["record_layout"] == true &&
         r["metrics"]["timed_records"].is_null() &&
         r["metrics"]["tls_flights"].is_null() &&
         r["metrics"]["transport_counts"].is_null() &&
         r["wire"]["flights"]["SH"]["anchor"].is_null(),
     "byte-only layouts are not timed");
  ck(r["metrics"]["library_io"].is_null(), "byte stream is not library I/O");
  auto endpoint = c;
  endpoint["scenario_contract"] = "endpoint.v1";
  for (const auto *only : {&headers, &bytes})
    ck(!run(*only, endpoint)["wire"]["transport_hook"]["verified"].is_boolean(),
       "headers or a bare ciphertext stream cannot qualify measured hook calls");
  auto h = run(headers, c);
  ck(h["metrics"]["header_layout"] == true &&
         h["metrics"]["ciphertext_bytes"].is_null() &&
         h["metrics"]["timed_records"].is_null(),
     "header-only observation not timed");
  auto cross_check = [&](bool cut_sent, bool cut_received) {
    auto both = pub;
    both.insert(both.begin(), headers.front());
    for (const auto &e : headers)
      if (e.at("kind") == "header" &&
          (e.at("offset") == 0 || !(e.at("sent") == true ? cut_sent : cut_received)))
        both.insert(both.end() - 1, e);
    return run(both, c);
  };
  ck(cross_check(false, false)["metrics"]["header_layout"] == true,
     "complete matching header callbacks");
  for (bool sent : {true, false}) {
    auto cut = cross_check(sent, !sent);
    ck(cut["metrics"]["header_layout"] == (sent ? J(false) : J(nullptr)) &&
           cut["metrics"]["record_layout"] == true &&
           cut["metrics"]["tls_flights"] == true && !cut["wire"]["headers"].empty(),
       "header prefix cannot certify complete independent record stream");
  }
  auto gap = pub;
  gap.insert(gap.begin(), headers.front());
  for (const auto &e : headers)
    if (e.at("kind") == "header" && !(e.at("sent") == true && e.at("offset") == 0))
      gap.insert(gap.end() - 1, e);
  auto missed = run(gap, c);
  ck(missed["metrics"]["header_layout"] == false &&
         missed["metrics"]["timed_records"] == true && missed["status"] == "verified",
     "missing internal header does not invalidate independent evidence");
  auto p = run(pub, c);
  ck(p["metrics"]["library_io"] == true, "continuous timed library I/O");
  auto cut = pub;
  auto off = cut.front();
  off["active"] = false;
  cut.insert(cut.end() - 1, off);
  ck(run(cut, c)["metrics"]["library_io"] == false, "interrupted library I/O");
  ck(run(fully_framed(es), c)["metrics"]["library_io"].is_null(),
     "socket I/O cannot replace library I/O");
  ck(p["metrics"]["tls_flights"] == true &&
         p["metrics"]["transport_counts"].is_null() &&
         p["wire"]["flights"]["SH"]["source"] == "library_io",
     "library-only anchors not socket counts");
  auto extra =
      headers[std::find_if(headers.begin(), headers.end(),
                           [](auto &e) { return e.at("kind") == "header"; }) -
              headers.begin()];
  extra["offset"] = 999999;
  bytes.push_back(extra);
  ck(run(bytes, c)["status"] == "verified", "post-end header excluded");
  auto native = es;
  for (auto &e : native)
    if (e.at("kind") == "identity")
      e["suite"] = 0;
  ck(run(native, c)["status"] == "unknown", "no cipher proof");
  c["peer_negotiated"] = {{"suite", 0x1301}};
  auto corroborated = run(native, c);
  ck(corroborated["status"] == "verified" &&
         corroborated["negotiated_basis"]["suite"] == "same_connection_peer",
     "same-connection numeric corroboration");
  c["peer_negotiated"]["suite"] = 0x1302;
  ck(run(es, c)["status"] == "contradicted", "cross-role cipher conflict");
}
void combined_tests(const J &es) {
  auto c = context();
  c["role"] = "client";
  J data = J::array();
  for (auto e : es) {
    if (e["kind"] == "plain")
      continue;
    if (e.value("name", "") == "end") {
      for (auto [n, s] : {std::pair{"write_attempt", "70696e67"},
                          {"write_accepted", "70696e67"},
                          {"read_return", "68656c6f706f6e67"},
                          {"validated", "68656c6f706f6e67"}}) {
        J p = e;
        p.update(J{{"kind", "plain"},
                   {"role", "client"},
                   {"name", n},
                   {"hex", s},
                   {"length", std::strlen(s) / 2}});
        data.push_back(p);
      }
    }
    e["role"] = "client";
    data.push_back(e);
  }
  auto r = run(data, c);
  ck(r["status"] == "verified", "combined read should qualify");
  auto a = r["timeline"]["SAD1"]["last_read_return"],
       b = r["timeline"]["SAD2"]["first_read_return"];
  ck(a["seq"] == b["seq"] && r["timing"]["end"]["seq"] == b["seq"],
     "shared real read-return boundary");
  // The application services an already readable greeting before its write.
  auto greet = *find(data, "read_return");
  greet["hex"] = "68656c6f";
  greet["length"] = 4;
  auto resp = find(data, "read_return");
  (*resp)["hex"] = "706f6e67";
  (*resp)["length"] = 4;
  // A write may block without accepting any CAD; its first attempt is not
  // the benchmark boundary when the greeting was read before the retry.
  auto overlap = data;
  auto retry = *find(overlap, "write_attempt");
  overlap.insert(find(overlap, "write_accepted"), greet);
  overlap.insert(find(overlap, "write_accepted"), retry);
  auto endpoint = c;
  endpoint["scenario_contract"] = "endpoint.v1";
  ck(run(overlap, c)["status"] == "verified" &&
         run(overlap, endpoint)["metrics"]["task"] == false,
     "S4 endpoint requires final CAD acceptance before the first SAD1 read");
  data.insert(find(data, "write_attempt"), greet);
  auto read_first = run(data, c);
  ck(read_first["metrics"]["task"].is_null() && read_first["status"] == "unknown",
     "S4 read-first does not establish CAD dependency");
  (*find(data, "verify_peer"))["value"] = false;
  ck(run(data, c)["status"] == "contradicted",
     "S4 read-first does not hide authentication contradiction");
}
void pmu_tests(const J &es) {
  J data = es;
  auto attach = [&](J &e, uint64_t n) {
    auto ns = e.at("ns").get<uint64_t>();
    e["pmu_status"] = "available";
    e["pmu"] = {{"type", "PERF_TYPE_HARDWARE"},
                {"cycles_config", "PERF_COUNT_HW_CPU_CYCLES"},
                {"instructions_config", "PERF_COUNT_HW_INSTRUCTIONS"},
                {"cycles_id", 5},
                {"instructions_id", 7},
                {"cycles", n * 3},
                {"instructions", n * 2},
                {"enabled_ns", n},
                {"running_ns", n},
                {"read_begin_ns", ns},
                {"read_end_ns", ns}};
  };
  auto &a = *find(data, "hs_begin");
  auto it = std::find_if(data.elements().rbegin(), data.elements().rend(), [](auto &e) {
    return e.value("name", "") == "write_accepted";
  });
  attach(a, 1);
  attach(*it, 5);
  auto r = run(data);
  ck(r["timing"]["pmu_delta"]["cycles"] == 12 && r["metrics"]["pmu"] == true,
     "same thread raw PMU delta");
  (*it)["pmu"]["running_ns"] = 4;
  ck(run(data)["timing"]["pmu_status"] == "multiplexed" &&
         run(data)["metrics"]["pmu"].is_null(),
     "multiplexed counter diagnostic");
  (*it)["pmu"]["running_ns"] = 5;
  auto full_start = a, full_end = *it;
  (*it)["pmu"] = nullptr;
  ck(run(data)["timing"]["pmu_status"] == "missing",
     "one absent boundary is not partial");
  *it = full_end;
  (*it)["pmu"]["instructions"] = nullptr;
  ck(run(data)["timing"]["pmu_status"] == "missing",
     "inconsistent group is not partial");
  for (auto *e : {&a, &*it}) {
    (*e)["pmu_status"] = "partial";
    for (auto key : {"instructions", "instructions_id", "instructions_config"})
      (*e)["pmu"][key] = nullptr;
  }
  auto partial = run(data);
  ck(partial["timing"]["pmu_status"] == "partial" &&
         partial["timing"]["pmu_delta"]["cycles"] == 12 &&
         partial["timing"]["pmu_delta"]["cycles_id"] == 5 &&
         partial["timing"]["pmu_delta"]["instructions"].is_null() &&
         partial["metrics"]["pmu"].is_null(),
     "genuine single-member delta only");
  for (auto key : {"cycles_id", "cycles_config", "type", "running_ns"}) {
    auto saved = (*it)["pmu"][key];
    (*it)["pmu"][key] = (std::string_view(key) == "cycles_id" ||
                         std::string_view(key) == "running_ns")
                            ? J(0)
                            : J("wrong");
    ck(run(data)["timing"]["pmu_status"] == "missing",
       "invalid partial counter metadata");
    (*it)["pmu"][key] = saved;
  }
  (*it)["tid"] = 1;
  ck(run(data)["timing"]["pmu_status"] == "missing",
     "foreign-tid partial rejected");
  a = full_start;
  *it = full_end;
  (*it)["tid"] = 1;
  ck(run(data)["metrics"]["pmu"].is_null(), "cross thread PMU rejects");
  (*it)["tid"] = a["tid"];
  (*it)["pmu"]["instructions_id"] = 55;
  ck(run(data)["metrics"]["pmu"].is_null(), "cross group PMU rejects");
}

} // namespace
int main(int argc, char **argv) try {
  if (argc > 1) {
    if (std::string_view(argv[1]) == "cycles-only") {
      // Leave one free descriptor after loader startup: the real hardware
      // cycles leader can open, but the instructions member must fail EMFILE.
      int n = open("/dev/null", O_RDONLY);
      ck(n >= 0, "probe free FD");
      close(n);
      rlimit limits{};
      ck(getrlimit(RLIMIT_NOFILE, &limits) == 0, "get file limit");
      limits.rlim_cur = n + 1;
      ck(setrlimit(RLIMIT_NOFILE, &limits) == 0, "limit test-only process");
    }
    errno = ERANGE;
    produce();
    ck(errno == ERANGE, "observer modified errno");
    return 0;
  }
  auto es = capture_legacy_fixture(argv[0]);
  // Exercise the exact predicate shared by the scheduling and replay paths.
  // Unavailable required metrics stay unavailable; only otherwise valid
  // decision-required warmups may be bypassed for a fresh observation.
  for (auto mode : {"partial", "multiplexed"}) {
    J warm = {{"purpose", "warmup"},
              {"operation_ok", false},
              {"qualification", "decision_required"},
              {"pmu_status", mode},
              {"eligible", false}};
    J measurement = {{"purpose", "sample"}, {"qualified", true}};
    std::vector<J> scheduled{warm};
    if (turtle::native::warmup_allows_measurement(warm))
      scheduled.push_back(measurement);
    ck(scheduled.size() == 2 && scheduled.front()["eligible"] == false &&
           scheduled.back()["qualified"] == true,
       "incomplete warmup permits fresh measurement");
    warm["qualification"] = "unknown"; // another mandatory metric missing
    ck(!turtle::native::warmup_allows_measurement(warm),
       "missing non-PMU metric blocks warmup");
    warm["pmu_status"] = "unsupported";
    ck(!turtle::native::warmup_allows_measurement(warm),
       "denied required PMU blocks warmup");
  }
  lifecycle_tests(es);
  endpoint_contract_tests(es);
  submission_composite_greeting_test(es);
  endpoint_first_read_test(es);
  write_pair_tests(es);
  wire_tests(es);
  endpoint_transport_tests(es);
  named_tests(es);
  settled_auth_test(es);
  close_notify_test(es);
  source_tests(es);
  combined_tests(es);
  pmu_tests(es);
  auto cycles = capture_legacy_fixture(argv[0], "cycles-only");
  if (cycles.front().at("pmu_status") == "partial") {
    auto report = run(cycles);
    ck(report["timing"]["pmu_status"] == "partial" &&
           report["timing"]["pmu_delta"]["cycles"].get<uint64_t>() > 0 &&
           cycles.front().at("pmu_errno") == EMFILE &&
           cycles.front().at("pmu_reason") == "instructions_open_failed",
       "live one-member group");
    std::cout << "live cycles-only group: "
              << report["timing"]["pmu_delta"].dump() << "\n";
  } else
    ck(cycles.front().at("pmu_status") == "unsupported" &&
           cycles.front().at("pmu").is_null(),
       "unsupported leader must not produce partial");

  std::cout << "native evidence: pass\n";
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << "\n";
  return 1;
}
