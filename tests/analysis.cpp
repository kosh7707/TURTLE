#include "native-packets-fixture.hpp"
#include "analysis/analysis.hpp"
#include "analysis/evidence.hpp"
#include "capture/capture.hpp"
#include "profiling/profiling.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string_view>
using turtle::artifact::Bytes;
using turtle::artifact::integer;
using turtle::artifact::Json;
namespace {
using packet_fixture::append;
using packet_fixture::packet;
using packet_fixture::write_pcap;
void require(bool ok, const char *reason) {
  if (!ok)
    throw std::runtime_error(reason);
}
Bytes unhex(const std::string &s) {
  Bytes b;
  for (std::size_t i = 0; i < s.size(); i += 2)
    b.push_back(
        static_cast<unsigned char>(std::stoul(s.substr(i, 2), nullptr, 16)));
  return b;
}
void phases(const std::filesystem::path &fixtures) {
  auto source = turtle::artifact::load(fixtures / "phases.json");
  turtle::analysis::Endpoints eps;
  for (const auto &[role, e] : source.at("endpoints").items()) {
    turtle::analysis::Endpoint ep;
    ep.summary = e.at("summary");
    ep.events = e.at("events");
    ep.records = e.at("records");
    for (const auto &[d, s] : e.at("streams").items())
      ep.streams[d] = unhex(s);
    eps.emplace(role, std::move(ep));
  }
  auto actual = turtle::analysis::phases(
      eps, Json::object(), {{"availability", "not_collected"}}, true);
  if (actual != source.at("expected")) {
    std::cerr << Json::diff(source.at("expected"), actual).dump(2) << '\n';
    throw std::runtime_error("phase_reference_mismatch");
  }
  eps.at("client").summary["negotiated"]["profile"] = 0;
  auto missing = turtle::analysis::phases(
      eps, Json::object(), {{"availability", "not_collected"}}, true);
  require(missing.at("complete") == false && missing.at("roles").empty(),
          "undeclared_profile");
}
Bytes frame(unsigned n, const std::string &s) {
  Bytes b{'T', 'U'};
  append(b, n, 2);
  b.push_back(23);
  append(b, 0x303, 2);
  append(b, s.size(), 2);
  b.insert(b.end(), s.begin(), s.end());
  return b;
}
void capture(const std::filesystem::path &root, bool raw) {
  auto wire = frame(1, "abcdefg"), second = frame(2, "123456789"),
       other = frame(1, "pong");
  if (raw)
    for (auto buf : {&wire, &second, &other})
      buf->erase(buf->begin(), buf->begin() + 4);
  auto first_record_end = wire.size();
  wire.insert(wire.end(), second.begin(), second.end());
  auto part = [&](std::size_t a, std::size_t b) {
    return Bytes(wire.begin() + static_cast<std::ptrdiff_t>(a),
                 wire.begin() + static_cast<std::ptrdiff_t>(b));
  };
  std::uint32_t initial = 0xfffffff0;
  Bytes sack{1, 1, 5, 10};
  append(sack, initial + 22, 4);
  append(sack, initial + 26, 4);
  std::vector<Bytes> packets{
      packet(true, initial, 2),
      packet(false, 100, 18),
      packet(true, initial + 1, 16, part(0, 3)),
      packet(true, initial + 4, 16, part(3, 14)),
      packet(true, initial + 7, 16, part(6, 25)),
      packet(true, initial + 26, 16, part(25, wire.size())),
      packet(true, initial + 13, 16, part(12, 17)),
      packet(false, 101, 16, other, initial + 1 + first_record_end, sack)};
  for (bool little : {false, true}) {
    auto file = root / (little ? "little.pcap" : "big.pcap");
    write_pcap(file, packets, little);
    auto r = turtle::capture::analyze(
        file, {{"client_to_server", wire}, {"server_to_client", other}},
        {{"client_to_server", wire.size()}, {"server_to_client", other.size()}},
        "192.0.2.2", "198.51.100.2", raw);
    const auto &out = r.at("client_to_server");
    require(out.at("availability") == "available", "pcap_coverage");
    require(out.at("retransmitted_payload_bytes") == 13,
            "partial_retransmission");
    require(out.at("unique_payload_bytes") == wire.size(), "union_bytes");
    require(out.at("packets")[0].at("timestamp_ns") == 2000000000123456789ULL,
            "pcap_timestamp_integer");
    require(r.at("server_to_client").at("retransmitted_payload_bytes") == 0,
            "zero_retransmission");
    const auto &copy = r.at("server_to_client").at("packets").back();
    require(copy.at("opposite_records_cumulatively_acked") ==
                    Json::array({1}) &&
                copy.at("sack_stream_ranges") ==
                    Json::array({Json::array({21, 25})}),
            "copy_specific_ack_sack");
    require(!out.at("packets")[3].at("retransmitted_record_ranges").empty(),
            "record_retransmission_attribution");
    require(out.at("packets")[3].at("records").back().at("record") == 2,
            "multiple_frames");
  }
  auto f = frame(1, "TU-inside-body");
  auto records = turtle::capture::records(f);
  require(records.size() == 1, "TU_in_payload");
  auto tls = Bytes(f.begin() + 4, f.end());
  turtle::capture::verify_tls(f, tls);
}
Bytes protected_records(std::initializer_list<std::size_t> lengths) {
  Bytes wire;
  for (auto plaintext : lengths) {
    wire.insert(wire.end(), {23, 3, 3});
    append(wire, plaintext + 17, 2); // fixed AEAD tag plus inner content type
    wire.resize(wire.size() + plaintext + 17);
  }
  return wire;
}
void raw_boundaries() {
  const std::string suite = "TLS_AES_256_GCM_SHA384";
  auto inspect = [&](std::initializer_list<std::size_t> lengths,
                     bool declared = true, unsigned app = 8) {
    return turtle::analysis::finished_boundary(
        turtle::capture::raw_records(protected_records(lengths)), app, suite,
        declared);
  };
  auto warm = inspect({400, 53, 4, 4}),
       measured = inspect({300, 100, 30, 23, 1, 3, 4});
  require(warm.at("value").at("record") == 2 &&
              measured.at("value").at("record") == 4,
          "finished_not_an_ordinal_learned_from_warmup");
  require(inspect({53, 4, 4}, false).at("value").is_null() &&
              inspect({53, 4, 4}, true, 7).at("value").is_null() &&
              inspect({53, 4, 0, 4}).at("value").is_null(),
          "unsupported_tail_not_guessed");
  auto stream = protected_records({2, 3});
  auto rs = turtle::capture::raw_records(stream);
  auto split = turtle::capture::mapping(rs, 2, 7),
       coalesced = turtle::capture::mapping(rs, 23, 32);
  require(split.size() == 2 && split[0].at("part") == "tls_header" &&
              split[1].at("wire_begin") == 5 && coalesced.size() == 3 &&
              coalesced[0].at("record") == 1 && coalesced[1].at("record") == 2,
          "raw_record_intersections");
}
// A controlled mTLS server flight. One or several encrypted TLSCiphertexts
// may carry EE/CR/Certificate/CertificateVerify/Finished. Public callbacks
// can identify those messages within a TLS call, not within a record.
void opaque_flight(const std::filesystem::path &dir, const Bytes &server) {
  using namespace turtle::analysis;
  const evidence::Task task({{"scenario", "S0"},
                             {"auth", "mtls"},
                             {"measured_role", "server"},
                             {"recording", "detailed"},
                             {"record_contract", "flight-boundaries.v1"},
                             {"application", Json::object()}});
  Json policy = {{"negotiated",
                  {{"record_policy", 0},
                   {"profile", 2},
                   {"cipher", {{"value", "TLS_AES_256_GCM_SHA384"}}}}}};
  Json peers = {{"client", policy}, {"server", policy}};
  std::filesystem::create_directories(dir / "server");
  Endpoint raw;
  raw.events = {
      {{"kind", "call"}, {"operation", "handshake"}, {"direction", "send"}}};
  for (auto direction : {"send", "receive"}) {
    bool send = std::string_view(direction) == "send";
    Bytes body{3, 3};
    body.resize(34);   // legacy_version and Random
    body.push_back(0); // session ID
    Bytes tail = send ? Bytes{0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4}
                      : Bytes{0, 2, 0x13, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4};
    body.insert(body.end(), tail.begin(), tail.end());
    Bytes hello{static_cast<unsigned char>(send ? 2 : 1), 0, 0,
                static_cast<unsigned char>(body.size())};
    hello.insert(hello.end(), body.begin(), body.end());
    Bytes bytes{22, 3, 3, 0, 2, hello[0], hello[1], 22, 3, 3};
    append(bytes, hello.size() - 2, 2);
    bytes.insert(bytes.end(), hello.begin() + 2, hello.end());
    bytes.insert(bytes.end(),
                 {20, 3, 3, 0, 1, 1}); // separate compatibility CCS
    const auto protected_wire = send ? server : protected_records({48});
    bytes.insert(bytes.end(), protected_wire.begin(), protected_wire.end());
    const auto key = std::string("wire_") + direction;
    turtle::artifact::write_text(dir / "server" / (key + ".bin"),
                                 std::string(bytes.begin(), bytes.end()));
    raw.summary["streams"][key]["bytes"] = bytes.size();
    raw.summary["scenario"][key + "_bytes"] = bytes.size();
    raw.events.push_back({{"kind", "socket"},
                          {"direction", direction},
                          {"id", raw.events.size() + 1},
                          {"call_id", 1},
                          {"parent", 0},
                          {"success", true},
                          {"transferred", bytes.size()},
                          {"wire_begin", 0},
                          {"wire_end", bytes.size()},
                          {"begin", {{"wall_ns", 100}}},
                          {"end", {{"wall_ns", 120}}}});
    for (const auto &record : turtle::capture::raw_records(bytes)) {
      const auto start = bytes.begin() + integer(record.at("wire_begin"));
      raw.events.push_back({{"kind", "header"},
                            {"direction", direction},
                            {"id", raw.events.size() + 1},
                            {"call_id", 1},
                            {"header", Bytes(start, start + 5)}});
    }
  }
  Json obs, report;
  auto headers_only = raw;
  evidence::collect(dir, task, false, true, headers_only, peers, obs, report);
  require(
      evidence::available(obs.at("headers")) &&
          !evidence::available(obs.at("message_notifications").at("send")) &&
          !evidence::available(
              obs.at("finished_boundary").at("server_to_client")),
      "encrypted_flight_order_or_internal_times_guessed_from_record_headers");
  for (const auto &r : headers_only.records.at("send"))
    require(r.contains("header_event") && !r.contains("message_type") &&
                !r.contains("terminates_finished"),
            "protected_record_gained_inner_message_identity");
  const auto &flights = obs.at("tls_flights");
  require(flights.at("SH").at("value").at("records").size() == 2 &&
              flights.at("SH").at("value").at("socket_anchor").at("wall_ns") ==
                  100 &&
              flights.at("CH").at("value").at("socket_anchor").at("wall_ns") ==
                  120 &&
              !evidence::available(flights.at("server_protected_flight")),
          "fragmented_hello_or_unproven_finished_timestamp_incorrect");
  for (unsigned type : {8u, 13u, 11u, 15u, 20u})
    raw.events.push_back({{"kind", "message"},
                          {"direction", "send"},
                          {"call_id", 1},
                          {"id", raw.events.size() + 1},
                          {"message_type", type}});
  evidence::collect(dir, task, false, true, raw, peers, obs, report);
  require(
      raw.records == headers_only.records &&
          obs.at("message_notifications").at("send").at("value").size() == 5,
      "native_message_notifications_reassigned_encrypted_record_boundaries");
  // Cipher getters are not a prerequisite for record coverage.
  peers["client"]["negotiated"]["record_policy"] = 1;
  peers["server"]["negotiated"]["record_policy"] = 1;
  evidence::collect(dir, task, false, true, raw, peers, obs, report);
  const auto &group =
      obs.at("tls_flights").at("server_protected_flight").at("value");
  require(group.at("records").size() ==
                  turtle::capture::raw_records(server).size() &&
              group.at("records").front().at("record") == 4 &&
              group.at("conceptual_members") ==
                  Json{"EE", "CR", "SC", "SCV", "SF"} &&
              group.at("inner_message_times").is_null() &&
              group.at("public_io_anchor").is_null() &&
              obs.at("tls_flights")
                      .at("client_protected_flight")
                      .at("value")
                      .at("conceptual_members") == Json{"CC", "CCV", "CF"},
          "opaque_group_mistook_ccs_or_inner_messages_for_records");
  peers["client"]["negotiated"]["cipher"] = evidence::missing("unsupported");
  evidence::collect(dir, task, false, true, raw, peers, obs, report);
  require(evidence::available(obs.at("records")) &&
              !evidence::available(
                  obs.at("tls_flights").at("server_protected_flight")),
          "missing_cipher_invalidated_independent_record_coverage");
  auto wrong = raw.streams.at("send");
  wrong[5] = 1; // same record headers and counts but not ServerHello bytes
  turtle::artifact::write_text(dir / "server/wire_send.bin",
                               std::string(wrong.begin(), wrong.end()));
  evidence::collect(dir, task, false, true, raw, peers, obs, report);
  require(!evidence::available(obs.at("tls_flights").at("SH")),
          "outer_headers_only_accepted_as_server_hello");
}
// Synthetic record/copy evidence, not a live handshake: the four greeting
// bytes span two records; the second may also carry two response bytes.
void presend_order(const std::filesystem::path &dir, const std::string &role,
                   bool shared_tail) {
  using turtle::artifact::save;
  auto client = protected_records({12, 4});
  const std::size_t shared = shared_tail ? 2 : 0;
  auto sf = protected_records({16}),
       greeting = protected_records({2, 2 + shared});
  auto response = protected_records({4 - shared}),
       server = protected_records({16, 2, 2 + shared, 4 - shared});
  auto greeting_end = sf.size() + greeting.size();
  std::filesystem::create_directories(dir / role);
  turtle::analysis::Endpoint ep;
  ep.events = {
      {{"kind", "call"}, {"direction", "receive"}, {"operation", "handshake"}}};
  auto add_socket_stream = [&](const char *direction, const Bytes &bytes) {
    const auto key = std::string("wire_") + direction;
    ep.summary["streams"][key]["bytes"] = bytes.size();
    ep.summary["scenario"][key + "_bytes"] = bytes.size();
    turtle::artifact::write_text(dir / role / (key + ".bin"),
                                 std::string(bytes.begin(), bytes.end()));
    // Good socket coverage, but no BIO or header notifications on this adapter.
    ep.events.push_back({{"kind", "socket"},
                         {"direction", direction},
                         {"id", ep.events.size() + 1},
                         {"parent", 1},
                         {"call_id", 1},
                         {"success", true},
                         {"transferred", bytes.size()},
                         {"begin", {{"wall_ns", 1}}},
                         {"end", {{"wall_ns", 2}}},
                         {"wire_begin", 0},
                         {"wire_end", bytes.size()}});
  };
  add_socket_stream("send", role == "client" ? client : server);
  add_socket_stream("receive", role == "client" ? server : client);
  Json health = {{"availability", "available"},
                 {"ready_before_connect", true},
                 {"kernel_dropped", 0},
                 {"interface_dropped", 0},
                 {"server_port", 4433}};
  save(dir / "network.json", {{"availability", "available"},
                              {"capture", {{role, health}}},
                              {"client_ip", "192.0.2.2"},
                              {"server_ip", "198.51.100.2"}});
  save(dir / "processes.json", {{"server_port", 4433}});
  Json negotiated = {{"record_policy", 1},
                     {"profile", 1},
                     {"cipher", {{"value", "TLS_AES_256_GCM_SHA384"}}}};
  Json peers = {{"client", {{"negotiated", negotiated}}},
                {"server", {{"negotiated", negotiated}}}};
  turtle::analysis::evidence::Task task(
      {{"scenario", "S4"},
       {"auth", "server"},
       {"measured_role", role},
       {"recording", "detailed"},
       {"application",
        {{"request", "ping"}, {"greeting", "helo"}, {"response", "pong"}}}});
  const unsigned cbase = 101, sbase = 1001;
  enum Order { indeterminate, greeting_received, finished_received };
  for (auto expected : {indeterminate, greeting_received, finished_received}) {
    auto client_ack = expected == finished_received   ? sf.size()
                      : expected == greeting_received ? greeting_end
                                                      : greeting_end - 1;
    auto cf_copy = packet(true, cbase, 16, client, sbase + client_ack);
    auto greeting_copy =
        packet(false, sbase + sf.size(), 16, greeting,
               cbase + (expected == finished_received ? client.size() : 0));
    // Packet 5 is the named copy. Only its ACK counts, not the later pure ACK.
    write_pcap(
        dir / (role + ".pcap"),
        {packet(true, cbase - 1, 2), packet(false, sbase - 1, 18, {}, cbase),
         packet(false, sbase, 16, sf, cbase),
         expected == finished_received ? cf_copy : greeting_copy,
         expected == finished_received ? greeting_copy : cf_copy,
         packet(false, sbase + greeting_end, 16, response,
                cbase + client.size()),
         packet(true, cbase + client.size(), 16, {}, sbase + server.size())},
        false);
    Json obs, report;
    auto measured = ep;
    turtle::analysis::evidence::collect(dir, task, true, true, measured, peers,
                                        obs, report);
    require(obs.at("records").at("value") == true &&
                obs.at("capture").at("value") == true &&
                obs.at("public_io").at("reason") ==
                    "public_io_coverage_incomplete" &&
                obs.at("headers").at("reason") ==
                    "header_notification_coverage_incomplete",
            "missing_optional_hooks_do_not_drop_socket_or_tcp_evidence");
    if (shared_tail) {
      const auto &record =
          measured.records.at(role == "client" ? "receive" : "send").at(2);
      Json ranges = {{{"message", "greeting"},
                      {"plaintext_begin", 2},
                      {"plaintext_end", 4}},
                     {{"message", "response"},
                      {"plaintext_begin", 4},
                      {"plaintext_end", 6}}};
      require(record.at("application_ranges") == ranges,
              "shared_record_contains_greeting_tail_and_response_prefix");
    }
    const auto &order = obs.at("presend_tcp_order");
    require(order.at("socket_only") == "indeterminate" &&
                order.at("scope") == "named_TCP_copy_not_peer_TLS_processing",
            "no_cross_direction_claim_from_socket_or_peer_tls");
    if (expected == indeterminate) {
      require(order.at("verdict") == "indeterminate" &&
                  order.at("ack_witnesses").empty(),
              "partial_greeting_ack_and_later_pure_ack_are_not_witnesses");
      continue;
    }
    bool client_copy = expected == greeting_received;
    Json witness = {
        {"packet_id", 5},
        {"direction", client_copy ? "client_to_server" : "server_to_client"},
        {"contains_first_byte_of_record", client_copy ? 1 : 2},
        {"ack_stream_offset", client_copy ? greeting_end : client.size()},
        {"peer_record_fully_received_before_this_copy", client_copy ? 3 : 1}};
    require(order.at("verdict") == "copy_specific_ack_evidence" &&
                order.at("ack_witnesses") == Json::array({witness}),
            "named_copy_orders_whole_greeting_and_finished_not_response");
  }
}
const Json &metric_row(const Json &report, const char *name) {
  for (const auto &row : report.at("measurements"))
    if (row.at("group") == "metrics" && row.at("metric") == name)
      return row;
  throw std::runtime_error(std::string("missing metric row: ") + name);
}

void reject_bad_schedules(const std::filesystem::path &root, const Json &valid) {
  auto expect_rejection = [&](const Json &manifest, std::string_view reason) {
    try {
      turtle::analysis::regenerate_lifecycle(root, manifest);
    } catch (const std::runtime_error &e) {
      if (reason == e.what())
        return;
      throw;
    }
    throw std::runtime_error("accepted malformed schedule: " + std::string(reason));
  };
  auto duplicate = valid;
  duplicate.at("order").push_back(valid.at("order").front());
  expect_rejection(duplicate, "unknown_configuration_or_duplicate_schedule_slot");

  auto reordered = valid;
  std::swap(reordered.at("attempts").at(1), reordered.at("attempts").at(2));
  expect_rejection(reordered, "attempt_schedule_out_of_order");

  auto unplanned = valid;
  unplanned.at("attempts").back()["repeat"] = 2;
  expect_rejection(unplanned, "duplicate_or_unscheduled_attempt");
}

void lifecycle(const std::filesystem::path &root) {
  using turtle::artifact::load;
  using turtle::artifact::save;
  Json config = {
      {"id", "one"},
      {"scenario", "S3"},
      {"auth", "mtls"},
      {"measured_role", "client"},
      {"warmups", 1},
      {"recording", "basic"},
      {"required_metrics", {"scenario_wall_ns"}},
      {"optional_metrics", {"capture"}},
      {"application",
       {{"request", "ping"}, {"greeting", "helo"}, {"response", "pong"}}}};
  Json spec = {{"repetitions", 2}, {"configurations", Json::array({config})}};
  Json manifest = {{"spec", spec},
                   {"order", Json::array()},
                   {"attempts", Json::array()},
                   {"status", "complete"},
                   {"blocked", Json::object()},
                   {"schema", "turtle.manifest.v3"}};
  auto stamp = [](unsigned n) {
    return Json{{"wall_ns", n}, {"thread_cpu_ns", n / 2}};
  };
  for (int i = 0; i < 3; ++i) {
    auto purpose = i ? "measurement" : "warmup";
    auto id = std::to_string(i);
    Json a = {{"purpose", purpose},
              {"configuration", "one"},
              {"repeat", i ? i - 1 : 0},
              {"run_id", id},
              {"directory", "attempts/" + id}};
    manifest["order"].push_back(a);
    manifest["attempts"].push_back(a);
    auto dir = root / "attempts" / id;
    std::filesystem::create_directories(dir / "client");
    std::filesystem::create_directories(dir / "server");
    save(dir / "processes.json",
         {{"run_id", id},
          {"error", nullptr},
          {"returncodes", {{"client", 0}, {"server", 0}}}});
    for (auto role : {"client", "server"}) {
      auto prop = [](const char *value) {
        return Json{{"availability", "available"}, {"value", value}};
      };
      Json sc = {{"complete", true},         {"name", "S3"},
                 {"content_verified", true}, {"plaintext_sent", 4},
                 {"plaintext_received", 4},  {"begin_event", 1},
                 {"end_event", 3},           {"begin", stamp(10)},
                 {"end", stamp(36)}};
      Json ep = {
          {"schema", "turtle.endpoint.v4"},
          {"run_id", id},
          {"connection_id", id},
          {"role", role},
          {"purpose", purpose},
          {"measured_role", "client"},
          {"recording", "basic"},
          {"auth", "mtls"},
          {"status", "ok"},
          {"scenario", sc},
          {"negotiated",
           {{"version", 772},
            {"profile", 2},
            {"peer_verified", true},
            {"resumed", false},
            {"group", prop("X25519")},
            {"cipher", prop("TLS_AES_256_GCM_SHA384")}}},
          {"shutdown", "ok"},
          {"implementation", "fixture"},
          {"streams", Json::object()},
          {"collection", {{"framing", "none"}, {"perf_counters", false}}}};
      save(dir / role / "endpoint.json", ep);
    }
    Json events = Json::array();
    auto call = [&](std::string op, int lo, int hi, unsigned t, unsigned end) {
      events.push_back({{"schema", "turtle.event.v2"},
                        {"id", events.size() + 1},
                        {"role", "client"},
                        {"run_id", id},
                        {"connection_id", id},
                        {"parent", 0},
                        {"success", true},
                        {"kind", "call"},
                        {"operation", op},
                        {"plaintext_begin", lo},
                        {"plaintext_end", hi},
                        {"begin", stamp(t)},
                        {"end", stamp(end)},
                        {"transferred", hi - lo}});
    };
    call("handshake", 0, 0, 10, 18);
    call("application_write", 0, 4, 19, 25);
    call("application_read", 0, 2, 30, 36);
    call("application_read", 2, 4, 38, 40);
    call("content_verify", 0, 4, 41, 42);
    std::string lines;
    for (auto &e : events)
      lines += e.dump() + "\n";
    turtle::artifact::write_text(dir / "client/events.jsonl", lines);
  }
  reject_bad_schedules(root, manifest);
  save(root / "manifest.json", manifest);
  require(turtle::analysis::regenerate(root),
          "optional_capture_absent_is_not_gate_failure");
  auto agg = load(root / "analysis.json"),
       warm = load(root / "attempts/0/analysis.json"),
       sample = load(root / "attempts/1/analysis.json");
  require(agg.at("measurement_count") == 2 &&
              agg.at("successful_measurements") == 2 &&
              agg.at("eligible_measurements") == 2 &&
              agg.at("diagnostics").size() == 1,
          "warmups_excluded_from_sample_count");
  require(std::none_of(
              warm.at("measurements").begin(), warm.at("measurements").end(),
              [](const Json &r) { return r.at("valid_sample") == true; }),
          "warmup_must_not_emit_valid_rows");
  const auto &wall = metric_row(sample, "scenario_wall_ns");
  require(wall.at("valid_sample") == true && wall.at("role") == "client" &&
              wall.at("unit") == "ns" && wall.at("scope") == "" &&
              wall.at("excluded_reason").is_null(),
          "ordinary_timing_row");
  const auto &bytes = metric_row(sample, "retransmitted_send_bytes");
  require(bytes.at("valid_sample") == false && bytes.at("unit") == "bytes" &&
              bytes.at("excluded_reason") == "tcp_evidence_unavailable",
          "missing_metric_keeps_its_own_reason");
  require(metric_row(warm, "retransmitted_send_bytes").at("excluded_reason") ==
              "warmup",
          "warmup_precedes_metric_unavailability");
  require(sample.at("roles")
                      .at("client")
                      .at("metrics")
                      .at("first_response_wall_ns")
                      .at("value") == 26 &&
              sample.at("roles")
                      .at("client")
                      .at("metrics")
                      .at("response_verified_wall_ns")
                      .at("value") == 32,
          "first_byte_and_response_verification_are_distinct");
  auto c = config;
  c["required_metrics"].push_back("headers");
  auto r = turtle::analysis::assess(root / "attempts/0", c,
                                    manifest.at("attempts")[0]);
  require(r.at("success") == true && r.at("eligible") == false &&
              r.at("required_metrics_valid") == false,
          "required_hook_missing_not_task_failure");
  require(metric_row(r, "retransmitted_send_bytes").at("excluded_reason") ==
              "ineligible_attempt",
          "ineligible_precedes_warmup_and_metric_unavailability");
  // A corrupted warmup must not authorize valid measurement samples on replay.
  auto raw = load(root / "attempts/0/client/endpoint.json");
  raw["scenario"]["end_event"] = 4;
  save(root / "attempts/0/client/endpoint.json", raw);
  require(!turtle::analysis::regenerate(root) &&
              load(root / "analysis.json").at("eligible_measurements") == 0,
          "failed_warmup_blocks_stale_measurement_rows");
  std::filesystem::create_directories(root / "not-an-attempt");
  auto escape = root / "attempts" / "alias";
  if (!std::filesystem::exists(escape))
    std::filesystem::create_directory_symlink(root / "not-an-attempt", escape);
  for (auto path :
       {std::string("attempts/alias"), (root / "attempts" / "0").string(),
        std::string("attempts/../not-an-attempt")}) {
    auto altered = manifest;
    altered["attempts"][0]["directory"] = path;
    save(root / "manifest.json", altered);
    bool rejected = false;
    try {
      (void)turtle::analysis::regenerate(root);
    } catch (const std::exception &e) {
      rejected = std::string(e.what()) == "attempt_directory_outside_run";
    }
    require(rejected && !std::filesystem::exists(root / "not-an-attempt" /
                                                 "analysis.json"),
            "replay_directory_not_confined");
  }
}
void perf() {
  Json a = {{"available", true},
            {"cycles", 1ULL << 60},
            {"instructions", 1ULL << 58},
            {"time_enabled_ns", 100},
            {"time_running_ns", 100}},
       b = a;
  b["cycles"] = integer(a.at("cycles")) + 1001;
  b["instructions"] = integer(a.at("instructions")) + 77;
  b["time_enabled_ns"] = 200;
  b["time_running_ns"] = 200;
  auto r = turtle::analysis::counter_delta(a, b, "available");
  require(r.at("cycles").at("value") == 1001, "counter_integer");
  b["time_running_ns"] = 199;
  r = turtle::analysis::counter_delta(a, b, "available");
  require(r.at("cycles").at("value").is_null() &&
              r.at("cycles_raw").at("value") == 1001,
          "counter_no_scaling");
  b["cycles"] = a.at("cycles");
  b["time_running_ns"] = 200;
  require(turtle::analysis::counter_delta(a, b, "available")
                  .at("cycles")
                  .at("value") == 0,
          "counter_zero");
  b["time_running_ns"] = 100;
  auto never_ran = turtle::analysis::counter_delta(a, b, "available");
  require(never_ran.at("cycles").at("value").is_null() &&
              never_ran.at("cycles_raw").at("value").is_null(),
          "zero_running_not_zero_cycles");
  auto absent = turtle::analysis::counter_delta(
      {{"available", false}}, {{"available", false}}, "unsupported");
  require(absent.at("cycles").at("availability") == "unsupported",
          "counter_unavailable");
  auto parsed = turtle::profiling::parse_samples(
      "12/12 2000000000.123456789: 100 cycles:u: abc foo (/a)\n12/12 "
      "2000000000.123456790: 300 cycles:u: def bar (/a)\n");
  require(parsed.at("unparsed_or_lost").empty(), "sample_parser");
  auto samples = parsed.at("samples");
  require(samples[0].at("wall_ns") == 2000000000123456789ULL, "sample_integer");
  require(turtle::profiling::distribution(samples).at("functions")[0].at(
              "period_fraction") == .75,
          "period_weights");
  require(turtle::profiling::window(samples, integer(samples[0].at("wall_ns")),
                                    integer(samples[1].at("wall_ns")))
                  .at("sample_count") == 1,
          "half_open_window");
  require(!turtle::profiling::parse_samples("PERF_RECORD_LOST 3\n")
               .at("unparsed_or_lost")
               .empty(),
          "lost_samples");
}
} // namespace
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("fixtures output required");
    std::filesystem::create_directories(argv[2]);
    phases(argv[1]);
    raw_boundaries();
    opaque_flight(std::filesystem::path(argv[2]) / "opaque", protected_records({192}));
    opaque_flight(std::filesystem::path(argv[2]) / "opaque", protected_records({16, 103, 73}));
    lifecycle(std::filesystem::path(argv[2]) / "replay");
    if (turtle::capture::probe("lo").value("reason", Json(nullptr)) !=
        "pcap_not_built") {
      capture(argv[2], false);
      capture(argv[2], true);
      for (auto role : {"client", "server"})
        for (bool shared_tail : {false, true})
          presend_order(std::filesystem::path(argv[2]) / "s4-order", role,
                        shared_tail);
    }
    perf();
    std::cout
        << "Deterministic phase, pcap, counter and sample checks passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
