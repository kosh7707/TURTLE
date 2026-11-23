#include "analysis/evidence.hpp"
#include "capture/capture.hpp"

namespace turtle::analysis::evidence {
namespace fs = std::filesystem;
using artifact::integer;
using artifact::measurement;
namespace {
Json read_capture(const fs::path &dir, const std::string &role, Endpoint &ep) {
  const auto network = artifact::load(dir / "network.json");
  const auto health =
      network.value("capture", Json::object()).value(role, Json::object());
  require(network.value("availability", "") == "available" &&
              health.value("availability", "") == "available" &&
              health.value("ready_before_connect", false) &&
              health.value("kernel_dropped", Json(nullptr)) == 0 &&
              health.value("interface_dropped", Json(nullptr)) == 0,
          "capture_missing_or_dropped");

  std::map<std::string, Bytes> streams;
  std::map<std::string, std::uint64_t> scenario_end;
  for (auto local : {"send", "receive"}) {
    const auto direction = flow(role, local);
    streams.emplace(direction, ep.streams.at(local));
    scenario_end[direction] = integer(
        ep.summary.at("scenario").at(std::string("wire_") + local + "_bytes"));
  }
  auto captures =
      capture::analyze(dir / (role + ".pcap"), streams, scenario_end,
                       network.at("client_ip"), network.at("server_ip"), true);
  for (const auto &direction : captures)
    require(available(direction), "capture_stream_mismatch");
  const auto &forward = captures.at("client_to_server").at("packets");
  require(!forward.empty() &&
              forward.front().at("dport") == health.at("server_port") &&
              health.at("server_port") ==
                  artifact::load(dir / "processes.json").at("server_port"),
          "capture_attempt_port_mismatch");

  const auto outbound = flow(role, "send");
  const auto limit = scenario_end.at(outbound);
  std::uint64_t repeated = 0;
  for (const auto &packet : captures.at(outbound).at("packets")) {
    for (const auto &range : packet.at("retransmitted_ranges")) {
      auto begin = integer(range[0]), end = std::min(integer(range[1]), limit);
      if (begin < end)
        repeated += end - begin;
    }
  }
  ep.metrics["retransmitted_send_bytes"] = measurement(repeated);
  return captures;
}

// A later, unrelated ACK cannot establish what this data-bearing copy knew.
void append_ack_witnesses(Json &order, const Json &captures,
                          const char *direction, const Json &sent_record,
                          const Json &peer_record) {
  const auto first_byte = integer(sent_record.at("wire_begin"));
  const auto &peer_number = peer_record.at("number");
  for (const auto &packet : captures.at(direction).at("packets")) {
    if (!integer(packet.at("payload_bytes")) ||
        first_byte < integer(packet.at("wire_begin")) ||
        first_byte >= integer(packet.at("wire_end")))
      continue;
    const auto &acked = packet.at("opposite_records_cumulatively_acked");
    if (std::find(acked.begin(), acked.end(), peer_number) == acked.end())
      continue;
    order["ack_witnesses"].push_back(
        {{"packet_id", packet.at("id")},
         {"direction", direction},
         {"contains_first_byte_of_record", sent_record.at("number")},
         {"ack_stream_offset", packet.at("ack_stream_offset")},
         {"peer_record_fully_received_before_this_copy", peer_number}});
    order["verdict"] = "copy_specific_ack_evidence";
  }
}
} // namespace

void collect_tcp_evidence(const fs::path &dir, const Task &task, Endpoint &ep,
                          Json &observations, Json &out) {
  out["captures"][task.role] = read_capture(dir, task.role, ep);
  observations["capture"] = measurement(true);
  if (!task.greeting || !observations.contains("finished_boundary"))
    return;

  auto &order = observations["presend_tcp_order"];
  order = {{"socket_only", "indeterminate"},
           {"scope", "named_TCP_copy_not_peer_TLS_processing"},
           {"ack_witnesses", Json::array()},
           {"verdict", "indeterminate"}};
  const auto &boundaries = observations.at("finished_boundary");
  const auto &client_boundary = boundaries.at("client_to_server");
  if (!available(client_boundary) ||
      !available(boundaries.at("server_to_client")))
    return;

  const bool measured_client = task.role == "client";
  const auto &from_client = ep.records.at(measured_client ? "send" : "receive");
  const auto &from_server = ep.records.at(measured_client ? "receive" : "send");
  const auto &cf =
      from_client.at(integer(client_boundary.at("value").at("record")) - 1);
  // In S4 the greeting can span records or end inside a record shared with
  // the response. Use the TLS layer's verified plaintext ranges, not lengths
  // inferred again from ciphertext or a record ordinal from another connection.
  const Json *first_greeting = nullptr, *last_greeting = nullptr;
  for (const auto &record : from_server) {
    auto ranges = record.find("application_ranges");
    if (ranges == record.end())
      continue;
    for (const auto &part : *ranges) {
      if (part.at("message") != "greeting")
        continue;
      if (part.at("plaintext_begin") == 0)
        first_greeting = &record;
      if (part.at("plaintext_end") == task.greeting)
        last_greeting = &record;
    }
    if (!first_greeting || !last_greeting)
      continue;
    const auto &captures = out.at("captures").at(task.role);
    append_ack_witnesses(order, captures, "client_to_server", cf,
                         *last_greeting);
    append_ack_witnesses(order, captures, "server_to_client", *first_greeting,
                         cf);
    return;
  }
}
} // namespace turtle::analysis::evidence
