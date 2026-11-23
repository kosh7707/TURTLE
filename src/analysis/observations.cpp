#include "analysis/evidence.hpp"
#include "capture/capture.hpp"

namespace turtle::analysis::evidence {
namespace fs = std::filesystem;
using artifact::integer;
using artifact::measurement;
namespace {
// Do not attach any header event in this direction until all five-byte
// notifications match the actual stream. Socket evidence is independent.
bool link_header_events(Json &records, const Json &headers,
                        const Bytes &stream) {
  if (records.size() != headers.size())
    return false;
  for (std::size_t i = 0; i < records.size(); ++i) {
    const auto begin = stream.begin() + integer(records[i].at("wire_begin"));
    if (headers[i].value("header", Json(nullptr)) != Bytes(begin, begin + 5))
      return false;
  }
  for (std::size_t i = 0; i < records.size(); ++i)
    records[i]["header_event"] = headers[i].at("id");
  return true;
}
// The wire image is captured on the measured side only. Record identity is
// local to this connection; neither message order nor record sizes from a
// warmup are consulted.
void read_record_observations(const fs::path &dir, Endpoint &ep,
                              Json &observations) {
  // A malformed optional adapter notification must not erase independently
  // verified socket evidence. Require contiguous coverage for each source.
  const auto reason =
      ep.summary.at("scenario").value("observations_complete", false)
          ? Json(nullptr)
          : ep.summary.value("observation_reason", Json(nullptr));
  bool public_complete =
      reason != "nested_adapter_io" && reason != "unpaired_adapter_io";
  bool headers_complete = reason != "invalid_adapter_notification";
  Json batches = Json::object();
  for (auto d : {"send", "receive"}) {
    auto stream =
        artifact::read_bytes(dir / (std::string("wire_") + d + ".bin"));
    require(stream.size() == integer(ep.summary.at("streams")
                                         .at(std::string("wire_") + d)
                                         .at("bytes")),
            "wire_stream_size_mismatch");
    auto need = integer(
        ep.summary.at("scenario").at(std::string("wire_") + d + "_bytes"));
    require(need > 0 && need <= stream.size(), "scenario_stream_size_mismatch");
    auto records = capture::raw_records(std::span(stream).first(need));
    Json headers = Json::array(), messages = Json::array(), io = Json::array();
    std::uint64_t next_socket = 0, next_public = 0;
    std::map<std::uint64_t, capture::Ranges> submissions;
    for (const auto &e : ep.events) {
      if (e.at("kind") != "socket" || e.at("direction") != d ||
          !e.at("success").get<bool>() ||
          e.at("transferred").get<std::int64_t>() <= 0)
        continue;
      auto call = integer(e.at("call_id"));
      if (call && call <= ep.events.size() &&
          ep.events.at(call - 1).at("operation") == "shutdown")
        continue;
      auto parent = integer(e.at("parent"));
      if (!parent || parent > ep.events.size()) {
        public_complete = false;
        continue;
      }
      const auto &p = ep.events.at(parent - 1);
      const auto child_start = integer(e.at("begin").at("wall_ns")),
                 child_end = integer(e.at("end").at("wall_ns"));
      public_complete = public_complete && p.at("kind") == "transport" &&
                        integer(p.at("begin").at("wall_ns")) <= child_start &&
                        child_start <= child_end &&
                        child_end <= integer(p.at("end").at("wall_ns"));
      capture::merge(submissions[parent], integer(e.at("wire_begin")),
                     integer(e.at("wire_end")));
    }
    for (const auto &e : ep.events) {
      if (e.at("direction") != d || e.at("kind") == "call")
        continue;
      auto call = integer(e.at("call_id"));
      require(call && call <= ep.events.size() &&
                  ep.events.at(call - 1).at("kind") == "call",
              "trace_call_reference_missing");
      if (ep.events.at(call - 1).at("operation") == "shutdown")
        continue;
      auto kind = e.at("kind");
      if (kind == "header") {
        headers.push_back(e);
        continue;
      }
      if (kind == "message") {
        if (!e.contains("message_type"))
          continue;
        messages.push_back({{"event_id", e.at("id")},
                            {"call_id", call},
                            {"message_type", e.at("message_type")}});
        continue;
      }
      if (kind != "socket" && kind != "transport")
        continue;
      if (e.at("success") != true ||
          e.at("transferred").get<std::int64_t>() <= 0)
        continue;
      auto a = integer(e.at("wire_begin")), b = integer(e.at("wire_end"));
      auto &cursor = kind == "socket" ? next_socket : next_public;
      bool valid = b > a && b <= need &&
                   b - a == integer(e.at("transferred")) && a == cursor;
      if (kind == "transport")
        valid = valid &&
                submissions[integer(e.at("id"))] == capture::Ranges{{a, b}};
      if (!valid && kind == "transport") {
        public_complete = false;
        continue;
      }
      require(valid, "socket_io_range_gap_or_mismatch");
      cursor = b;
      auto parts = capture::mapping(records, a, b);
      for (const auto &p : parts) {
        auto &record = records.at(integer(p.at("record")) - 1);
        auto key = kind == "socket" ? "socket_ranges" : "public_io_ranges";
        record[key].push_back(
            {{"event_id", e.at("id")},
             {"source", e.value("source", std::string("socket"))},
             {"wire_begin", p.at("wire_begin")},
             {"wire_end", p.at("wire_end")},
             {"part", p.at("part")}});
      }
      io.push_back({{"event_id", e.at("id")},
                    {"kind", kind},
                    {"call_id", call},
                    {"record_ranges", parts}});
    }
    require(next_socket == need, "socket_trace_incomplete");
    public_complete = public_complete && next_public == need;
    const bool matched = link_header_events(records, headers, stream);
    headers_complete = headers_complete && matched;
    ep.records[d] = std::move(records);
    ep.links[d] = std::move(io);
    batches[d] = messages.empty()
                     ? missing("no_handshake_message_notifications")
                     : measurement(std::move(messages));
    ep.streams[d] = std::move(stream);
  }
  observations["records"] = measurement(true);
  observations["public_io"] = public_complete
                                  ? measurement(true)
                                  : missing("public_io_coverage_incomplete");
  observations["headers"] =
      headers_complete ? measurement(true)
                       : missing("header_notification_coverage_incomplete");
  // Handshake message callbacks identify messages in a public call, not
  // necessarily the TLS record containing them (records may be coalesced).
  observations["message_notifications"] = std::move(batches);
}
} // namespace

void collect(const fs::path &dir, const Task &task, bool include_capture,
             bool task_matches, Endpoint &ep, const Json &roles,
             Json &observations, Json &out) {
  if (task.recording == "detailed") {
    try {
      read_record_observations(dir / task.role, ep, observations);
    } catch (const std::exception &e) {
      for (auto key : {"records", "public_io", "headers"})
        observations[key] = missing(e.what());
    }
  }
  if (available(observations.at("records")) && task_matches)
    annotate_tls_records(task, roles, ep, observations);

  ep.metrics["retransmitted_send_bytes"] =
      measurement(nullptr, "not_collected", "tcp_evidence_unavailable");
  if (include_capture) {
    try {
      collect_tcp_evidence(dir, task, ep, observations, out);
    } catch (const std::exception &e) {
      observations["capture"] = missing(e.what());
    }
  }
}
} // namespace turtle::analysis::evidence
