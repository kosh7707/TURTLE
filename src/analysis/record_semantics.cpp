#include "analysis/evidence.hpp"

namespace turtle::analysis {
using artifact::integer;
bool is_hello_retry(const Bytes &hello) {
  constexpr std::array<unsigned char, 32> retry{
      0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
      0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
      0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
  return hello.size() >= 38 &&
         std::equal(retry.begin(), retry.end(), hello.begin() + 6);
}
namespace {
constexpr unsigned new_session_ticket = 4;
constexpr unsigned finished = 20;
constexpr unsigned key_update = 24;

bool has_unexpected_control(const Json &notifications) {
  if (!evidence::available(notifications))
    return false;
  // Tickets, KeyUpdate, or any message after Finished contradict the
  // application-only suffix, even if its byte count happens to match.
  bool finished_seen = false, unexpected = false;
  for (const auto &message : notifications.at("value")) {
    const auto type = integer(message.at("message_type"));
    unexpected = unexpected || finished_seen || type == new_session_ticket ||
                 type == key_update;
    if (type == finished)
      finished_seen = true;
  }
  return unexpected;
}

void label_application_tail(Json &records, const Json &boundary,
                            const evidence::Task &task, bool from_client) {
  const auto finished_record = integer(boundary.at("value").at("record"));
  records.at(finished_record - 1)["terminates_finished"] = true;
  const auto overhead = integer(boundary.at("aead_tag_bytes")) + 1;
  std::uint64_t begin = 0;
  for (auto i = finished_record; i < records.size(); ++i) {
    auto &record = records[i];
    const auto end = begin + integer(record.at("body_bytes")) - overhead;
    auto label_overlap = [&](const char *message, std::uint64_t message_begin,
                             std::uint64_t message_end) {
      const auto lo = std::max(begin, message_begin);
      const auto hi = std::min(end, message_end);
      if (lo < hi)
        record["application_ranges"].push_back({{"message", message},
                                                {"plaintext_begin", lo},
                                                {"plaintext_end", hi}});
    };
    if (from_client) {
      label_overlap("request", 0, task.request);
    } else {
      label_overlap("greeting", 0, task.greeting);
      label_overlap("response", task.greeting, task.greeting + task.response);
    }
    begin = end;
  }
}

// Count complete leading TLSPlaintext records that carry this one Hello.
// The handshake header itself may straddle two or more record payloads.
size_t hello_prefix(const Json &records, const Bytes &wire, bool client) {
  Bytes hello;
  size_t count = 0;
  for (const auto &r : records) {
    if (r.at("content_type") != 22)
      break;
    const auto a = integer(r.at("wire_begin")) + 5,
               b = integer(r.at("wire_end"));
    hello.insert(hello.end(), wire.begin() + a, wire.begin() + b);
    ++count;
  }
  if (hello.size() < 38 || hello[0] != (client ? 1 : 2) || hello[4] != 3 ||
      hello[5] != 3 || (!client && is_hello_retry(hello)))
    return 0;
  const auto size =
      (size_t(hello[1]) << 16) | (size_t(hello[2]) << 8) | hello[3];
  if (size != hello.size() - 4)
    return 0;
  for (auto i = count; i < records.size(); ++i)
    if (records[i].at("content_type") == 22)
      return 0;
  return count;
}

// A transport anchor is a call boundary covering the boundary byte, not a
// packet arrival or an internal handshake-message timestamp.
Json flight(const Endpoint &ep, const Json &records, size_t first, size_t end,
            bool send, bool public_trace) {
  const auto &boundary = records.at(send ? first : end - 1);
  auto anchor = [&](const char *source) -> Json {
    if (!boundary.contains(source) || boundary.at(source).empty())
      return nullptr;
    const auto &ranges = boundary.at(source);
    auto id = integer((send ? ranges.front() : ranges.back()).at("event_id"));
    const auto &event = ep.events.at(id - 1);
    const auto edge = send ? "begin" : "end";
    if (!event.contains(edge) || event.at(edge).at("wall_ns").is_null())
      return nullptr;
    return {{"event_id", id},
            {"edge", edge},
            {"wall_ns", event.at(edge).at("wall_ns")}};
  };
  auto spans = Json::array();
  for (auto i = first; i < end; ++i) {
    const auto &r = records[i];
    spans.push_back({{"record", r.at("number")},
                     {"wire_begin", r.at("wire_begin")},
                     {"wire_end", r.at("wire_end")}});
  }
  return {{"local_direction", send ? "send" : "receive"},
          {"records", std::move(spans)},
          {"socket_anchor", anchor("socket_ranges")},
          {"public_io_anchor",
           public_trace ? anchor("public_io_ranges") : Json(nullptr)}};
}

void describe_flights(const evidence::Task &task, Endpoint &ep,
                      Json &observations, const char *local, bool client,
                      const Json &finished) {
  auto &flights = observations["tls_flights"];
  auto &plain = flights[client ? "CH" : "SH"];
  auto &opaque =
      flights[client ? "client_protected_flight" : "server_protected_flight"];
  const auto &records = ep.records.at(local);
  const auto &wire = ep.streams.at(local);
  size_t start = hello_prefix(records, wire, client);
  if (!start) {
    plain = opaque = evidence::missing("clear_hello_not_verified");
    return;
  }
  const bool send = std::string_view(local) == "send";
  const bool public_trace = evidence::available(observations.at("public_io"));
  plain =
      artifact::measurement(flight(ep, records, 0, start, send, public_trace));
  if (!evidence::available(finished)) {
    opaque = evidence::missing(finished.at("reason").get<std::string>());
    return;
  }
  const auto stop = integer(finished.at("value").at("record"));
  while (start < stop && records[start].at("content_type") == 20 &&
         records[start].at("body_bytes") == 1 &&
         wire.at(integer(records[start].at("wire_begin")) + 5) == 1)
    ++start;
  if (start >= stop ||
      std::any_of(records.begin() + start, records.begin() + stop,
                  [](const auto &r) { return r.at("content_type") != 23; })) {
    opaque = evidence::missing("protected_flight_not_contiguous");
    return;
  }
  auto group = flight(ep, records, start, stop, send, public_trace);
  const bool mutual = task.auth == "mtls";
  group["conceptual_members"] =
      client ? (mutual ? Json{"CC", "CCV", "CF"} : Json{"CF"})
             : (mutual ? Json{"EE", "CR", "SC", "SCV", "SF"}
                       : Json{"EE", "SC", "SCV", "SF"});
  group["inner_message_times"] = nullptr;
  group["finished_record_basis"] = finished.at("basis");
  opaque = artifact::measurement(std::move(group));
}
} // namespace

Json finished_boundary(const Json &records, std::uint64_t application_bytes,
                       const std::string &cipher, bool declared_unpadded_tail) {
  if (!declared_unpadded_tail)
    return evidence::missing("application_tail_policy_unproven");
  const auto suite = evidence::canonical(cipher);
  unsigned tag;
  if (suite == "TLSAES128GCMSHA256" || suite == "TLSAES256GCMSHA384" ||
      suite == "TLSCHACHA20POLY1305SHA256" || suite == "TLSAES128CCMSHA256")
    tag = 16;
  else if (suite == "TLSAES128CCM8SHA256")
    tag = 8;
  else
    return evidence::missing("unknown_aead_tag_length");

  // An unpadded body holds content, one inner content-type byte and the tag.
  const auto overhead = tag + 1;
  auto remaining = application_bytes;
  for (std::size_t i = records.size(); i > 0; --i) {
    const auto &record = records[i - 1];
    if (record.at("content_type") != 23)
      return evidence::missing("unexpected_record_in_protected_tail");
    const auto body = integer(record.at("body_bytes"));
    if (body <= overhead)
      return evidence::missing("unexpected_record_in_protected_tail");
    if (!remaining) {
      auto result =
          artifact::measurement({{"record", record.at("number")},
                                 {"wire_begin", record.at("wire_begin")},
                                 {"wire_end", record.at("wire_end")}});
      result.update({{"basis", "same_connection_unpadded_application_tail"},
                     {"application_bytes", application_bytes},
                     {"aead_tag_bytes", tag}});
      return result;
    }
    const auto content = body - overhead;
    if (content > remaining)
      return evidence::missing("application_tail_length_mismatch");
    remaining -= content;
  }
  return evidence::missing("finished_predecessor_missing");
}

namespace evidence {
void annotate_tls_records(const Task &task, const Json &roles, Endpoint &ep,
                          Json &observations) {
  const auto &client = roles.at("client").at("negotiated");
  const auto &server = roles.at("server").at("negotiated");
  const auto &suite = client.at("cipher").at("value");
  const auto cipher =
      suite.is_string() ? suite.get<std::string>() : std::string{};
  const bool declared = client.value("record_policy", 0) == 1 &&
                        server.value("record_policy", 0) == 1 &&
                        client.value("profile", 0) != 0 &&
                        server.value("profile", 0) != 0;
  for (auto local : {"send", "receive"}) {
    const auto direction = flow(task.role, local);
    const bool from_client = direction == "client_to_server";
    const auto &messages = observations.at("message_notifications").at(local);
    if (has_unexpected_control(messages)) {
      observations["finished_boundary"][direction] =
          missing("unexpected_post_handshake_control");
    } else {
      observations["finished_boundary"][direction] = finished_boundary(
          ep.records.at(local), task.sent(from_client), cipher, declared);
    }
    const auto &boundary = observations.at("finished_boundary").at(direction);
    if (available(boundary))
      label_application_tail(ep.records.at(local), boundary, task, from_client);
    if (task.named_flights)
      describe_flights(task, ep, observations, local, from_client, boundary);
  }
}
} // namespace evidence
} // namespace turtle::analysis
