#include "analysis/evidence.hpp"

namespace turtle::analysis {
using artifact::integer;
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
      continue;
    }
    observations["finished_boundary"][direction] =
        finished_boundary(ep.records.at(local), task.sent(from_client),
                          client.at("cipher").at("value"), declared);
    const auto &boundary = observations.at("finished_boundary").at(direction);
    if (available(boundary))
      label_application_tail(ep.records.at(local), boundary, task, from_client);
  }
}
} // namespace evidence
} // namespace turtle::analysis
