#include "submission/connection_evidence.hpp"

#include <charconv>
#include <stdexcept>
#include <string>
#include <utility>

namespace turtle::submission {
namespace {
using artifact::Json;
using artifact::integer;

const Json missing = nullptr;

const Json &field(const Json &object, std::string_view key) {
  if (object.is_object())
    if (auto it = object.find(key); it != object.end())
      return *it;
  return missing;
}

class Checks {
  Json issues_ = Json::array();
  bool failed_ = false;

public:
  void expect(std::string name, const Json &observed, const Json &expected = true) {
    if (observed == expected)
      return;
    failed_ |= !observed.is_null();
    issues_.push_back({{"check", std::move(name)},
                       {"observed", observed},
                       {"expected", expected},
                       {"state", observed.is_null() ? "insufficient_evidence"
                                                     : "failed"}});
  }

  void report(Json &result) {
    result["state"] = failed_          ? "failed"
                      : issues_.empty() ? "passed"
                                        : "insufficient_evidence";
    result["issues"] = std::move(issues_);
  }
};

Json point(const Json &event, std::string_view role,
           std::string_view layer = "application") {
  if (event.is_null())
    return nullptr;
  Json item{{"event", event.at("name")},
            {"role", role},
            {"layer", layer},
            {"monotonic_ns", event.at("ns")},
            {"sequence", event.at("seq")}};
  if (event.contains("length"))
    item["bytes"] = event.at("length");
  if (event.contains("offset"))
    item["offset"] = event.at("offset");
  if (event.contains("message") && !event.at("message").is_null())
    item["message"] = event.at("message");
  return item;
}

// Only called with two points from the same role. Sequence establishes the
// operation ordering when the monotonic clock returns equal readings.
Json before(const Json &a, const Json &b) {
  if (a.is_null() || b.is_null())
    return nullptr;
  if (a.at("role") != b.at("role"))
    throw std::logic_error("cross-role event comparison");
  return a.at("sequence") < b.at("sequence") &&
         a.at("monotonic_ns") <= b.at("monotonic_ns");
}

Json app_span(const Json &a, const Json &b) {
  if (a.is_null() || b.is_null() || (a != b && before(a, b) != true))
    return nullptr;
  return {{"clock", "CLOCK_MONOTONIC"},
          {"start", a},
          {"end", b},
          {"delta_ns", integer(b.at("monotonic_ns")) -
                           integer(a.at("monotonic_ns"))}};
}

std::string hex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) {
    result += digits[byte >> 4];
    result += digits[byte & 15];
  }
  return result;
}

class Participant {
  const Json &report_;
  std::string role_;

public:
  Participant(const Json &pair, const char *role)
      : report_(field(pair, role)), role_(role) {}

  const std::string &role() const { return role_; }
  const Json &metric(const char *name) const {
    return field(field(report_, "metrics"), name);
  }
  const Json &fact(const char *name) const {
    return field(field(report_, "facts"), name);
  }
  const Json &message(const char *label) const {
    return field(field(report_, "timeline"), label);
  }
  Json lifecycle(const char *name, const char *layer = "application") const {
    return point(field(field(report_, "lifecycle"), name), role_, layer);
  }
  const Json &message_events() const { return field(report_, "message_events"); }

  Json session(Checks &checks, bool verify) const {
    const auto &version = field(field(report_, "negotiated"), "version");
    auto complete = lifecycle("hs_complete");
    checks.expect(role_ + ": handshake complete",
                  complete.is_null() ? Json(nullptr) : Json(true));
    checks.expect(role_ + ": TLS version", version, 0x0304);
    checks.expect(role_ + ": resumption", fact("resumed"), false);
    checks.expect(role_ + ": early data", fact("early_data"), false);
    checks.expect(role_ + ": peer verification configured", fact("verify_peer"), verify);
    checks.expect(role_ + ": peer certificate present", fact("peer_cert_present"), verify);
    if (verify)
      checks.expect(role_ + ": peer certificate verified", fact("peer_verified"));
    checks.expect(role_ + ": requested authentication", metric("authentication"));
    return {{"negotiated", field(report_, "negotiated")},
            {"resumed", fact("resumed")},
            {"early_data", fact("early_data")},
            {"verify_peer", fact("verify_peer")},
            {"peer_verified", fact("peer_verified")},
            {"peer_cert_present", fact("peer_cert_present")},
            {"authentication", metric("authentication")},
            {"handshake_complete", std::move(complete)},
            {"local_finished_message", lifecycle("local_finished_message", "tls_message")},
            {"peer_finished_message", lifecycle("peer_finished_message", "tls_message")}};
  }
};

Json exchange(Checks &checks, const Participant &sender,
              const Participant &receiver, const char *label,
              std::string_view expected) {
  const auto &tx = sender.message(label);
  const auto &rx = receiver.message(label);
  const std::string name = label;
  checks.expect(name + ": sender content matches", field(tx, "content_consistent"));
  checks.expect(name + ": receiver content matches", field(rx, "content_consistent"));
  auto offer = point(field(tx, "first_write_attempt"), sender.role());
  auto accepted = point(field(tx, "final_write_accept"), sender.role());
  auto first = point(field(rx, "first_read_return"), receiver.role());
  auto full = point(field(rx, "last_read_return"), receiver.role());
  auto verified = point(field(rx, "validated"), receiver.role());

  // The native analyzer's 'complete' can remain unknown when no observation
  // was made and write_offer_pairs can be null for the composite-only ABI.
  checks.expect(name + ": all write offers paired", field(tx, "write_offer_pairs"));
  checks.expect(name + ": sender complete", field(tx, "complete"));
  checks.expect(name + ": receiver complete", field(rx, "complete"));
  checks.expect(name + ": first write before last acceptance", before(offer, accepted));
  checks.expect(name + ": last receive before validation", before(full, verified));
  auto read_span = app_span(first, full);
  checks.expect(name + ": first/full receive boundary",
                read_span.is_null() ? Json(nullptr) : Json(true));

  return {{"expected_bytes", expected.size()},
          {"expected_hex", hex(expected)},
          {"sender_content_matches", field(tx, "content_consistent")},
          {"receiver_content_matches", field(rx, "content_consistent")},
          {"sent_bytes", field(tx, "complete") == true ? Json(expected.size()) : Json(nullptr)},
          {"received_bytes", field(rx, "complete") == true ? Json(expected.size()) : Json(nullptr)},
          {"first_write_offer", std::move(offer)},
          {"final_write_accept", std::move(accepted)},
          {"first_read_return", std::move(first)},
          {"full_read_return", std::move(full)},
          {"first_to_full_read_span", std::move(read_span)},
          {"validated", std::move(verified)}};
}

Json server_response(Checks &checks, const Json &sessions, const Json &cad,
                     const Json &sad2) {
  const auto &handshake = sessions.at("server").at("handshake_complete");
  const auto &validated = cad.at("validated");
  const auto &write = sad2.at("first_write_offer");
  const auto a = before(handshake, write), b = before(validated, write);
  checks.expect("server: handshake before first SAD2 write", a);
  checks.expect("server: CAD validation before first SAD2 write", b);
  return {{"handshake_complete", handshake}, {"cad_validated", validated},
          {"first_sad2_write", write}, {"handshake_before_write", a},
          {"cad_validation_before_write", b}};
}

Json server_first(Checks &checks, const Participant &server,
                  const Json &session, const Json &greeting, bool server_measured) {
  const auto &sf = session.at("local_finished_message");
  const auto &cf = session.at("peer_finished_message");
  const auto &hs = session.at("handshake_complete");
  const auto &offer = greeting.at("first_write_offer");
  const auto &accept = greeting.at("final_write_accept");
  checks.expect("server: greeting-first runtime report", server.fact("server_first"));
  checks.expect("server: greeting accepted before handshake completes",
                before(accept, hs));
  if (server_measured) {
    checks.expect("server: SF message before greeting write", before(sf, offer));
    checks.expect("server: greeting accepted before CF message", before(accept, cf));
    checks.expect("server: CF message before handshake completes", before(cf, hs));
  }
  // Neither protocol-message callback stamps a particular underlying hook.
  return {{"runtime_report", server.fact("server_first")},
          {"sf_message", sf},
          {"first_greeting_write", offer},
          {"final_greeting_accept", accept},
          {"cf_processed_message", cf},
          {"handshake_complete", hs},
          {"cf_transport_receive", nullptr},
          {"cf_transport_receive_reason", "protected record not identified by byte-count hooks"},
          {"basis", server_measured ? "tls_message_callbacks_and_app_io"
                                     : "peer_greeting_path_and_app_io"}};
}

Json client_order(const Json &session, const Json &greeting) {
  const auto &cf = session.at("local_finished_message");
  const auto &sad = greeting.at("full_read_return");
  Json order = nullptr;
  if (before(cf, sad) == true)
    order = "local_finished_message_before_greeting_full_read";
  else if (before(sad, cf) == true)
    order = "greeting_full_read_before_local_finished_message";
  return {{"tls_message_vs_app_read", order},
          {"local_finished_message", cf},
          {"greeting_full_read", sad},
          {"transport_order", nullptr},
          {"transport_order_reason", "hooks do not identify protected CF or SAD1"}};
}

uint64_t positive(std::string_view text) {
  uint64_t number = 0;
  auto [end, err] = std::from_chars(text.data(), text.data() + text.size(), number);
  if (err != std::errc{} || end != text.data() + text.size() || number == 0)
    throw std::runtime_error("invalid transport trace number");
  return number;
}
} // namespace

Json app_evidence(const Json &participants, std::string_view scenario,
                  std::string_view auth, const Json &application,
                  std::string_view measured_role) {
  Participant client(participants, "client"), server(participants, "server");
  const bool response = scenario == "S3" || scenario == "S4";
  const bool request = scenario == "S1" || response;
  const bool greeting = scenario == "S2" || scenario == "S4";
  Checks checks;
  Json result{{"sessions", {{"client", client.session(checks, true)},
                            {"server", server.session(checks, auth == "mtls")}}},
              {"messages", {{"CAD", nullptr}, {"SAD1", nullptr}, {"SAD2", nullptr}}},
              {"server_response_gate", nullptr},
              {"server_first", nullptr},
              {"client_order", nullptr},
              {"s2_research_endpoint", nullptr}};
  checks.expect("client: native scenario contract", client.metric("peer_task"));
  checks.expect("server: native scenario contract", server.metric("peer_task"));
  auto &messages = result.at("messages");
  if (request)
    messages["CAD"] = exchange(checks, client, server, "CAD",
                               application.at("request").get_ref<const std::string &>());
  if (response)
    messages["SAD2"] = exchange(checks, server, client, "SAD2",
                                application.at("response").get_ref<const std::string &>());
  if (greeting) {
    if (application.at("greeting") == application.at("response") && response)
      checks.expect("SAD1 and SAD2 distinguishable", false);
    messages["SAD1"] = exchange(checks, server, client, "SAD1",
                                application.at("greeting").get_ref<const std::string &>());
    result["server_first"] =
        server_first(checks, server, result.at("sessions").at("server"),
                     messages.at("SAD1"), measured_role == "server");
    result["client_order"] =
        client_order(result.at("sessions").at("client"), messages.at("SAD1"));
    if (scenario == "S2") {
      const bool measured_client = measured_role == "client";
      result["s2_research_endpoint"] = {
          {"event", measured_client ? "SAD1_full_read_return" : "CF_transport_receive"},
          {"point", measured_client ? messages.at("SAD1").at("full_read_return")
                                     : Json(nullptr)},
          {"reason", measured_client ? Json(nullptr)
                                     : Json("protected CF cannot be isolated by byte-count hooks")}};
    }
  }
  if (response)
    result["server_response_gate"] =
        server_response(checks, result.at("sessions"), messages.at("CAD"),
                        messages.at("SAD2"));

  auto observed_zero = [&](const Participant &p) -> Json {
    if (!p.message_events().is_array())
      return nullptr;
    if (scenario == "S0")
      checks.expect(p.role() + ": no application bytes", p.message_events().empty());
    return p.metric("peer_task") == true &&
                   (scenario != "S0" || p.message_events().empty())
               ? Json(0)
               : Json(nullptr);
  };
  const auto client_zero = observed_zero(client), server_zero = observed_zero(server);
  result["application_bytes"] = {
      {"client", {{"sent", request ? messages["CAD"]["sent_bytes"] : client_zero},
                  {"received", nullptr}}},
      {"server", {{"received", request ? messages["CAD"]["received_bytes"] : server_zero},
                  {"sent", nullptr}}}};
  // Derive only totals backed by completed, content-checked operations.
  auto total = [&](const char *key, const Json &zero) -> Json {
    const auto a = greeting ? messages["SAD1"][key] : zero;
    const auto b = response ? messages["SAD2"][key] : zero;
    return a.is_null() || b.is_null() ? Json(nullptr) : Json(integer(a) + integer(b));
  };
  result["application_bytes"]["client"]["received"] = total("received_bytes", client_zero);
  result["application_bytes"]["server"]["sent"] = total("sent_bytes", server_zero);
  checks.report(result);
  return result;
}

Json sdk_application_interval(const Json &native_timing, std::string_view role) {
  const auto &wall = field(native_timing, "wall_ns");
  if (wall.is_null())
    return nullptr;
  auto interval = app_span(point(field(native_timing, "begin"), role),
                           point(field(native_timing, "end"), role));
  if (!interval.is_null() && interval.at("delta_ns") == wall)
    return interval;
  return nullptr;
}

Json read_transport(std::istream &csv, std::istream &count, std::string_view role,
                    const Json &handshake_complete, const Json &cad_last_read) {
  std::string line;
  char extra;
  if (!std::getline(count, line) || count.eof() || line.empty() ||
      line[0] < '1' || line[0] > '9' || count.get(extra) || !count.eof() ||
      count.bad())
    throw std::runtime_error("missing or malformed transport trace count");
  const auto expected_rows = positive(line);
  if (!std::getline(csv, line) || line != "event,monotonic_ns,bytes")
    throw std::runtime_error("missing transport trace header");
  uint64_t last_ns = 0, send = 0, recv = 0, seq = 0;
  Json first, last, candidate;
  while (std::getline(csv, line)) {
    if (csv.eof())
      throw std::runtime_error("unterminated transport trace row");
    const auto begin = line.find(',');
    if (begin == line.npos)
      throw std::runtime_error("invalid transport trace fields");
    auto end = line.find(',', begin + 1);
    if (end == line.npos)
      throw std::runtime_error("invalid transport trace fields");
    const std::string_view raw(line), event = raw.substr(0, begin);
    const auto ns = positive(raw.substr(begin + 1, end - begin - 1));
    const auto bytes = positive(raw.substr(end + 1));
    const bool sent = event == "before_send_offer";
    if ((!sent && event != "after_recv") || ns < last_ns)
      throw std::runtime_error("invalid transport trace event or timestamp order");
    sent ? ++send : ++recv;
    last_ns = ns;
    last = {{"event", event},
            {"role", role},
            {"layer", "ciphertext_hook"},
            {"direction", sent ? "send" : "receive"},
            {"monotonic_ns", ns},
            {"bytes", bytes},
            {"row", ++seq}};
    if (first.is_null())
      first = last;
    if (role == "server" && !sent && !handshake_complete.is_null() &&
        !cad_last_read.is_null() && ns >= integer(handshake_complete.at("ns")) &&
        ns <= integer(cad_last_read.at("ns")))
      candidate = last;
  }
  if (!csv.eof() || csv.bad() || !send || !recv)
    throw std::runtime_error("incomplete bidirectional transport trace");
  if (seq != expected_rows)
    throw std::runtime_error("transport trace row count differs from producer count");
  Json receive_boundary = nullptr;
  if (!cad_last_read.is_null()) {
    receive_boundary = {{"candidate", std::move(candidate)},
                        {"identified", nullptr},
                        {"reason", "latest receive hook between handshake and CAD full read; protected content not identified"}};
  }
  return {{"before_send_offers", send},
          {"after_recv_returns", recv},
          {"send_size_semantics", "requested_write_bytes"},
          {"receive_size_semantics", "positive_return_bytes"},
          {"cad_receive_boundary", std::move(receive_boundary)},
          {"coverage_span", {{"clock", "CLOCK_MONOTONIC"},
                             {"start", first},
                             {"end", last},
                             {"delta_ns", last_ns - integer(first.at("monotonic_ns"))}}}};
}
} // namespace turtle::submission
