#include "native/pre_cf.hpp"
#include <algorithm>
#include <charconv>
#include <optional>
#include <set>
namespace turtle::native {
using artifact::Json;
namespace {
struct Stream {
  std::string hex;
  uint64_t last_seq = 0;
};
bool ok(const Json &r) {
  return r.at("status") != "invalid" && r.at("status") != "contradicted";
}
std::set<std::string> supplied(const Json &r) {
  std::set<std::string> sources;
  bool ready = false;
  for (const auto &e : r.at("events")) {
    if (e.at("kind") == "event" && e.at("name") == "ready")
      ready = true;
    if (e.at("kind") == "coverage") {
      auto source = e.at("source").get<std::string>();
      if (ready || e.at("active") == true)
        sources.insert(source);
      else
        sources.erase(source);
    } else if (ready && e.contains("source"))
      sources.insert(e.at("source").get<std::string>());
    else if (ready && e.at("kind") == "header")
      sources.insert("header");
  }
  return sources;
}
std::optional<Stream> trace(const Json &r, const std::string &source, bool send,
                            uint64_t limit = UINT64_MAX) {
  Stream out;
  bool bound = false, ready = false;
  uint64_t last_end = 0;
  for (const auto &e : r.at("events")) {
    auto seq = artifact::integer(e.at("seq"));
    if (seq > limit)
      break;
    if (e.at("kind") == "coverage" && e.at("source") == source) {
      if (ready)
        return {}; // any in-window detach/late attach breaks continuity
      bound = e.at("active").get<bool>();
    }
    if (e.at("kind") == "event" && e.at("name") == "ready") {
      if (!bound)
        return {};
      ready = true;
    }
    if (ready && source == "stream" && e.at("kind") == "bytes" &&
        e.at("sent") == send) {
      out.hex += e.at("hex").get_ref<const std::string &>();
      out.last_seq = seq;
      continue;
    }
    if (e.at("kind") != "io" || e.at("source") != source ||
        e.at("sent") != send)
      continue;
    if (!ready)
      continue;
    if (!bound)
      return {};
    if (e.at("result").get<int64_t>() <= 0 || e.at("peek") == true)
      continue;
    if (artifact::integer(e.at("begin_ns")) < last_end ||
        !e.at("hex").is_string())
      return {};
    last_end = artifact::integer(e.at("ns"));
    const auto &b = e.at("hex").get_ref<const std::string &>();
    if (b.size() != 2 * artifact::integer(e.at("result")))
      return {};
    out.hex += b;
    out.last_seq = seq;
  }
  if (!ready || out.hex.empty())
    return {};
  return out;
}
// Optional send observations can veto the proof, never supply the TCP bound.
// The receiver is allowed to have consumed only a prefix when the gate closes.
bool agrees(const Json &server, const std::string &received) {
  std::optional<std::string> reported;
  for (const auto &source : supplied(server)) {
    if (source == "header")
      continue;
    auto seen = trace(server, source, true);
    if (!seen || !seen->hex.starts_with(received) ||
        (reported && seen->hex != *reported))
      return false;
    reported = std::move(seen->hex);
  }
  const auto &known = reported ? *reported : received;
  bool ready = false, header_bound = false;
  for (const auto &e : server.at("events")) {
    if (e.at("kind") == "event" && e.at("name") == "ready")
      ready = true;
    if (e.at("kind") == "coverage" && e.at("source") == "header") {
      if (ready)
        return false;
      header_bound = e.at("active").get<bool>();
    }
    if (!ready || e.at("kind") != "header" || e.at("sent") != true)
      continue;
    auto off = artifact::integer(e.at("offset"));
    if (!header_bound)
      return false;
    if (off < known.size() / 2) {
      const auto &header = e.at("hex").get_ref<const std::string &>();
      auto pos = static_cast<size_t>(off) * 2;
      auto len = std::min(known.size() - pos, header.size());
      if (known.compare(pos, len, header, 0, len) != 0)
        return false;
    }
  }
  return true;
}
unsigned byte(const std::string &hex, size_t n) {
  unsigned v;
  auto p = hex.data() + 2 * n;
  auto [end, rc] = std::from_chars(p, p + 2, v, 16);
  if (rc != std::errc() || end != p + 2)
    throw std::invalid_argument("invalid_probe_hex");
  return v;
}
bool protected_records(const std::string &hex, size_t start) {
  auto size = hex.size() / 2;
  if (start >= size)
    return false;
  for (size_t i = 0; i < size;) {
    if (size - i < 5 || byte(hex, i + 1) != 3 || byte(hex, i + 2) != 3)
      return false;
    size_t z = 256 * byte(hex, i + 3) + byte(hex, i + 4);
    if (!z || z > 16640 || z > size - i - 5 ||
        (i < start && i + 5 + z > start) || (i >= start && byte(hex, i) != 23))
      return false;
    i += 5 + z;
  }
  return true;
}
} // namespace
Json pre_cf_extent(const Json &client, const Json &server, size_t greeting,
                   bool direct_reference_server) {
  if (!greeting || !ok(client) || !ok(server))
    return nullptr;
  auto &cm = client.at("lifecycle");
  auto &sm = server.at("lifecycle");
  if (!cm.value("probe_paused", Json(nullptr)).is_object() ||
      cm.value("probe_resumed", Json(nullptr)).is_object() ||
      sm.value("hs_complete", Json(nullptr)).is_object())
    return nullptr;
  auto paused = artifact::integer(cm.at("probe_paused").at("seq"));
  auto received = trace(client, "library_io", false);
  if (!received || received->last_seq >= paused)
    return nullptr;
  // The trusted probe client uses SSL_set_fd's direct socket BIO; its positive
  // BIO reads (including read-ahead) have already removed these bytes from TCP.
  const auto sources = supplied(server);
  // Only a transport hook or the known reference's direct SSL_set_fd BIO
  // supplies a terminal TCP extent. Generic BIO/stream/header observations
  // are cross-checks; actual delivery must be proven at the frozen receiver.
  std::string source;
  if (sources.contains("socket"))
    source = "socket";
  else if (direct_reference_server && sources.contains("library_io"))
    source = "library_io";
  if (!agrees(server, received->hex))
    return nullptr;
  auto sent = source.empty() ? std::nullopt : trace(server, source, true);
  size_t accepted = 0;
  uint64_t first = 0, offer = 0, last = 0;
  for (const auto &e : server.at("message_events")) {
    if (e.at("message") != "SAD1")
      continue;
    auto seq = artifact::integer(e.at("seq"));
    if (e.at("name") == "write_attempt") {
      if (!first)
        first = seq;
      offer = seq;
    }
    if (e.at("name") == "write_accepted") {
      if (!offer || offer >= seq ||
          artifact::integer(e.at("offset")) != accepted)
        return nullptr;
      if (sent) {
        auto flush = trace(server, source, true, seq);
        if (!flush || flush->last_seq <= offer)
          return nullptr;
      }
      accepted += artifact::integer(e.at("length"));
      last = seq;
      offer = 0;
    }
  }
  if (accepted != greeting || !first || !last)
    return nullptr;
  if (!sent)
    return {{"client_source", "direct_probe_socket_bio"},
            {"server_source", nullptr},
            {"pause_seq", paused},
            {"pause_ns", cm.at("probe_paused").at("ns")},
            {"last_sad1_accept_seq", last},
            {"client_consumed_bytes", received->hex.size() / 2},
            {"server_terminal_bytes", nullptr},
            {"required_queue_bytes", nullptr}};
  auto before = trace(server, source, true, first);
  if (!before || !protected_records(sent->hex, before->hex.size() / 2))
    return nullptr;
  auto consumed = received->hex.size() / 2, terminal = sent->hex.size() / 2;
  return {{"client_source", "direct_probe_socket_bio"},
          {"server_source", source},
          {"pause_seq", paused},
          {"pause_ns", cm.at("probe_paused").at("ns")},
          {"last_sad1_accept_seq", last},
          {"last_sender_io_seq", sent->last_seq},
          {"client_consumed_bytes", consumed},
          {"server_terminal_bytes", terminal},
          {"required_queue_bytes", terminal - consumed}};
}
bool pre_cf_arrived(const Json &e, uint64_t queued) {
  return !e.is_null() && !e.at("required_queue_bytes").is_null() &&
         queued >= artifact::integer(e.at("required_queue_bytes"));
}
Json pre_cf_delivery(const Json &client, const Json &server, const Json &extent,
                     uint64_t queued) {
  if (extent.is_null() || !ok(client) || !ok(server))
    return nullptr;
  auto validation = client.at("timeline").at("SAD1").at("validated");
  auto resume = client.at("lifecycle").value("probe_resumed", Json(nullptr));
  if (validation.is_null() || resume.is_null() ||
      resume.at("seq") <= extent.at("pause_seq") ||
      resume.at("seq") >= validation.at("seq"))
    return nullptr;
  auto consumed = trace(client, "library_io", false,
                        artifact::integer(validation.at("seq")));
  if (!consumed)
    return nullptr;
  auto prior = artifact::integer(extent.at("client_consumed_bytes"));
  auto total = consumed->hex.size() / 2;
  if (total < prior || total - prior > queued ||
      !agrees(server, consumed->hex))
    return nullptr;
  if (!extent.at("server_source").is_null()) {
    auto sent = trace(server, extent.at("server_source").get<std::string>(), true);
    if (!pre_cf_arrived(extent, queued) || !sent ||
        sent->hex.size() / 2 !=
            artifact::integer(extent.at("server_terminal_bytes")) ||
        !sent->hex.starts_with(consumed->hex))
      return nullptr;
  }
  return {{"validated_seq", validation.at("seq")},
          {"consumed_through_validation", total},
          {"needed_from_queue", total - prior}};
}
} // namespace turtle::native
