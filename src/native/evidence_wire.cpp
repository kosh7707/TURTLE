#include "native/evidence_wire.hpp"
#include "native/evidence.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace turtle::native {
namespace {
using J = nlohmann::json;
using Bytes = std::vector<unsigned char>;
void check(bool v, const char *reason) {
  if (!v)
    throw std::invalid_argument(reason);
}
uint64_t u(const J &e, const char *key) {
  const auto &n = e.at(key);
  check(n.is_number_unsigned() ||
            (n.is_number_integer() && n.get<int64_t>() >= 0),
        "invalid_wire_unsigned");
  return n.get<uint64_t>();
}
Bytes decode(const J &j) {
  const std::string &s = j.get_ref<const std::string &>();
  check(s.size() % 2 == 0, "odd_hex");
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    throw std::invalid_argument("invalid_hex");
  };
  Bytes b;
  b.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2)
    b.push_back((nib(s[i]) << 4) | nib(s[i + 1]));
  return b;
}
std::string encode(const Bytes &bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(2 * bytes.size());
  for (auto b : bytes) {
    out += digits[b >> 4];
    out += digits[b & 15];
  }
  return out;
}
struct Direction {
  Bytes bytes;
  uint64_t transferred = 0, prefix_bytes = 0;
  bool complete = true;
  J spans = J::array();
};
struct Source {
  bool active = false, started = false, interrupted = false;
  uint64_t sends = 0, receives = 0, peeks = 0;
  Direction dir[2];
};
struct Record {
  size_t lo, hi;
  int type;
};
std::vector<Record> records(const Bytes &b, bool &valid) {
  std::vector<Record> result;
  size_t i = 0;
  while (i < b.size()) {
    if (b.size() - i < 5) {
      valid = false;
      break;
    }
    auto end = i + 5 + 256 * b[i + 3] + b[i + 4];
    if (b[i] < 20 || b[i] > 23 || b[i + 1] != 3 || b[i + 2] > 3 ||
        end > b.size() || end - i - 5 > 16640) {
      valid = false;
      break;
    }
    check(result.size() < 65536, "record_count_limit");
    result.push_back({i, end, b[i]});
    i = end;
  }
  return result;
}
J anchor(const Direction &d, size_t offset, bool sent) {
  const auto x = std::lower_bound(
      d.spans.begin(), d.spans.end(), offset,
      [](const J &span, size_t off) { return span.at("end") <= off; });
  const auto key = sent ? "begin_ns" : "end_ns";
  if (x != d.spans.end() && x->at("begin") <= offset && !x->at(key).is_null())
    return J{{"seq", x->at("seq")},
             {"ns", x->at(key)},
             {"edge", sent ? "begin" : "end"}};
  return nullptr;
}
bool retry_random(const Bytes &h) {
  constexpr std::array<unsigned char, 32> retry = {
      0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
      0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
      0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
  // Fixed HelloRetryRequest random, RFC 8446 section 4.1.3.
  return h.size() >= 38 &&
         std::equal(retry.begin(), retry.end(), h.begin() + 6);
}
bool hello_info(const Bytes &h, bool client, J &id, bool &retry) {
  if (h.size() < 40 || h[0] != (client ? 1 : 2) ||
      h[1] * 65536 + h[2] * 256u + h[3] != h.size() - 4 || h[4] != 3 ||
      h[5] != 3)
    return false;
  size_t p = 38, n = h[p++];
  if (n > 32 || p + n >= h.size())
    return false;
  p += n;
  auto word = [&](size_t at) { return unsigned(h[at]) * 256 + h[at + 1]; };
  if (client) {
    if (p + 2 > h.size())
      return false;
    n = word(p);
    p += 2;
    if (!n || n % 2 || p + n >= h.size())
      return false;
    p += n;
    n = h[p++];
    if (!n || p + n > h.size())
      return false;
    p += n;
  } else {
    if (p + 3 > h.size() || h[p + 2] != 0)
      return false;
    id["suite"] = word(p);
    p += 3;
    retry = retry_random(h);
  }
  if (p + 2 > h.size() || p + 2 + word(p) != h.size())
    return false;
  p += 2;
  while (p < h.size()) {
    if (p + 4 > h.size())
      return false;
    auto type = word(p);
    n = word(p + 2);
    p += 4;
    if (p + n > h.size())
      return false;
    if (!client && type == 43) {
      if (n != 2 || id.contains("version"))
        return false;
      id["version"] = word(p);
    }
    if (!client && type == 51) {
      if ((retry && n != 2) || (!retry && (n < 5 || word(p + 2) != n - 4)) ||
          id.contains("group"))
        return false;
      id["group"] = word(p);
    }
    p += n;
  }
  return client || (id.contains("version") && id.contains("group"));
}
// A positive HRR in an uninterrupted observed prefix survives a later loss
// of coverage or a truncated final record. Do not infer HRR absence this way.
bool initial_retry(const Direction &d) {
  Bytes h;
  for (size_t off = 0; off + 5 <= d.prefix_bytes && d.bytes[off] == 22;) {
    if (d.bytes[off + 1] != 3 || d.bytes[off + 2] > 3)
      return false;
    size_t len = d.bytes[off + 3] * 256u + d.bytes[off + 4],
           next = off + 5 + len;
    if (next > d.prefix_bytes || len > 16384)
      return false;
    h.insert(h.end(), d.bytes.begin() + off + 5, d.bytes.begin() + next);
    off = next;
    if (h.size() < 4)
      continue;
    size_t total = 4 + h[1] * 65536u + h[2] * 256u + h[3];
    if (total > 65536 || h[0] != 2)
      return false;
    if (h.size() >= total) {
      h.resize(total);
      J id = J::object();
      bool retry = false;
      return hello_info(h, false, id, retry) && retry;
    }
  }
  return false;
}
} // namespace
void evaluate_wire(const J &c, J &r) {
  const auto &events = r.at("events");
  J ready = nullptr, end = nullptr, ready_ns = nullptr, end_ns = nullptr;
  for (const auto &e : events)
    if (e["kind"] == "event") {
      if (e["name"] == "ready") {
        ready = e["seq"];
        ready_ns = e["ns"];
      }
      if (e["name"] == "end") {
        end = e["seq"];
        end_ns = e["ns"];
      }
    }
  std::map<std::string, Source> src;
  J headers = J::array(), wire = J::object();
  for (const auto &e : events) {
    auto k = e.at("kind").get<std::string>();
    auto seq = u(e, "seq");
    if (seq == ready) {
      for (auto &[_, source] : src) {
        source.started = source.active;
        source.interrupted = !source.active;
      }
    }
    if (k != "coverage" && k != "io" && k != "bytes" && k != "header")
      continue;
    if (k == "header") {
      check(e.at("sent").is_boolean() && decode(e.at("hex")).size() == 5,
            "invalid_header");
      u(e, "offset");
      if ((ready.is_null() || seq >= ready) && (end.is_null() || seq <= end))
        headers.push_back(e);
      continue;
    }
    std::string name = e.at("source");
    check(name == "socket" || name == "library_io" || name == "stream" ||
              name == "header",
          "invalid_source");
    auto &s = src[name];
    if (k == "coverage") {
      check(e.at("active").is_boolean(), "invalid_coverage_flag");
      bool active = e["active"];
      check(active != s.active, "duplicate_coverage_state");
      s.active = active;
      if (!ready.is_null() && seq > ready && (end.is_null() || seq < end) &&
          (!active || !s.started))
        s.interrupted = true;
      continue;
    }
    if (k == "bytes") {
      check(name == "stream" && e.at("sent").is_boolean(),
            "invalid_stream_observation");
      if ((!ready.is_null() && seq < ready) || (!end.is_null() && seq > end))
        continue;
      auto b = decode(e.at("hex"));
      check(!b.empty() && b.size() == u(e, "length"), "invalid_stream_length");
      auto &d = s.dir[e.at("sent").get<bool>()];
      if (!s.active)
        s.interrupted = true;
      d.spans.push_back(J{{"begin", d.transferred},
                          {"end", d.transferred + b.size()},
                          {"seq", seq},
                          {"begin_ns", nullptr},
                          {"end_ns", nullptr}});
      if (s.started && !s.interrupted && d.complete &&
          d.prefix_bytes == d.transferred)
        d.prefix_bytes += b.size();
      d.transferred += b.size();
      d.bytes.insert(d.bytes.end(), b.begin(), b.end());
      continue;
    }
    check((name == "socket" || name == "library_io") &&
              e.at("sent").is_boolean() && e.at("peek").is_boolean() &&
              e.at("result").is_number_integer(),
          "invalid_io");
    bool sent = e.at("sent"), peek = e.at("peek");
    auto result = e.at("result").get<int64_t>();
    check((!sent || !peek) && u(e, "begin_ns") &&
              u(e, "begin_ns") <= u(e, "ns") &&
              u(e, "begin_tid") == u(e, "tid") &&
              (result <= 0 || uint64_t(result) <= u(e, "requested")),
          "invalid_io_range");
    if (!ready.is_null() && seq < ready)
      continue;
    if (!end.is_null() && seq > end)
      continue;
    if (!s.active || (!ready_ns.is_null() && e["begin_ns"] < ready_ns) ||
        (!end_ns.is_null() && e["ns"] > end_ns))
      s.interrupted = true;
    auto &d = s.dir[sent];
    if (sent)
      ++s.sends;
    else if (result > 0) {
      ++s.receives;
      if (peek)
        ++s.peeks;
    }
    if (result <= 0)
      continue;
    Bytes b;
    if (!e.at("hex").is_null()) {
      b = decode(e.at("hex"));
      check(b.size() == uint64_t(result), "invalid_ciphertext_size");
    }
    if (peek)
      continue;
    if (!d.spans.empty() && d.spans.back().at("end_ns") > e.at("begin_ns"))
      d.complete =
          false; // Completion order is not wire order for overlapping calls.
    d.spans.push_back(J{{"begin", d.transferred},
                        {"end", d.transferred + result},
                        {"seq", seq},
                        {"begin_ns", e["begin_ns"]},
                        {"end_ns", e["ns"]}});
    if (s.started && !s.interrupted && d.complete &&
        d.prefix_bytes == d.transferred)
      d.prefix_bytes += b.size();
    d.transferred += result;
    d.complete &= !b.empty();
    d.bytes.insert(d.bytes.end(), b.begin(), b.end());
  }
  auto &metrics = r["metrics"];
  wire["headers"] = headers;
  metrics["header_layout"] = nullptr;
  auto covered = [&](const Source &s) {
    return !ready.is_null() && !end.is_null() && s.started && !s.interrupted;
  };
  auto transferred_both = [&](const Source &s) {
    return covered(s) && s.dir[0].transferred && s.dir[1].transferred;
  };
  if (uses_endpoint_contract(c)) {
    // One continuously observed transport source must actually transfer data
    // in both directions. No peek, failed call or opposite endpoint can fill
    // a missing direction. The buffer contents themselves are optional.
    J source = nullptr;
    bool seen = false, interrupted = false;
    for (auto name : {"library_io", "socket"}) {
      auto it = src.find(name);
      if (it == src.end())
        continue;
      seen = true;
      if (transferred_both(it->second)) {
        source = name;
        break;
      }
      interrupted |= it->second.interrupted;
    }
    const bool ok = !source.is_null();
    wire["transport_hook"] = {
        {"verified", ok ? J(true) : interrupted ? J(false) : J(nullptr)},
        {"source", source},
        {"reason", ok ? J(nullptr) : !seen ? J("hook_unobserved")
                     : interrupted ? J("coverage_interrupted")
                     : ready.is_null() || end.is_null() ? J("missing_lifecycle_window")
                                                        : J("no_bidirectional_transfer")}};
  }
  metrics["library_io"] = nullptr;
  if (src.count("library_io")) {
    const auto &io = src.at("library_io");
    if (io.interrupted)
      metrics["library_io"] = false;
    else if (transferred_both(io))
      metrics["library_io"] = true;
  }
  if (src.count("socket")) {
    auto &s = src["socket"];
    wire["counts"] = {{"send_attempts", s.sends},
                      {"positive_receives", s.receives},
                      {"positive_peeks", s.peeks},
                      {"sent_bytes", s.dir[1].transferred},
                      {"consumed_bytes", s.dir[0].transferred}};
    metrics["transport_counts"] = covered(s) && s.sends > 0 && s.receives > 0
                                      ? J(true)
                                  : s.interrupted ? J(false)
                                                  : J(nullptr);
  }
  J flights = J::object(), neg = J::object();
  uint64_t framed_end[2] = {0, 0};
  bool timed = true;
  bool both = true, layout = true, raw_hrr = false;
  for (bool from_client : {false, true}) {
    bool sent = (c.at("role") == "client") == from_client;
    std::string flow = from_client ? "client_to_server" : "server_to_client";
    Source *best = nullptr;
    std::string provider;
    for (auto name : {"socket", "library_io", "stream"})
      if (src.count(name)) {
        auto &s = src[name];
        auto &d = s.dir[sent];
        wire["ranges"][name][flow] = d.spans;
        if (!from_client && initial_retry(d))
          raw_hrr = true;
        if (covered(s) && d.complete && !d.bytes.empty()) {
          if (best)
            check(best->dir[sent].bytes == d.bytes,
                  "divergent_ciphertext_sources");
          else {
            best = &s;
            provider = name;
          }
        }
      }
    if (!best) {
      both = false;
      continue;
    }
    if (provider == "stream")
      timed = false;
    const auto &d = best->dir[sent];
    bool ok = true;
    auto rec = records(d.bytes, ok);
    layout &= ok;
    if (!ok || rec.empty())
      continue;
    framed_end[sent] = rec.back().hi;
    if (sent)
      wire["sender_extent"] = {
          {"run_id", c.at("run_id")}, {"connection_id", c.at("connection_id")},
          {"role", c.at("role")},     {"end_seq", end},
          {"bytes", d.transferred},   {"hex", encode(d.bytes)},
          {"source", provider}};
    J list = J::array();
    for (auto &z : rec)
      list.push_back(J{{"type", z.type},
                       {"begin", z.lo},
                       {"end", z.hi},
                       {"first", anchor(d, z.lo, true)},
                       {"last", anchor(d, z.hi - 1, false)}});
    wire["records"][flow] = {{"source", provider}, {"records", list}};
    for (const auto &h : headers)
      if (h["sent"] == bool(sent)) {
        auto off = u(h, "offset");
        auto it = std::find_if(rec.begin(), rec.end(),
                               [&](auto z) { return z.lo == off; });
        check(it != rec.end(), "header_offset_conflict");
        auto b = decode(h.at("hex"));
        check(std::equal(b.begin(), b.end(), d.bytes.begin() + off),
              "header_content_conflict");
      }
    size_t first = 0;
    Bytes hello;
    while (first < rec.size() && rec[first].type == 22) {
      const auto &z = rec[first++];
      hello.insert(hello.end(), d.bytes.begin() + z.lo + 5,
                   d.bytes.begin() + z.hi);
    }
    J ids = J::object();
    bool retry = false;
    if (!hello_info(hello, from_client, ids, retry))
      continue;
    if (!from_client) {
      neg = ids;
      raw_hrr |= retry;
    }
    auto flight = [&](size_t a, size_t b) {
      return J{{"begin", rec[a].lo},
               {"end", rec[b].hi},
               {"source", provider},
               {"anchor", anchor(d, sent ? rec[a].lo : rec[b].hi - 1, sent)},
               {"inner_message_times", nullptr}};
    };
    flights[from_client ? "CH" : "SH"] = flight(0, first - 1);
    if (retry)
      continue;
    auto &facts = r.at("facts");
    auto policy = [&](const std::string &key) {
      return sent ? facts.value(key, J(nullptr))
                  : c.value("peer_" + key, J(nullptr));
    };
    if (policy("sender_unpadded") != true ||
        policy("application_only_tail") != true)
      continue;
    auto suite = r.at("negotiated").value("suite", J(nullptr));
    if (suite.is_null())
      suite = neg.value("suite", J(nullptr));
    if (suite.is_null())
      continue;
    unsigned id = suite.get<unsigned>();
    if (id < 0x1301 || id > 0x1305)
      continue;
    size_t overhead = id == 0x1305 ? 9 : 17;
    auto messages = c.at("messages");
    uint64_t app =
        from_client ? messages.value("CAD", 0u)
                    : messages.value("SAD1", 0u) + messages.value("SAD2", 0u);
    // An expected workload is not proof of its actual application tail.
    // Use the native positive TLS returns from this direction as well.
    uint64_t observed = 0;
    for (const auto &event : r.at("message_events")) {
      if (event.at("name") == (sent ? "write_accepted" : "read_return") &&
          (event.at("message") == "CAD") == from_client)
        observed += u(event, "length");
    }
    if (observed != app)
      continue;
    size_t stop = rec.size();
    if (!sent) {
      // Peer END and local END are different boundaries. An encrypted alert or
      // ticket following peer END may already be in this receiver's read
      // buffer.
      const auto extent = c.value("peer_sender_extent", J(nullptr));
      if (extent.is_null())
        continue;
      check(extent.at("run_id") == c.at("run_id") &&
                extent.at("connection_id") == c.at("connection_id") &&
                extent.at("role") == (from_client ? "client" : "server") &&
                u(extent, "end_seq") > 0,
            "wrong_sender_extent_binding");
      auto prefix = decode(extent.at("hex"));
      check(!prefix.empty() && prefix.size() == u(extent, "bytes"),
            "invalid_sender_extent");
      size_t overlap = std::min(prefix.size(), d.bytes.size());
      check(
          std::equal(prefix.begin(), prefix.begin() + overlap, d.bytes.begin()),
          "sender_extent_content_conflict");
      if (prefix.size() > d.bytes.size())
        continue;
      auto terminal = std::find_if(rec.begin(), rec.end(), [&](auto rec) {
        return rec.hi == prefix.size();
      });
      check(terminal != rec.end(), "sender_extent_not_record_aligned");
      stop = size_t(terminal - rec.begin()) + 1;
      if (stop <= first)
        continue;
    }
    while (app && stop > first) {
      const auto &z = rec[stop - 1];
      auto body = z.hi - z.lo - 5;
      if (z.type != 23 || body <= overhead || body - overhead > app)
        break;
      app -= body - overhead;
      --stop;
    }
    while (first < stop && rec[first].type == 20 &&
           rec[first].hi - rec[first].lo == 6 &&
           d.bytes[rec[first].lo + 5] == 1)
      ++first;
    if (app || first == stop ||
        !std::all_of(rec.begin() + first, rec.begin() + stop,
                     [](auto z) { return z.type == 23; }))
      continue;
    J group = flight(first, stop - 1);
    group["basis"] = "same_connection_unpadded_application_only_tail";
    group["application_bytes"] = observed;
    group["aead_tag_bytes"] = overhead - 1;
    flights[from_client ? "client_protected_flight"
                        : "server_protected_flight"] = std::move(group);
  }
  if (raw_hrr) {
    r["wire_hrr"] = true;
  } else if (!neg.empty())
    r["wire_hrr"] = false;
  wire["negotiated"] = neg;
  if (raw_hrr || r.at("facts").value("hrr", J(nullptr)) == true) {
    flights = J::object();
    wire["flight_exclusion"] = "hello_retry_request";
  }
  wire["flights"] = flights;
  metrics["ciphertext_bytes"] = both ? J(true) : J(nullptr);
  metrics["record_layout"] = !layout ? J(false) : both ? J(true) : J(nullptr);
  metrics["timed_records"] = timed ? metrics["record_layout"] : J(nullptr);
  // Header callbacks are independent record-layout evidence. They are not
  // data delivery, and their timestamps are not send/receive boundaries.
  if (src.count("header") && covered(src["header"])) {
    uint64_t next[2] = {0, 0};
    bool contiguous = true;
    for (const auto &h : headers) {
      if (h.at("seq") < ready || h.at("seq") > end)
        continue;
      auto b = decode(h.at("hex"));
      bool sent = h.at("sent");
      contiguous &= u(h, "offset") == next[sent];
      check(b[0] >= 20 && b[0] <= 23 && b[1] == 3 && b[2] <= 3 &&
                (256 * b[3] + b[4]) <= 16640,
            "invalid_header_sequence");
      next[sent] += 5 + 256 * b[3] + b[4];
    }
    // A contiguous callback prefix does not certify the entire direction.
    // An inbound suffix may merely be buffered read-ahead; that does not
    // contradict the callbacks, but cannot corroborate a full layout either.
    if (!contiguous || framed_end[1] > next[1])
      metrics["header_layout"] = false;
    else if (framed_end[0] <= next[0] && next[0] && next[1])
      metrics["header_layout"] = true;
  }
  r["wire"] = std::move(wire);
}
} // namespace turtle::native
