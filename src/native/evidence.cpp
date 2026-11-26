#include "native/evidence.hpp"
#include "native/evidence_wire.hpp"
#include <algorithm>
#include <initializer_list>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>

namespace turtle::native {
namespace {
using J = turtle::artifact::Json;
void require(bool valid, const char *reason) {
  if (!valid)
    throw std::invalid_argument(reason);
}
uint64_t u(const J &j, const char *key) {
  const auto &v = j.at(key);
  require(v.is_number_unsigned() ||
              (v.is_number_integer() && v.get<int64_t>() >= 0),
          "invalid_unsigned");
  return v.get<uint64_t>();
}
J all(std::initializer_list<J> values) {
  bool unknown = false;
  for (const auto &v : values) {
    if (v == false)
      return false;
    if (v != true)
      unknown = true;
  }
  return unknown ? J(nullptr) : J(true);
}
J match(const J &value, const J &expected) {
  return value.is_null() ? J(nullptr) : J(value == expected);
}
J present(const J &e) { return e.is_null() ? J(nullptr) : J(true); }
J before(const J &a, const J &b) {
  if (a.is_null() || b.is_null())
    return nullptr;
  return u(a, "ns") <= u(b, "ns") && u(a, "seq") < u(b, "seq");
}
struct Trace {
  bool plain_mismatch = false;
  std::set<std::string> wrong_content;
  uint64_t sent = 0, received = 0, validated = 0;
  J milestones = J::object(), facts = J::object(), identity = nullptr;
  std::map<std::string, std::map<std::string, std::vector<J>>> ranges;
  // There is no retry/result protocol: a new native offer supersedes an
  // unanswered one on the same thread; a positive return consumes it once.
  struct Offer {
    uint64_t seq, ns, offset, root_seq, root_offset;
    std::string bytes;
    // Nonzero only after the last offer's accepted prefix was verified.
    uint64_t next = 0;
  };
  std::map<uint64_t, Offer> pending;
  J write_errors = J::array();
  void composite_greeting(const J &e, const J &c) {
    const auto expected = u(c.at("messages"), "SAD1");
    // Either the neutral accept contract is the only observation, or the
    // submission recorded a complete greeting. Never pad a partial trace.
    const bool opaque = sent == 0 && !ranges.contains("SAD1");
    const bool observed = sent == expected && ranges.contains("SAD1");
    require(uses_endpoint_contract(c) && c.at("role") == "server" &&
                (c.at("scenario") == "S2" || c.at("scenario") == "S4") &&
                e.at("value") == true && milestones.contains("hs_complete") &&
                before(milestones.at("hs_complete"), e) == true &&
                !milestones.contains("end") && expected > 0 &&
                (opaque || observed) && pending.empty() &&
                !facts.contains("submission_greeting_accepted"),
            "invalid_composite_greeting");
    sent = expected;
  }
  void plain(const J &raw, const J &c, J &result) {
    auto op = raw.at("name").get<std::string>();
    bool tx = op == "write_attempt" || op == "write_accepted";
    require(tx || op == "read_return" || op == "validated",
            "invalid_plain_operation");
    auto n = u(raw, "length");
    require(n > 0 && n <= 1048576, "invalid_plain_bytes");
    uint64_t &cursor = tx ? sent : op == "validated" ? validated : received;
    auto start = cursor, end = start + n;
    J offer_seq = nullptr, match_offer = nullptr;
    const bool suffix =
        raw.contains("offer_ref") || raw.contains("suffix_offset");
    std::string_view bytes;
    if (suffix) {
      require(uses_endpoint_contract(c) && op == "write_attempt" &&
                  !raw.contains("hex"),
              "invalid_offer_reference");
      auto it = pending.find(u(raw, "tid"));
      require(it != pending.end(), "unknown_offer_reference");
      auto &offer = it->second;
      const auto skip = u(raw, "suffix_offset");
      const size_t full_size = offer.bytes.size() / 2;
      require(offer.root_seq == u(raw, "offer_ref") && offer.next == start &&
                  start > offer.root_offset &&
                  skip == start - offer.root_offset && skip < full_size &&
                  n == full_size - skip && u(raw, "ns") >= offer.ns,
              "invalid_offer_suffix");
      offer.seq = u(raw, "seq");
      offer.ns = u(raw, "ns");
      offer.offset = start;
      offer.next = 0;
    } else {
      const auto &encoded = raw.at("hex");
      require(encoded.is_string(), "invalid_plain_bytes");
      bytes = encoded.get_ref<const std::string &>();
      require(bytes.size() == 2 * n, "invalid_plain_bytes");
    }
    if (tx && !suffix) {
      auto tid = u(raw, "tid");
      if (op == "write_attempt") {
        auto seq = u(raw, "seq");
        pending.insert_or_assign(tid, Offer{seq, u(raw, "ns"), start, seq,
                                            start, std::string(bytes)});
      } else if (auto it = pending.find(tid);
                 it != pending.end() && !it->second.next) {
        auto &offer = it->second;
        auto offered = std::string_view(offer.bytes).substr(
            2 * (offer.offset - offer.root_offset));
        offer_seq = offer.seq;
        if (offer.ns > u(raw, "ns") || !offered.starts_with(bytes)) {
          match_offer = false;
          write_errors.push_back({{"reason", "write_return_contradicts_offer"},
                                  {"offer_seq", offer_seq},
                                  {"return_seq", raw.at("seq")}});
        } else if (offer.offset == start)
          match_offer = true;
        if (match_offer == true && offered.size() > bytes.size() &&
            c.contains("scenario_contract")) {
          offer.next = end;
          offer.ns = u(raw, "ns");
        } else
          pending.erase(it);
      }
    }
    uint64_t base = 0;
    bool from_client = tx == (c.at("role") == "client");
    for (auto label : {"CAD", "SAD1", "SAD2"}) {
      if (from_client != (std::string_view(label) == "CAD"))
        continue;
      auto length = c.at("messages").value(label, uint64_t(0));
      auto lo = std::max(base, start), hi = std::min(base + length, end);
      if (lo < hi) {
        const auto &expected =
            c.at("plaintext").at(label).get_ref<const std::string &>();
        require(expected.size() == 2 * length, "invalid_plain_expectation");
        // The entire referenced full offer already underwent this comparison
        // at root_offset. No new bytes are introduced by a checked suffix.
        const auto span = 2 * (hi - lo);
        const bool matches =
            suffix || bytes.substr(2 * (lo - start), span) ==
                          std::string_view(expected).substr(2 * (lo - base), span);
        if (!matches) {
          plain_mismatch = true;
          wrong_content.insert(label);
        }
        J e = raw;
        e.erase("hex");
        e.update(J{{"kind", "event"},
                   {"message", label},
                   {"offset", lo - base},
                   {"length", hi - lo}});
        if (op == "read_return" && c.contains("scenario_contract"))
          e["matches_expected"] = matches;
        if (op == "write_accepted") {
          e["offer_seq"] = offer_seq;
          e["offer_match"] = match_offer;
        }
        if (op == "validated") {
          if (hi != base + length) {
            base += length;
            continue;
          }
          e["offset"] = 0;
          e["length"] = length;
        }
        add(e);
        result.push_back(std::move(e));
      }
      base += length;
    }
    if (end > base)
      plain_mismatch = true;
    if (op != "write_attempt")
      cursor = end;
  }
  void add(const J &e) {
    auto k = e.at("kind").get<std::string>();
    if (k == "event") {
      auto n = e.at("name").get<std::string>();
      const auto &m = e.at("message");
      u(e, "offset");
      u(e, "length");
      static const std::set<std::string> operations = {
          "write_attempt", "write_accepted", "read_return", "validated"};
      if (operations.count(n)) {
        require(m == "CAD" || m == "SAD1" || m == "SAD2", "unknown_message");
        ranges[m.get<std::string>()][n].push_back(e);
      } else {
        static const std::set<std::string> milestones_set = {
            "ready",        "hs_begin",      "hs_progress",
            "hs_complete",  "auth_accepted", "end",
            "probe_paused", "probe_resumed", "probe_server_paused",
            "local_finished_message", "peer_finished_message"};
        require(milestones_set.count(n) && m.is_null() && u(e, "offset") == 0 &&
                    u(e, "length") == 0,
                "unknown_lifecycle_event");
        require(n == "hs_progress" || !milestones.contains(n),
                "duplicate_lifecycle_event");
        if (!milestones.contains(n))
          milestones[n] = e;
      }
    } else if (k == "fact") {
      auto n = e.at("name").get<std::string>();
      auto v = e.at("value");
      require(v.is_boolean() || v.is_null(), "invalid_fact_type");
      require(!facts.contains(n) || facts[n] == v, "conflicting_fact");
      facts[n] = v;
    } else if (k == "identity") {
      require(identity.is_null(), "duplicate_identity");
      identity = J::object();
      for (auto field : {"version", "suite", "group"}) {
        auto id = u(e, field);
        require(id <= 65535, "invalid_negotiated_id");
        identity[field] = id ? J(id) : J(nullptr);
      }
      require(e.at("peer_name").is_string() || e.at("peer_name").is_null(),
              "invalid_peer_name");
      identity["peer_name"] = e.at("peer_name");
    } else
      require(k == "coverage" || k == "io" || k == "bytes" || k == "header",
              "unknown_observation_kind");
  }
};
J pmu(const J &a, const J &b) {
  if (a.is_null() || b.is_null() || a.at("tid") != b.at("tid"))
    return nullptr;
  const auto &p = a.at("pmu");
  const auto &q = b.at("pmu");
  if (p.is_null() || q.is_null())
    return nullptr;
  for (const auto *snapshot : {&p, &q}) {
    const auto &v = *snapshot;
    if (v.value("type", "") != "PERF_TYPE_HARDWARE" ||
        v.value("cycles_config", "") != "PERF_COUNT_HW_CPU_CYCLES")
      return nullptr;
    for (auto key : {"cycles_id", "cycles", "enabled_ns", "running_ns",
                     "read_begin_ns", "read_end_ns"})
      if (!v.contains(key) || v.at(key).is_null())
        return nullptr;
    if (!u(v, "cycles_id") || u(v, "running_ns") > u(v, "enabled_ns"))
      return nullptr;
  }
  if (p.at("cycles_id") != q.at("cycles_id"))
    return nullptr;
  const bool partial = p.value("instructions", J(nullptr)).is_null();
  if (partial != q.value("instructions", J(nullptr)).is_null())
    return nullptr;
  const char *expected_status = partial ? "partial" : "available";
  if (a.value("pmu_status", "") != expected_status ||
      b.value("pmu_status", "") != expected_status)
    return nullptr;
  for (const auto *snapshot : {&p, &q}) {
    const auto &v = *snapshot;
    if (partial) {
      if (!v.value("instructions_id", J(nullptr)).is_null() ||
          !v.value("instructions_config", J(nullptr)).is_null())
        return nullptr;
    } else if (v.value("instructions_config", "") !=
                   "PERF_COUNT_HW_INSTRUCTIONS" ||
               !v.contains("instructions_id") || !u(v, "instructions_id") ||
               v.at("instructions_id") == v.at("cycles_id"))
      return nullptr;
  }
  if (!partial && p.at("instructions_id") != q.at("instructions_id"))
    return nullptr;
  J d = {{"instructions", nullptr},
         {"cycles_id", p.at("cycles_id")},
         {"type", p.at("type")},
         {"cycles_config", p.at("cycles_config")},
         {"instructions_id", p.value("instructions_id", J(nullptr))},
         {"instructions_config", p.value("instructions_config", J(nullptr))}};
  for (auto key : {"cycles", "instructions", "enabled_ns", "running_ns"}) {
    if (partial && std::string_view(key) == "instructions")
      continue;
    if (u(q, key) <= u(p, key))
      return nullptr;
    d[key] = u(q, key) - u(p, key);
  }
  if (u(d, "enabled_ns") < u(d, "running_ns") ||
      u(p, "read_begin_ns") < u(a, "ns") ||
      u(p, "read_end_ns") < u(p, "read_begin_ns") ||
      u(q, "read_begin_ns") < u(p, "read_end_ns") ||
      u(q, "read_begin_ns") < u(b, "ns") ||
      u(q, "read_end_ns") < u(q, "read_begin_ns"))
    return nullptr;
  d["tid"] = a.at("tid");
  d["begin_seq"] = a.at("seq");
  d["end_seq"] = b.at("seq");
  return d;
}
std::string pmu_status(const J &a, const J &b, const J &delta) {
  if (a.is_null() || b.is_null())
    return "unobserved";
  if (!delta.is_null()) {
    if (delta.at("instructions").is_null())
      return "partial";
    return delta.at("running_ns") == delta.at("enabled_ns") ? "available"
                                                            : "multiplexed";
  }
  if (a.at("pmu").is_object() || b.at("pmu").is_object())
    return "missing";
  for (auto s : {"unsupported", "missing", "not_collected"})
    if (a.value("pmu_status", "") == s && b.value("pmu_status", "") == s)
      return s;
  return "unavailable";
}
void evaluate(Trace &t, const J &c, J &r) {
  auto &f = t.facts;
  auto &e = t.milestones;
  auto &m = r["metrics"];
  const bool client = c.at("role") == "client", mutual = c.at("auth") == "mtls";
  auto s = c.at("scenario").get<std::string>();
  require(s.size() == 2 && s[0] == 'S' && s[1] >= '0' && s[1] <= '4',
          "invalid_scenario");
  const bool endpoint = uses_endpoint_contract(c);
  const bool composite_greeting =
      f.value("submission_greeting_accepted", J(nullptr)) == true;
  J core = all({before(e["ready"], e["hs_begin"]),
                before(e["hs_begin"], e["hs_complete"]),
                before(e["hs_complete"], e["end"])});
  J dest = t.identity.is_object() ? t.identity : J::object();
  r["negotiated"] = dest;
  r["facts"] = f;
  J auth = all({present(e["auth_accepted"]),
                match(f["verify_peer"], client || mutual),
                before(e["hs_begin"], e["auth_accepted"]),
                before(e["auth_accepted"], e["end"])});
  if (client || mutual) {
    auto name = dest["peer_name"];
    auth = all({auth, match(f["peer_verified"], true),
                name.is_null()
                    ? J(nullptr)
                    : J(name.is_string() && !name.get<std::string>().empty())});
    if (c.contains("peer_name") && c["peer_name"].is_string() &&
        !c["peer_name"].get<std::string>().empty())
      auth = all({auth, match(name, c["peer_name"])});
  }
  J profile = all({match(f["hrr"], false), match(f["early_data"], false),
                   match(f["resumed"], false), match(dest["version"], 0x304),
                   present(dest["suite"]), present(dest["group"])});
  J requested_ids = true;
  bool ids_requested = false;
  for (auto key : {"suite", "group"}) {
    auto expected = "expected_" + std::string(key);
    if (c.contains(expected) && !c[expected].is_null() && c[expected] != 0) {
      ids_requested = true;
      requested_ids = all({requested_ids, match(dest[key], c[expected])});
    }
  }
  profile = all({profile, requested_ids});
  J timeline = !t.plain_mismatch, peer_task = !t.plain_mismatch;
  for (auto msg : {"CAD", "SAD1", "SAD2"}) {
    bool cad = std::string_view(msg) == "CAD",
         greet = std::string_view(msg) == "SAD1";
    bool used = cad     ? (s == "S1" || s == "S3" || s == "S4")
                : greet ? (s == "S2" || s == "S4")
                        : (s == "S3" || s == "S4");
    auto &streams = t.ranges[msg];
    auto &item = r["timeline"][msg];
    if (!used) {
      if (!streams.empty())
        timeline = peer_task = false;
      item = nullptr;
      continue;
    }
    uint64_t size = u(c.at("messages"), msg);
    require(size > 0, "missing_message_size");
    bool send = client == cad;
    const char *transfer = send ? "write_accepted" : "read_return";
    auto &fragments = streams[transfer];
    auto &attempts = streams["write_attempt"];
    auto &validations = streams["validated"];
    if (!streams[send ? "read_return" : "write_accepted"].empty() ||
        !(send ? validations : attempts).empty())
      timeline = peer_task = false;
    J pairs = true;
    uint64_t pos = 0;
    bool consistent = !t.wrong_content.count(msg);
    J first = nullptr, last = nullptr, attempt = nullptr, valid = nullptr,
      prev = nullptr;
    for (const auto &ev : fragments) {
      auto n = u(ev, "length");
      if (send)
        pairs = all({pairs, ev.at("offer_match")});
      consistent &= pos == u(ev, "offset") && n > 0 && n <= size - pos;
      if (!consistent)
        continue;
      if (first.is_null())
        first = ev;
      if (!prev.is_null() && before(prev, ev) != true)
        consistent = false;
      pos += n;
      prev = ev;
      if (pos == size)
        last = ev;
    }
    if (!attempts.empty()) {
      attempt = attempts.front();
      for (const auto &ev : attempts)
        consistent &= u(ev, "offset") < size && u(ev, "length") > 0 &&
                      u(ev, "length") <= size - u(ev, "offset");
    }
    if (!validations.empty()) {
      valid = validations.front();
      consistent &= validations.size() == 1 && u(valid, "offset") == 0 &&
                    u(valid, "length") == size;
    }
    if (endpoint && !send) {
      // A later wrong fragment disqualifies the task, not a genuine first
      // return of the expected prefix. Never label a wrong prefix as SAD/CAD.
      if (!fragments.empty() && fragments.front().at("offset") == 0 &&
          fragments.front().at("matches_expected") == true)
        first = fragments.front();
      auto ordered = before(last, valid);
      if (!consistent || ordered != true) {
        consistent &= ordered != false;
        valid = nullptr;
      }
    }
    item = {{"first_write_attempt", attempt},
            {"final_write_accept", send ? last : J(nullptr)},
            {"first_read_return", send ? J(nullptr) : first},
            {"last_read_return", send ? J(nullptr) : last},
            {"validated", valid}};
    J detail =
        all({J(consistent), send ? pairs : before(last, valid), present(last)});
    J task = all({J(consistent), J(pairs != false),
                  send ? present(last) : present(valid),
                  before(send ? last : valid, e["end"])});
    if (greet && composite_greeting && fragments.empty())
      task = J(consistent);
    if (endpoint && !send)
      task = all({task, before(last, valid)});
    if (!first.is_null())
      detail = all({detail, before(e["hs_begin"], first)});
    timeline = all({timeline, detail});
    peer_task = all({peer_task, task});
    item["complete"] = detail;
    if (send)
      item["write_offer_pairs"] = all({pairs, present(last)});
    item["content_consistent"] = consistent;
  }
  auto point = [&](const char *msg, const char *key) -> J {
    auto &x = r["timeline"][msg];
    return x.is_object() ? x.at(key) : J(nullptr);
  };
  auto cad_write = point("CAD", "first_write_attempt"),
       cad_valid = point("CAD", "validated");
  auto greeting = point("SAD1", "final_write_accept"),
       response = point("SAD2", "first_write_attempt");
  J ordering = true;
  if (endpoint && client && s == "S2") {
    // Only the actual first-entry and explicit local callback return may
    // identify these operations. TLS can finish internally inside the read.
    const auto &begin = e["hs_begin"], &done = e["hs_complete"];
    J first_op = begin.is_null() ? J(nullptr) : begin.value("first_operation", J(nullptr));
    J confirmed = done.is_null() ? J(nullptr) : done.value("confirmed_by", J(nullptr));
    J confirmation = match(confirmed, "handshake_until_local_complete");
    if (confirmation == true)
      confirmation = before(point("SAD1", "validated"), done);
    ordering = all({match(first_op, "read_plain"),
                    before(begin, point("SAD1", "first_read_return")), confirmation});
    m["s2_read_first"] = ordering;
  }
  if (client && (s == "S1" || s == "S3" || s == "S4"))
    ordering = before(e["hs_complete"], cad_write);
  if (client && (s == "S3" || s == "S4"))
    ordering = all({ordering, before(point("CAD", "final_write_accept"),
                                     point("SAD2", "first_read_return"))});
  if (!client && (s == "S3" || s == "S4"))
    ordering = all({before(e["hs_complete"], response),
                    endpoint && e["auth_accepted"].is_null()
                        ? J(true)
                        : before(e["auth_accepted"], response),
                    before(cad_valid, response)});
  J early = nullptr;
  if (!client && (s == "S2" || s == "S4")) {
    early = before(greeting, e["hs_complete"]);
    if (endpoint) {
      // An ordinary write before a *later confirmation* alone need not have
      // used a pre-Finished send opportunity. Neither fact proves arrival.
      early = all({early, match(f["server_first"], true)});
      if (!composite_greeting)
        ordering = all({ordering, early});
      else if (!greeting.is_null())
        ordering = all({ordering, before(greeting, e["hs_complete"]),
                        f["server_first"] != false});
    } else {
      J proof = c.value("capability_proof", J(nullptr));
      require(proof.is_null() || proof.is_boolean(), "invalid_capability_proof");
      ordering = all({ordering, early, c.value("probe", false) ? J(true) : proof,
                      f["server_first"] != false});
    }
  }
  if (s == "S4") {
    auto v1 = point("SAD1", "validated"), v2 = point("SAD2", "validated");
    auto same = !v1.is_null() && !v2.is_null() && v1.at("seq") == v2.at("seq");
    if (client) {
      const auto read = point("SAD1", "first_read_return");
      if (endpoint)
        ordering = all({ordering, before(point("CAD", "final_write_accept"), read)});
      else {
        // Historical admission tested first write attempt, not acceptance.
        auto independent = before(cad_write, read);
        ordering = all({ordering, independent == true ? J(true) : J(nullptr)});
      }
    }
    const auto message_order = client ? (same ? J(true) : before(v1, v2))
                               : composite_greeting && greeting.is_null()
                                   ? J(true)
                                   : before(greeting, response);
    ordering = all({ordering, message_order});
  }
  m["authentication"] = auth;
  m["profile"] = profile;
  m["full_handshake_auth"] = all({core, auth, profile});
  m["ordinary_server_first"] = early;
  m["message_timeline"] = timeline;
  J prerequisites = m["full_handshake_auth"];
  if (endpoint) {
    // A successful local handshake is not independent security evidence.
    // Preserve known contradictions and explicitly requested negotiation IDs.
    m["requested_negotiation"] = ids_requested ? requested_ids : J(nullptr);
    prerequisites =
        all({core, auth != false, profile != false, requested_ids,
             f.value("endpoint_unsupported", J(nullptr)) != true});
  }
  m["peer_task"] = all({prerequisites, peer_task, ordering});
  m["task"] = all({m["peer_task"], timeline});
  J finish = e["hs_complete"];
  const char *unavailable = "boundary_unobserved";
  if (s == "S1")
    finish = client ? point("CAD", "final_write_accept") : cad_valid;
  if (s == "S2") {
    if (!endpoint)
      finish = client ? point("SAD1", "first_read_return") : greeting;
    else if (client) {
      finish = point("SAD1", "last_read_return");
      unavailable = "greeting_full_read_unobserved";
    } else {
      // An application return or a Finished callback cannot identify the
      // receive boundary of that protected TLS message on the transport.
      finish = nullptr;
      unavailable = "cf_transport_receive_unobserved";
    }
  }
  if (s == "S3" || s == "S4")
    finish = client ? point("SAD2", "first_read_return")
                    : point("SAD2", "final_write_accept");
  J start = e["hs_begin"], wall = nullptr;
  const auto delta = [&](const J &end) -> J {
    if (before(start, end) != true)
      return nullptr;
    return u(end, "ns") - u(start, "ns");
  };
  wall = delta(finish);
  r["timing"] = {{"begin", start},
                 {"end", finish},
                 {"wall_ns", wall},
                 {"pmu_delta", pmu(start, finish)}};
  if (endpoint && s == "S2")
    r["timing"][client ? "first_greeting_read_ns" : "greeting_write_accept_ns"] =
        delta(client ? point("SAD1", "first_read_return") : greeting);
  if (endpoint && s == "S2" && client && !finish.is_null())
    r["timing"]["end_label"] = "last_read_return";
  m["timing"] = wall.is_null() ? before(start, finish) : J(true);
  if (wall.is_null()) {
    if (start.is_null())
      unavailable = "start_unobserved";
    else if (!finish.is_null()) {
      unavailable = "invalid_interval";
      m["timing"] = false;
    }
    r["timing"]["unavailable_reason"] = unavailable;
  }
  r["timing"]["pmu_status"] =
      pmu_status(start, finish, r["timing"]["pmu_delta"]);
  m["pmu"] = r["timing"]["pmu_status"] == "available" ? J(true) : J(nullptr);
  r["lifecycle"] = e;
}
} // namespace
bool uses_endpoint_contract(const J &c) {
  if (!c.contains("scenario_contract"))
    return false;
  require(c.at("scenario_contract") == endpoint_contract_id,
          "unsupported_scenario_contract");
  return true;
}
J analyze_evidence(const std::string &data, const J &c) {
  J r = {{"status", "unknown"},          {"timing", {{"wall_ns", nullptr}}},
         {"timeline", J::object()},      {"events", J::array()},
         {"message_events", J::array()}, {"errors", J::array()},
         {"metrics", J::object()},       {"negotiated", J::object()},
         {"facts", J::object()}};
  for (auto key : {"task", "peer_task", "authentication", "profile",
                   "full_handshake_auth", "ordinary_server_first", "message_timeline",
                   "timing", "pmu", "transport_counts", "ciphertext_bytes", "record_layout",
                   "timed_records", "tls_flights"})
    r["metrics"][key] = nullptr;
  try {
    require(c.at("role") == "client" || c.at("role") == "server",
            "invalid_role");
    require(c.at("auth") == "mtls" || c.at("auth") == "server", "invalid_auth");
    require(c.at("run_id").is_string() &&
                !c.at("run_id").get<std::string>().empty() &&
                c.at("connection_id").is_string() &&
                !c.at("connection_id").get<std::string>().empty(),
            "empty_binding");
    require(data.size() <= 64 * 1024 * 1024, "source_size_limit");
    Trace t;
    uint64_t pid = 0, count = 0, version = 0;
    bool sealed = false;
    for (size_t off = 0; off < data.size();) {
      auto end = data.find('\n', off);
      require(end != std::string::npos && end - off < 3 * 1024 * 1024,
              "invalid_evidence_frame");
      auto ev = J::parse(std::string_view(data).substr(off, end - off));
      off = end + 1;
      const auto kind = ev.at("kind").get<std::string>();
      require(kind != "observer_loss",
              "observer_recording_incomplete");
      const auto v = u(ev, "v");
      require(v == 1 || v == buffered_evidence_version,
              "unsupported_observer_version");
      if (!version)
        version = v;
      require(v == version, "mixed_observer_versions");
      for (auto key : {"run_id", "connection_id", "role"})
        require(ev.at(key) == c.at(key), "wrong_evidence_binding");
      const auto origin = u(ev, "pid");
      require(origin > 0, "missing_event_origin");
      if (c.contains("pid"))
        require(ev.at("pid") == c.at("pid"), "wrong_measured_process");
      if (kind == "observer_complete") {
        require(version == buffered_evidence_version && ev.size() == 7 &&
                    count > 0 && u(ev, "count") == count && origin == pid,
                "invalid_observer_seal");
        require(off == data.size(), "trailing_observer_evidence");
        sealed = true;
        break;
      }
      require(u(ev, "seq") == ++count && count <= 100000, "invalid_sequence");
      require(u(ev, "ns") && u(ev, "tid"), "missing_event_origin");
      if (!pid)
        pid = origin;
      require(origin == pid, "process_changed");
      require(ev.at("pmu").is_null() || ev.at("pmu").is_object(),
              "invalid_pmu_snapshot");
      if (ev.at("kind") == "plain")
        t.plain(ev, c, r["message_events"]);
      else {
        require(ev.at("kind") != "event" || ev.at("message").is_null(),
                "labeled_raw_event");
        if (ev.at("kind") == "fact" &&
            ev.at("name") == "submission_greeting_accepted")
          t.composite_greeting(ev, c);
        t.add(ev);
      }
      r["events"].push_back(std::move(ev));
    }
    require(version != buffered_evidence_version || sealed,
            "observer_recording_incomplete");
    if (version)
      r["observer_stream"] = sealed ? "complete" : "legacy_unsealed";
    r["negotiated"] = t.identity.is_object() ? t.identity : J::object();
    r["facts"] = t.facts;
    bool peer_conflict = false;
    if (c.contains("peer_negotiated")) {
      const auto &peer = c.at("peer_negotiated");
      require(peer.is_object(), "invalid_peer_identity");
      for (auto key : {"version", "suite", "group"}) {
        const auto id = peer.value(key, J(nullptr));
        if (id.is_null())
          continue;
        require(u(peer, key) > 0 && u(peer, key) <= 65535, "invalid_peer_id");
        auto &local = r["negotiated"][key];
        if (!local.is_null() && local != id)
          peer_conflict = true;
        else if (local.is_null()) {
          local = id;
          r["negotiated_basis"][key] = "same_connection_peer";
        }
      }
    }
    t.identity = r.at("negotiated");
    evaluate_wire(c, r);
    if (!t.identity.is_object())
      t.identity = J::object();
    bool conflict = peer_conflict;
    for (const auto &[key, id] : r.at("wire").at("negotiated").items()) {
      if (t.identity.contains(key) && !t.identity[key].is_null() &&
          t.identity[key] != id)
        conflict = true;
      else {
        t.identity[key] = id;
        r["negotiated_basis"][key] = "observed_server_hello";
      }
    }
    if (r.contains("wire_hrr")) {
      if (t.facts.contains("hrr") && t.facts["hrr"].is_boolean() &&
          t.facts["hrr"] != r["wire_hrr"])
        conflict = true;
      if (r["wire_hrr"] == true || !t.facts.contains("hrr") ||
          t.facts["hrr"].is_null())
        t.facts["hrr"] = r["wire_hrr"];
    }
    evaluate(t, c, r);
    if (!t.write_errors.empty()) {
      for (const auto &error : t.write_errors)
        r["errors"].push_back(error);
      // Ciphertext and its layout are still observable; a contradicted native
      // return no longer corroborates this sender's application-tail length.
      r["wire"]["flights"].erase(c.at("role") == "client"
                                     ? "client_protected_flight"
                                     : "server_protected_flight");
      for (auto key : {"task", "peer_task", "message_timeline"})
        r["metrics"][key] = false;
    }
    if (conflict) {
      for (auto key : {"task", "peer_task", "profile", "full_handshake_auth"})
        r["metrics"][key] = false;
      r["errors"].push_back("contradictory_negotiated_evidence");
      r["wire"]["flights"] = J::object();
      r["wire"]["flight_exclusion"] = "contradictory_negotiated_evidence";
      r["metrics"]["tls_flights"] = false;
    }
    J result = all({r["metrics"]["task"], r["metrics"]["timing"]});
    r["status"] = result == true    ? "verified"
                  : result == false ? "contradicted"
                                    : "unknown";
  } catch (const std::exception &ex) {
    r["status"] = "invalid";
    r["errors"].push_back(ex.what());
    for (auto &[key, metric] : r["metrics"].items())
      metric = nullptr;
  }
  return r;
}
void qualify_flights(J &r, bool mutual, const J &peer_full_handshake_auth) {
  if (r.at("status") == "invalid")
    return;
  auto &metrics = r.at("metrics");
  auto &flights = r.at("wire").at("flights");
  auto confirmed = all({metrics.at("full_handshake_auth"), peer_full_handshake_auth});
  metrics["tls_flights"] = all({confirmed, metrics.at("record_layout"),
                                metrics.at("timed_records"),
                                flights.size() == 4 ? J(true) : J(nullptr)});
  if (confirmed != true)
    return;
  if (flights.contains("client_protected_flight"))
    flights["client_protected_flight"]["conceptual_members"] =
        mutual ? J{"CC", "CCV", "CF"} : J{"CF"};
  if (flights.contains("server_protected_flight"))
    flights["server_protected_flight"]["conceptual_members"] =
        mutual ? J{"EE", "CR", "SC", "SCV", "SF"} : J{"EE", "SC", "SCV", "SF"};
}
} // namespace turtle::native
