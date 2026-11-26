#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include <algorithm>
#include <set>
#include <stdexcept>
namespace turtle::analysis {
using artifact::integer;
using artifact::interval;
using artifact::measurement;
namespace {
bool includes(const Json &a, const Json &v) {
  return std::find(a.begin(), a.end(), v) != a.end();
}
std::uint64_t sum(const Json &rows, const std::string &field) {
  std::uint64_t n = 0;
  for (const auto &r : rows)
    n += integer(r.at(field));
  return n;
}
Json classify(const Endpoints &endpoints) {
  Json groups = Json::object();
  for (auto n : phase_names)
    groups[n] = Json::array();
  groups["compatibility_ccs"] = Json::array();
  for (auto role : {"client", "server"}) {
    const auto &ep = endpoints.at(role);
    const auto &neg = ep.summary.at("negotiated");
    if (neg.at("profile") != 1)
      throw std::runtime_error("server_auth_1rtt_profile_not_declared");
    if (neg.at("version") != 0x304 || neg.at("resumed") != false)
      throw std::runtime_error("phase_profile_requires_full_tls13");
    const auto &call = handshake(ep);
    auto selected = select(ep.records.at("send"), [&](const Json &r) {
      return includes(r.at("call_ids"), call.at("id"));
    });
    Json plain = Json::array(), encrypted = Json::array();
    const auto &wire = ep.streams.at("send");
    Bytes hello;
    for (const auto &r : selected) {
      if (r.at("call_ids") != Json::array({call.at("id")}))
        throw std::runtime_error("record_crosses_handshake_call_boundary");
      auto kind = integer(r.at("content_type"));
      auto a = integer(r.at("wire_begin")) + 9, b = integer(r.at("wire_end"));
      if (kind == 22) {
        plain.push_back(r);
        hello.insert(hello.end(), wire.begin() + static_cast<std::ptrdiff_t>(a),
                     wire.begin() + static_cast<std::ptrdiff_t>(b));
      } else if (kind == 23)
        encrypted.push_back(r);
      else if (kind == 20) {
        if (b - a != 1 || wire.at(a) != 1)
          throw std::runtime_error("unsupported_compatibility_ccs");
        groups["compatibility_ccs"].push_back(r);
      } else
        throw std::runtime_error("phase_profile_record_sequence_incomplete");
    }
    if (plain.empty() || encrypted.empty() ||
        integer(plain.back().at("wire_end")) >
            integer(encrypted.front().at("wire_begin")))
      throw std::runtime_error("phase_profile_record_order");
    bool client = std::string(role) == "client";
    if (hello.size() < 4 || hello[0] != (client ? 1 : 2) ||
        ((static_cast<std::size_t>(hello[1]) << 16) |
         (static_cast<std::size_t>(hello[2]) << 8) | hello[3]) !=
            hello.size() - 4)
      throw std::runtime_error("profile_requires_one_complete_hello");
    if (!client && is_hello_retry(hello))
      throw std::runtime_error("hello_retry_request_outside_phase_profile");
    groups[client ? "client_hello" : "server_hello"] = plain;
    groups[client ? "client_finished" : "server_auth"] = encrypted;
  }
  return groups;
}
std::pair<Json, Json> network_metrics(const Json &records, const Json &captures,
                                      const Json &network) {
  auto direction = records.front().at("key").at("direction").get<std::string>();
  std::string sender = direction == "client_to_server" ? "client" : "server";
  capture::Ranges ranges;
  for (const auto &r : records)
    ranges.emplace_back(integer(r.at("wire_begin")), integer(r.at("wire_end")));
  auto observation =
      captures.value(sender, Json::object()).value(direction, Json::object());
  bool healthy = network.value("capture", Json::object())
                         .value(sender, Json::object())
                         .value("availability", "") == "available" &&
                 observation.value("availability", "") == "available";
  Json metrics = Json::object(), links = Json::array();
  for (auto name : {"tcp_payload_bytes", "retransmitted_bytes"})
    metrics[name] = measurement(
        nullptr,
        network.value("availability", "") == "not_collected" ? "not_collected"
                                                             : "missing",
        "sender_capture_unavailable");
  if (healthy) {
    std::uint64_t payload = 0, repeated = 0;
    for (const auto &p : observation.at("packets"))
      if (integer(p.at("payload_bytes"))) {
        for (auto [a, b] : capture::overlap(ranges, integer(p.at("wire_begin")),
                                            integer(p.at("wire_end"))))
          payload += b - a;
        for (const auto &r : p.at("retransmitted_ranges"))
          for (auto [a, b] :
               capture::overlap(ranges, integer(r.at(0)), integer(r.at(1))))
            repeated += b - a;
      }
    metrics["tcp_payload_bytes"] = measurement(payload);
    metrics["retransmitted_bytes"] = measurement(repeated);
  }
  for (auto role : {"client", "server"})
    for (const auto &p : captures.value(role, Json::object())
                             .value(direction, Json::object())
                             .value("packets", Json::array()))
      if (integer(p.at("payload_bytes"))) {
        auto r = capture::overlap(ranges, integer(p.at("wire_begin")),
                                  integer(p.at("wire_end")));
        if (!r.empty())
          links.push_back({{"capture_role", role},
                           {"packet_id", p.at("id")},
                           {"wire_ranges", capture::range_rows(r)}});
      }
  return {metrics,
          {{"source_role", sender},
           {"direction", direction},
           {"packet_links", links}}};
}
Json role_phases(const std::string &role, const Endpoint &ep,
                 const Json &groups, const Json &captures,
                 const Json &network) {
  const auto &call = handshake(ep);
  auto events = select(ep.events, [&](const Json &e) {
    return e.at("call_id") == call.at("id") && e.at("kind") != "call";
  });
  auto transports =
      select(events, [](const Json &e) { return e.at("kind") == "transport"; });
  auto sockets =
      select(events, [](const Json &e) { return e.at("kind") == "socket"; });
  for (const auto &[name, records] : groups.items())
    for (const auto &r : records) {
      auto direction = r.at("key").at("direction") == flow(role, "send")
                           ? "send"
                           : "receive";
      auto other = select(ep.records.at(direction), [&](const Json &x) {
        return x.at("number") == r.at("number");
      });
      if (other.size() != 1 ||
          other[0].at("wire_begin") != r.at("wire_begin") ||
          other[0].at("wire_end") != r.at("wire_end") ||
          other[0].at("call_ids") != Json::array({call.at("id")}))
        throw std::runtime_error("peer_phase_record_or_call_mismatch");
    }
  auto classes = [&](const Json &e, bool point) {
    std::set<std::string> names;
    auto direction = flow(role, e.at("direction").get<std::string>());
    auto a = integer(e.at("wire_begin")), b = integer(e.at("wire_end"));
    for (const auto &[name, rs] : groups.items())
      for (const auto &r : rs)
        if (r.at("key").at("direction") == direction) {
          auto x = integer(r.at("wire_begin")), y = integer(r.at("wire_end"));
          if ((x < b && y > a) || (point && a == b && x <= a && a < y))
            names.insert(name);
        }
    return Json::array(Json::Array(names.begin(), names.end()));
  };
  std::map<std::uint64_t, Json> refs;
  Json event_links = Json::array(), shared = Json::array();
  for (const auto &e : events) {
    auto related = classes(e, e.at("kind") == "socket");
    std::string basis = "byte_overlap";
    if (related.empty() && e.at("kind") == "frame") {
      related = classes(ep.events.at(integer(e.at("parent")) - 1), false);
      basis = "enclosing_transport";
    }
    Json ref = {
        {"event_id", e.at("id")}, {"phases", related}, {"basis", basis}};
    refs[integer(e.at("id"))] = ref;
    event_links.push_back(ref);
    if (related.size() > 1)
      shared.push_back(e.at("id"));
  }
  Json order = Json::array();
  for (const auto &e : sockets)
    if (e.at("transferred").get<std::int64_t>() > 0) {
      const auto &tags = refs.at(integer(e.at("id"))).at("phases");
      if (tags.size() != 1)
        throw std::runtime_error("socket_crosses_or_lacks_phase_boundary");
      if (tags[0] != "compatibility_ccs" &&
          (order.empty() || order.back() != tags[0]))
        order.push_back(tags[0]);
    }
  if (order != Json::array(Json::Array(phase_names.begin(), phase_names.end())))
    throw std::runtime_error("phase_local_io_order_incomplete");
  Json rows = Json::array(), begin = call.at("begin"),
       begin_ref = {{"event_id", call.at("id")}, {"edge", "begin"}};
  for (std::size_t i = 0; i < phase_names.size(); ++i) {
    auto name = phase_names[i];
    const auto &rs = groups.at(name);
    auto assigned = select(sockets, [&](const Json &e) {
      return includes(refs.at(integer(e.at("id"))).at("phases"), name);
    });
    auto progress = select(assigned, [](const Json &e) {
      return e.at("transferred").get<std::int64_t>() > 0;
    });
    if (progress.empty())
      throw std::runtime_error("phase_progress_missing");
    auto end = i == 3 ? call.at("end") : progress.back().at("end");
    Json end_ref = {
        {"event_id", i == 3 ? call.at("id") : progress.back().at("id")},
        {"edge", "end"}};
    auto section = interval(begin, end),
         span =
             interval(progress.front().at("begin"), progress.back().at("end"));
    auto frames = select(events, [&](const Json &e) {
      return e.at("kind") == "frame" &&
             refs.at(integer(e.at("id"))).at("phases") == Json::array({name});
    });
    Json m = Json::object();
    for (auto k : clocks) {
      auto a = integer(begin.at(k)), b = integer(end.at(k));
      if (a > integer(span.at("begin").at(k)) ||
          integer(span.at("end").at(k)) > b)
        throw std::runtime_error("phase_socket_outside_interval");
      std::uint64_t clipped = 0, total = 0, frame_cost = 0;
      for (const auto &e : sockets) {
        auto x = std::max(a, integer(e.at("begin").at(k))),
             y = std::min(b, integer(e.at("end").at(k)));
        if (y > x)
          clipped += y - x;
      }
      for (const auto &e : assigned)
        total += integer(e.at("duration").at(k));
      for (const auto &e : frames)
        frame_cost += integer(e.at("duration").at(k));
      m[std::string("interval_") + k] =
          measurement(section.at("duration").at(k));
      m[std::string("interval_socket_") + k] = measurement(clipped);
      m[std::string("io_span_") + k] = measurement(span.at("duration").at(k));
      m[std::string("socket_") + k] = measurement(total);
      m[std::string("exclusive_frame_") + k] = measurement(frame_cost);
    }
    auto tls = sum(rs, "tls_end") - sum(rs, "tls_begin"),
         wire = sum(rs, "wire_end") - sum(rs, "wire_begin");
    m.update({{"tls_bytes", measurement(tls)},
              {"wire_bytes", measurement(wire)},
              {"frame_bytes", measurement(wire - tls)},
              {"record_count", measurement(rs.size())}});
    auto [nm, nl] = network_metrics(rs, captures, network);
    m.update(nm);
    Json keys = Json::array(), ranges = Json::array(),
         socket_ids = Json::array(), transport_ids = Json::array(),
         frame_ids = Json::array();
    for (const auto &r : rs) {
      keys.push_back(r.at("key"));
      ranges.push_back({r.at("wire_begin"), r.at("wire_end")});
    }
    for (const auto &e : assigned)
      socket_ids.push_back(e.at("id"));
    for (const auto &e : transports)
      if (includes(refs.at(integer(e.at("id"))).at("phases"), name))
        transport_ids.push_back(e.at("id"));
    for (const auto &e : frames)
      frame_ids.push_back(e.at("id"));
    rows.push_back({{"phase", name},
                    {"label", phase_labels[i]},
                    {"direction", role == senders[i] ? "send" : "receive"},
                    {"classification_basis",
                     i < 2 ? "plaintext_handshake_header"
                           : "declared_profile_and_handshake_call"},
                    {"interval", section},
                    {"io_span", span},
                    {"metrics", m},
                    {"interval_event_boundaries",
                     {{"begin", begin_ref}, {"end", end_ref}}},
                    {"internal_generation_or_verification",
                     measurement(nullptr, "unsupported",
                                 "internal_boundaries_not_observed")},
                    {"record_keys", keys},
                    {"wire_ranges", ranges},
                    {"socket_event_ids", socket_ids},
                    {"transport_event_ids", transport_ids},
                    {"exclusive_frame_event_ids", frame_ids},
                    {"network", nl}});
    begin = end;
    begin_ref = end_ref;
  }
  Json gaps = Json::array();
  begin = call.at("begin");
  Json preceding = nullptr;
  for (std::size_t i = 0; i <= transports.size(); ++i) {
    Json following = i < transports.size() ? transports[i] : Json(nullptr);
    auto end = following.is_null() ? call.at("end") : following.at("begin");
    auto before = preceding.is_null()
                      ? Json::array()
                      : refs.at(integer(preceding.at("id"))).at("phases"),
         after = following.is_null()
                     ? Json::array()
                     : refs.at(integer(following.at("id"))).at("phases");
    unsigned count = 0;
    for (auto name : phase_names)
      if (includes(after, name))
        ++count;
    auto gap = interval(begin, end);
    gap.update({{"id", gaps.size() + 1},
                {"preceding_transport_id",
                 preceding.is_null() ? Json(nullptr) : preceding.at("id")},
                {"following_transport_id",
                 following.is_null() ? Json(nullptr) : following.at("id")},
                {"preceding_phases", before},
                {"following_phases", after},
                {"before_shared_send",
                 !following.is_null() && following.at("direction") == "send" &&
                     count > 1}});
    gaps.push_back(gap);
    if (!following.is_null()) {
      begin = following.at("end");
      preceding = following;
    }
  }
  Json accounting = Json::object();
  for (auto k : clocks) {
    std::uint64_t outside = 0, transport = 0, parts = 0, shared_gap = 0,
                  socket = 0, clip = 0;
    for (const auto &g : gaps) {
      outside += integer(g.at("duration").at(k));
      if (g.at("before_shared_send") == true)
        shared_gap += integer(g.at("duration").at(k));
    }
    for (const auto &e : transports)
      transport += integer(e.at("duration").at(k));
    for (const auto &r : rows) {
      parts += integer(r.at("interval").at("duration").at(k));
      clip += integer(
          r.at("metrics").at(std::string("interval_socket_") + k).at("value"));
    }
    for (const auto &e : sockets)
      socket += integer(e.at("duration").at(k));
    auto total = integer(call.at("duration").at(k));
    if (total != parts || total != outside + transport || socket != clip)
      throw std::runtime_error("handshake_time_partition_mismatch");
    Json a = {{"handshake", total},
              {"phase_interval_sum", parts},
              {"transport_sum", transport},
              {"outside_transport_sum", outside},
              {"before_shared_send_gap_sum", shared_gap}};
    std::uint64_t all = 0, primary = 0, ccs = 0, shared_cost = 0, unlinked = 0;
    for (const auto &e : events)
      if (e.at("kind") == "frame") {
        auto n = integer(e.at("duration").at(k));
        all += n;
        auto tags = refs.at(integer(e.at("id"))).at("phases");
        if (tags.empty())
          unlinked += n;
        else if (tags.size() > 1)
          shared_cost += n;
        else if (tags[0] == "compatibility_ccs")
          ccs += n;
        else
          primary += n;
      }
    a.update({{"frame_events_sum", all},
              {"frame_exclusive_primary_sum", primary},
              {"frame_exclusive_ccs_sum", ccs},
              {"frame_shared_sum", shared_cost},
              {"frame_unlinked_sum", unlinked}});
    accounting[k] = a;
  }
  Json auxiliary = Json::array();
  for (auto direction : {"send", "receive"}) {
    auto rs = select(groups.at("compatibility_ccs"), [&](const Json &r) {
      return r.at("key").at("direction") == flow(role, direction);
    });
    if (!rs.empty()) {
      auto [m, n] = network_metrics(rs, captures, network);
      Json keys = Json::array();
      for (const auto &r : rs)
        keys.push_back(r.at("key"));
      auxiliary.push_back(
          {{"kind", "compatibility_ccs"},
           {"direction", direction},
           {"record_keys", keys},
           {"tls_bytes", sum(rs, "tls_end") - sum(rs, "tls_begin")},
           {"wire_bytes", sum(rs, "wire_end") - sum(rs, "wire_begin")},
           {"network_metrics", m},
           {"network", n}});
    }
  }
  return {{"rows", rows},
          {"accounting", accounting},
          {"outside_transport_intervals", gaps},
          {"event_links", event_links},
          {"auxiliary", auxiliary},
          {"shared_event_ids", shared}};
}
} // namespace
Json phases(Endpoints &eps, const Json &captures, const Json &network,
            bool success) {
  Json result = {{"complete", false},
                 {"invalid_reasons", Json::array()},
                 {"roles", Json::object()},
                 {"profile", "server_auth_1rtt"},
                 {"encrypted_content_inspected", false},
                 {"interval_basis", "handshake_entry_then_local_last_socket_"
                                    "returns_then_handshake_completion"}};
  try {
    if (!success || eps.size() != 2)
      throw std::runtime_error("successful_endpoint_pair_required");
    auto groups = classify(eps);
    for (auto role : {"client", "server"})
      result["roles"][role] =
          role_phases(role, eps.at(role), groups, captures, network);
    result["complete"] = true;
  } catch (const std::exception &e) {
    result["roles"] = Json::object();
    result["invalid_reasons"].push_back(e.what());
  }
  for (auto &[role, ep] : eps)
    ep.phases = result.at("roles").value(role, Json::object());
  return result;
}
} // namespace turtle::analysis
