#include "native/packets.hpp"
#include "capture/capture.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <stdexcept>

namespace turtle::native {
namespace {
using artifact::Bytes;
using artifact::integer;
using artifact::Json;
namespace fs = std::filesystem;
constexpr auto forward = "client_to_server", reverse = "server_to_client";

void check(bool ok, const char *message) {
  if (!ok)
    throw std::invalid_argument(message);
}
void file(const fs::path &p, std::uintmax_t limit) {
  check(fs::is_regular_file(fs::symlink_status(p)) && fs::file_size(p) <= limit,
        "invalid_capture_file");
}
Bytes extent(const Json &extent, const Json &raw, const std::string &role) {
  check(extent.at("run_id") == raw.at("run_id") &&
            extent.at("connection_id") == raw.at("connection_id") &&
            extent.at("role") == role && integer(extent.at("end_seq")) > 0,
        "wrong_sender_extent");
  const auto &s = extent.at("hex").get_ref<const std::string &>();
  const auto n = integer(extent.at("bytes"));
  check(n && n <= 8 * 1024 * 1024 && s.size() == n * 2,
        "invalid_sender_extent");
  Bytes out(n);
  for (size_t i = 0; i != n; ++i) {
    const char *p = s.data() + 2 * i;
    auto [end, error] = std::from_chars(p, p + 2, out[i], 16);
    check(error == std::errc{} && end == p + 2, "invalid_sender_extent_hex");
  }
  return out;
}

uint64_t prefix_seen_at(const Json &packets, uint64_t end) {
  // Check that this capture actually saw the acked prefix prior to this copy.
  capture::Ranges seen;
  for (const auto &p : packets) {
    if (integer(p.at("payload_bytes")))
      capture::merge(seen, integer(p.at("wire_begin")),
                     integer(p.at("wire_end")));
    if (!seen.empty() && seen.front().first == 0 && seen.front().second >= end)
      return integer(p.at("id"));
  }
  return 0;
}

void witnesses(Json &out, const Json &location, const char *site,
               const char *flow, uint64_t ingroup, uint64_t ack_end,
               const char *claim) {
  const auto &opposite =
      location.at(flow == std::string_view(forward) ? reverse : forward);
  const auto seen = prefix_seen_at(opposite.at("packets"), ack_end);
  if (!seen)
    return;
  for (const auto &p : location.at(flow).at("packets")) {
    if (!integer(p.at("payload_bytes")) || !p.contains("ack_stream_offset") ||
        integer(p.at("ack_stream_offset")) < ack_end ||
        integer(p.at("wire_begin")) > ingroup ||
        integer(p.at("wire_end")) <= ingroup || integer(p.at("id")) <= seen)
      continue;
    out.push_back({{"location", site},
                   {"packet_id", p.at("id")},
                   {"direction", flow},
                   {"timestamp_ns", p.at("timestamp_ns")},
                   {"sequence", p.at("sequence")},
                   {"ack", p.at("ack")},
                   {"contains_wire_offset", ingroup},
                   {"ack_stream_offset", p.at("ack_stream_offset")},
                   {"peer_required_prefix_end", ack_end},
                   {"claim", claim}});
  }
}

// Only derive the greeting's record range when the sender has already proven
// its unpadded application-only tail for *this* connection.
void presend(Json &out, const Json &location, const char *site,
             const Json &parts, const std::map<std::string, Bytes> &streams) {
  for (auto role : {"client", "server"})
    if (parts.at(role).at("metrics").value("profile", Json(nullptr)) != true ||
        parts.at(role).at("metrics").value("authentication", Json(nullptr)) !=
            true)
      return;
  const auto &client = parts.at("client").at("wire").at("flights");
  const auto &server = parts.at("server").at("wire").at("flights");
  if (!client.contains("client_protected_flight") ||
      !server.contains("server_protected_flight"))
    return;
  uint64_t greeting = 0;
  for (const auto &e : parts.at("server").at("message_events"))
    if (e.at("message") == "SAD1" && e.at("name") == "write_accepted")
      greeting += integer(e.at("length"));
  if (!greeting)
    return;
  const auto &cf = client.at("client_protected_flight"),
             &sf = server.at("server_protected_flight");
  const auto cr = capture::raw_records(streams.at(forward)),
             sr = capture::raw_records(streams.at(reverse));
  auto last_cf = std::find_if(cr.begin(), cr.end(), [&](const auto &x) {
    return x.at("wire_end") == cf.at("end");
  });
  auto first_sad = std::find_if(sr.begin(), sr.end(), [&](const auto &x) {
    return x.at("wire_begin") == sf.at("end");
  });
  if (last_cf == cr.end() || first_sad == sr.end())
    return;
  auto overhead = integer(sf.at("aead_tag_bytes")) + 1;
  for (auto r = first_sad; r != sr.end(); ++r) {
    auto length = integer(r->at("body_bytes"));
    if (r->at("content_type") != 23 || length <= overhead)
      return;
    if (length - overhead >= greeting) {
      witnesses(out, location, site, forward,
                integer(last_cf->at("wire_begin")), integer(r->at("wire_end")),
                "complete_greeting_record_received_before_this_client_finished_"
                "record_copy");
      witnesses(
          out, location, site, reverse, integer(first_sad->at("wire_begin")),
          integer(last_cf->at("wire_end")),
          "client_finished_record_received_before_this_greeting_record_copy");
      return;
    }
    greeting -= length - overhead;
  }
}
void tuple(const Json &trial, const Json &raw) {
  const auto &l = trial.at("server_listener"),
             &c = trial.at("connected").at("client"),
             &s = trial.at("connected").at("server");
  for (auto role : {"client", "server"}) {
    const auto &fd = trial.at("connected").at(role);
    check(fd.at("pid") == raw.at("pid").at(role) && integer(fd.at("pid")) > 0 &&
              integer(fd.at("inode")) > 0 && integer(fd.at("local_port")) > 0 &&
              integer(fd.at("local_port")) <= 65535,
          "socket_identity_mismatch");
  }
  check(l.at("pid") == s.at("pid") && integer(l.at("inode")) > 0 &&
            l.at("local_port") == raw.at("port") &&
            s.at("local_port") == raw.at("port") &&
            (l.at("local_ip") == s.at("local_ip") ||
             l.at("local_ip") == "0.0.0.0") &&
            c.at("local_ip") == s.at("remote_ip") &&
            c.at("remote_ip") == s.at("local_ip") &&
            c.at("local_port") == s.at("remote_port") &&
            c.at("remote_port") == s.at("local_port"),
        "capture_socket_tuple_mismatch");
}
std::array<uint32_t, 2> verify_flow(const Json &flows, const Json &c,
                                    const Json &s) {
  std::array<uint32_t, 2> isn{};
  size_t i = 0;
  for (auto dir : {forward, reverse}) {
    const bool client = (i == 0);
    auto &local = client ? c : s, &remote = client ? s : c;
    const auto &f = flows.at(dir);
    check(f.at("availability") == "available" &&
              f.at("coverage_complete") == true &&
              f.at("stream_matches") == true,
          "captured_tls_prefix_mismatch");
    const auto &pkts = f.at("packets");
    check(!pkts.empty(), "missing_captured_flow");
    const auto &syn = pkts.at(0);
    check(syn.at("src") == local.at("local_ip") &&
              syn.at("sport") == local.at("local_port") &&
              syn.at("dst") == remote.at("local_ip") &&
              syn.at("dport") == remote.at("local_port"),
          "capture_flow_tuple_mismatch");
    isn[i] = f.at("initial_sequence").get<uint32_t>();
    auto mask = client ? 2u : 18u;
    check((integer(syn.at("flags")) & 0x17u) == mask, "missing_opening_syn");
    for (const auto &p : pkts)
      if (integer(p.at("flags")) & 2u) {
        check(p.at("sequence") == isn[i] &&
                  (integer(p.at("flags")) & 0x17u) == mask &&
                  !integer(p.at("payload_bytes")) &&
                  (client || p.at("ack") == uint32_t(isn[0] + 1)),
              "ambiguous_syn_epoch");
      }
    ++i;
  }
  return isn;
}
} // namespace
Json analyze_packets(const fs::path &dir, const Json &raw,
                     const Json &participants) {
  Json out = {{"capture_verified", nullptr},
              {"capture_present", {{"client", false}, {"server", false}}},
              {"tcp_ack", nullptr},
              {"reason", nullptr},
              {"locations", Json::object()},
              {"ack_witnesses", Json::array()},
              {"ack_scope", "cumulative_TCP_receipt_before_named_packet_copy_"
                            "not_TLS_or_application"}};
  try {
    if (!fs::is_directory(fs::symlink_status(dir))) {
      out["reason"] = "capture_not_collected";
      return out;
    }
    for (auto site : {"client", "server"})
      out["capture_present"][site] = fs::is_regular_file(
          fs::symlink_status(dir / (std::string(site) + ".pcap")));
    file(dir / "trial.json", 1024 * 1024);
    auto t = artifact::load(dir / "trial.json");
    const bool loopback = t.at("mode") == "loopback";
    check(loopback || t.at("mode") == "netem", "unknown_capture_topology");
    out["capture_vantage"] = loopback
                                 ? "two_collectors_on_same_loopback_interface"
                                 : "separate_endpoint_network_namespaces";
    check(t.at("v") == 1 && t.at("run_id") == raw.at("run_id") &&
              t.at("connection_id") == raw.at("connection_id"),
          "capture_trial_identity_mismatch");
    if (!t.contains("connected") || !t.at("connected").is_object() ||
        !t.at("connected").value("client", Json(nullptr)).is_object() ||
        !t.at("connected").value("server", Json(nullptr)).is_object()) {
      out["reason"] = "socket_tuple_unobserved";
      return out;
    }
    check(t.at("pid") == raw.at("pid"), "capture_process_mismatch");
    tuple(t, raw);
    std::map<std::string, Bytes> streams;
    std::map<std::string, uint64_t> required;
    for (auto role : {"client", "server"}) {
      const auto &p = participants.at(role);
      if (p.at("status") == "invalid" ||
          !p.at("wire").contains("sender_extent")) {
        out["reason"] = "sender_extent_unavailable";
        return out;
      }
      auto direction = role == std::string_view("client") ? forward : reverse;
      auto bytes = extent(p.at("wire").at("sender_extent"), raw, role);
      required[direction] = bytes.size();
      streams.emplace(direction, std::move(bytes));
    }
    const auto &c = t.at("connected").at("client"),
               &s = t.at("connected").at("server");
    std::array<uint32_t, 2> first{};
    for (auto site : {"client", "server"}) {
      const auto &h = t.at("capture").at(site);
      if (h.value("availability", "") != "available") {
        out["reason"] = "capture_unavailable_or_dropped";
        return out;
      }
      check(h.at("ready_before_connect") == true &&
                h.at("kernel_dropped") == 0 && h.at("interface_dropped") == 0 &&
                h.at("server_port") == raw.at("port") &&
                h.at("returncode") == 0 &&
                h.at("interface") == (loopback ? "lo" : "eth0"),
            "capture_health_mismatch");
      auto status = dir / (std::string(site) + ".capture.json");
      file(status, 1024 * 1024);
      const auto report = artifact::load(status);
      for (auto field : {"availability", "kernel_dropped", "interface_dropped",
                         "packets_written", "timestamp_precision"})
        check(h.at(field) == report.at(field), "capture_status_mismatch");
      check(report.at("timestamp_precision") == "nanoseconds",
            "capture_precision_mismatch");
      auto path = dir / (std::string(site) + ".pcap");
      file(path, 16 * 1024 * 1024);
      auto loc = capture::analyze(path, streams, required, c.at("local_ip"),
                                  s.at("local_ip"), true);
      auto isn = verify_flow(loc, c, s);
      check(integer(h.at("packets_written")) >=
                integer(loc.at(forward).at("packet_count")) +
                    integer(loc.at(reverse).at("packet_count")),
            "capture_packet_count_mismatch");
      if (site == std::string_view("client"))
        first = isn;
      else
        check(first == isn, "capture_sequence_epoch_mismatch");
      out["locations"][site] = std::move(loc);
    }
    out["capture_verified"] = true;
    for (auto site : {"client", "server"})
      presend(out["ack_witnesses"], out["locations"][site], site, participants,
              streams);
    if (!out["ack_witnesses"].empty())
      out["tcp_ack"] = true;
  } catch (const std::exception &e) {
    out["capture_verified"] = false;
    out["tcp_ack"] = nullptr;
    out["ack_witnesses"] = Json::array();
    out["reason"] = e.what();
  }
  return out;
}
} // namespace turtle::native
