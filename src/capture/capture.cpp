#include "capture/capture.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <fstream>
#include <iostream>
#include <memory>
#ifndef TURTLE_NO_PCAP
#include <pcap/pcap.h>
#endif
#include <poll.h>
#include <set>
#include <stdexcept>
#include <unistd.h>
namespace turtle::capture {
using artifact::integer;
namespace {
std::uint16_t u16(const unsigned char *p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
#ifndef TURTLE_NO_PCAP
std::uint32_t u32(const unsigned char *p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}
using Handle = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
struct Packet {
  Json fields;
  Bytes payload;
};
std::vector<Packet> packets(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  std::array<unsigned char, 4> magic{};
  file.read(reinterpret_cast<char *>(magic.data()), 4);
  if (!file || magic == std::array<unsigned char, 4>{0x0a, 0x0d, 0x0d, 0x0a})
    throw std::runtime_error("classic_pcap_required");
  char err[PCAP_ERRBUF_SIZE]{};
  Handle handle(pcap_open_offline_with_tstamp_precision(
                    path.c_str(), PCAP_TSTAMP_PRECISION_NANO, err),
                pcap_close);
  if (!handle)
    throw std::runtime_error(err);
  if (pcap_datalink(handle.get()) != DLT_EN10MB)
    throw std::runtime_error("ethernet_capture_required");
  std::vector<Packet> result;
  pcap_pkthdr *h = nullptr;
  const unsigned char *data = nullptr;
  std::uint64_t id = 0;
  int rc = 0;
  while ((rc = pcap_next_ex(handle.get(), &h, &data)) >= 0) {
    if (rc == 0)
      continue;
    ++id;
    if (h->caplen < h->len)
      throw std::runtime_error("truncated_packet");
    if (h->caplen < 14)
      continue;
    std::size_t pos = 14;
    auto type = u16(data + 12);
    while (type == 0x8100 || type == 0x88a8) {
      if (pos + 4 > h->caplen)
        throw std::runtime_error("truncated_vlan");
      type = u16(data + pos + 2);
      pos += 4;
    }
    if (type != 0x0800)
      continue;
    if (pos + 20 > h->caplen)
      throw std::runtime_error("truncated_ipv4");
    auto ip = data + pos;
    if ((ip[0] >> 4) != 4 || ip[9] != 6)
      continue;
    auto ihl = static_cast<unsigned>((ip[0] & 15) * 4),
         total = static_cast<unsigned>(u16(ip + 2));
    if (u16(ip + 6) & 0x3fff)
      throw std::runtime_error("fragmented_ipv4_unsupported");
    if (ihl < 20 || total < ihl + 20 || pos + total > h->caplen)
      throw std::runtime_error("incomplete_tcp_packet");
    auto tcp = ip + ihl;
    auto thl = static_cast<unsigned>((tcp[12] >> 4) * 4);
    if (thl < 20 || thl > total - ihl)
      throw std::runtime_error("incomplete_tcp_header");
    char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, ip + 12, src, sizeof(src));
    inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));
    Json fields = {{"id", id},
                   {"timestamp_ns",
                    static_cast<std::uint64_t>(h->ts.tv_sec) * 1000000000ULL +
                        static_cast<std::uint64_t>(h->ts.tv_usec)},
                   {"src", src},
                   {"dst", dst},
                   {"sport", u16(tcp)},
                   {"dport", u16(tcp + 2)},
                   {"sequence", u32(tcp + 4)},
                   {"ack", u32(tcp + 8)},
                   {"flags", tcp[13]},
                   {"link_bytes", h->len},
                   {"ip_bytes", total}};
    Json sacks = Json::array();
    for (unsigned pos = 20; pos < thl;) {
      unsigned kind = tcp[pos++];
      if (kind == 0)
        break;
      if (kind == 1)
        continue;
      if (pos >= thl)
        throw std::runtime_error("invalid_tcp_option");
      unsigned len = tcp[pos++];
      if (len < 2 || len - 2 > thl - pos)
        throw std::runtime_error("invalid_tcp_option_length");
      if (kind == 5) {
        if (len < 10 || (len - 2) % 8)
          throw std::runtime_error("invalid_sack_length");
        for (unsigned i = 0; i < len - 2; i += 8)
          sacks.push_back({u32(tcp + pos + i), u32(tcp + pos + i + 4)});
      }
      pos += len - 2;
    }
    fields["sack_blocks"] = std::move(sacks);
    result.push_back({std::move(fields), Bytes(tcp + thl, ip + total)});
  }
  if (rc != -2)
    throw std::runtime_error(pcap_geterr(handle.get()));
  return result;
}
std::uint64_t length(const Ranges &ranges) {
  std::uint64_t n = 0;
  for (auto [a, b] : ranges)
    n += b - a;
  return n;
}
#endif
} // namespace
Ranges overlap(const Ranges &ranges, std::uint64_t a, std::uint64_t b) {
  Ranges r;
  for (auto [x, y] : ranges)
    if (x < b && y > a)
      r.emplace_back(std::max(x, a), std::min(y, b));
  return r;
}
void merge(Ranges &ranges, std::uint64_t a, std::uint64_t b) {
  if (b <= a)
    return;
  ranges.emplace_back(a, b);
  std::sort(ranges.begin(), ranges.end());
  Ranges r;
  for (auto p : ranges) {
    if (!r.empty() && p.first <= r.back().second)
      r.back().second = std::max(r.back().second, p.second);
    else
      r.push_back(p);
  }
  ranges = std::move(r);
}
Json records(std::span<const unsigned char> wire) {
  Json r = Json::array();
  std::uint64_t offset = 0, tls = 0;
  while (offset < wire.size()) {
    if (wire.size() - offset < 9 || wire[offset] != 'T' ||
        wire[offset + 1] != 'U')
      throw std::runtime_error("incomplete_frame");
    auto n = u16(wire.data() + offset + 2);
    if (n != r.size() + 1)
      throw std::runtime_error("record_number_mismatch");
    auto end = offset + 9 + u16(wire.data() + offset + 7);
    if (end > wire.size())
      throw std::runtime_error("incomplete_record");
    auto next = tls + end - offset - 4;
    r.push_back({{"number", n},
                 {"wire_begin", offset},
                 {"wire_end", end},
                 {"tls_begin", tls},
                 {"tls_end", next},
                 {"content_type", wire[offset + 4]},
                 {"legacy_version", u16(wire.data() + offset + 5)}});
    offset = end;
    tls = next;
  }
  return r;
}
Json raw_records(std::span<const unsigned char> wire) {
  Json rows = Json::array();
  for (std::size_t a = 0; a < wire.size();) {
    if (wire.size() - a < 5)
      throw std::runtime_error("truncated_tls_header");
    const auto body = u16(wire.data() + a + 3);
    if (wire[a] < 20 || wire[a] > 23 || wire[a + 1] != 3 ||
        body > (1u << 14) + 256 || wire.size() - a - 5 < body)
      throw std::runtime_error("invalid_tls_record");
    const auto b = a + 5 + body;
    rows.push_back({{"number", rows.size() + 1},
                    {"raw_tls", true},
                    {"content_type", wire[a]},
                    {"legacy_version", u16(wire.data() + a + 1)},
                    {"body_bytes", body},
                    {"wire_begin", a},
                    {"wire_end", b},
                    {"tls_begin", a},
                    {"tls_end", b}});
    a = b;
  }
  return rows;
}
void verify_tls(std::span<const unsigned char> wire,
                std::span<const unsigned char> tls) {
  auto r = records(wire);
  std::size_t offset = 0;
  for (const auto &x : r) {
    auto a = integer(x.at("wire_begin")) + 4, b = integer(x.at("wire_end"));
    if (offset + b - a > tls.size() ||
        !std::equal(wire.begin() + static_cast<std::ptrdiff_t>(a),
                    wire.begin() + static_cast<std::ptrdiff_t>(b),
                    tls.begin() + static_cast<std::ptrdiff_t>(offset)))
      throw std::runtime_error("deframed_stream_mismatch");
    offset += b - a;
  }
  if (offset != tls.size())
    throw std::runtime_error("deframed_stream_size_mismatch");
}
Json mapping(const Json &records, std::uint64_t begin, std::uint64_t end) {
  Json result = Json::array();
  auto it = std::upper_bound(records.begin(), records.end(), begin,
                             [](std::uint64_t n, const Json &r) {
                               return n < integer(r.at("wire_end"));
                             });
  for (; it != records.end() && integer(it->at("wire_begin")) < end; ++it) {
    const auto &r = *it;
    auto a = integer(r.at("wire_begin")), b = integer(r.at("wire_end"));
    auto prefix = r.value("raw_tls", false) ? 0u : 4u;
    std::array<Range, 3> parts{
        {{a, a + prefix}, {a + prefix, a + prefix + 5}, {a + prefix + 5, b}}};
    std::array<const char *, 3> names{
        {"frame_header", "tls_header", "tls_payload"}};
    for (std::size_t i = 0; i < 3; ++i) {
      auto lo = std::max(parts[i].first, begin),
           hi = std::min(parts[i].second, end);
      if (lo < hi)
        result.push_back(
            {{"record", r.at("number")},
             {"part", names[i]},
             {"wire_begin", lo},
             {"wire_end", hi},
             {"tls_begin",
              i ? Json(integer(r.at("tls_begin")) + lo - a - prefix)
                : Json(nullptr)},
             {"tls_end", i ? Json(integer(r.at("tls_begin")) + hi - a - prefix)
                           : Json(nullptr)}});
    }
  }
  return result;
}
Json analyze(const std::filesystem::path &path,
             const std::map<std::string, Bytes> &streams,
             const std::map<std::string, std::uint64_t> &required,
             const std::string &client, const std::string &server,
             bool raw_tls) {
#ifdef TURTLE_NO_PCAP
  (void)path;
  (void)streams;
  (void)required;
  (void)client;
  (void)server;
  (void)raw_tls;
  throw std::runtime_error("pcap_not_built");
#else
  auto parse_records = raw_tls ? raw_records : records;
  auto input = packets(path);
  std::set<std::pair<unsigned, unsigned>> flows;
  for (const auto &p : input) {
    const auto &f = p.fields;
    auto flags = integer(f.at("flags"));
    if (f.at("src") == client && f.at("dst") == server && (flags & 2) &&
        !(flags & 16))
      flows.emplace(f.at("sport").get<unsigned>(),
                    f.at("dport").get<unsigned>());
  }
  if (flows.size() != 1)
    throw std::runtime_error("capture_requires_one_connection_and_initial_syn");
  auto [cp, sp] = *flows.begin();
  Json result = Json::object();
  for (auto direction : {"client_to_server", "server_to_client"}) {
    bool forward = std::string(direction) == "client_to_server";
    std::vector<const Packet *> selected;
    for (const auto &p : input) {
      const auto &f = p.fields;
      if (f.at("src") == (forward ? client : server) &&
          f.at("dst") == (forward ? server : client) &&
          f.at("sport") == (forward ? cp : sp) &&
          f.at("dport") == (forward ? sp : cp))
        selected.push_back(&p);
    }
    auto syn =
        std::find_if(selected.begin(), selected.end(), [](const Packet *p) {
          return integer(p->fields.at("flags")) & 2;
        });
    if (syn == selected.end())
      throw std::runtime_error("missing_syn_for_direction");
    auto initial = (*syn)->fields.at("sequence").get<std::uint32_t>(),
         base = initial + 1;
    const auto &expected = streams.at(direction);
    auto need = required.at(direction);
    if (need > expected.size())
      throw std::runtime_error("required_stream_too_short");
    Json frame_list;
    try {
      frame_list = parse_records(expected);
    } catch (const std::exception &) {
      frame_list = parse_records(std::span(expected).first(need));
    }
    Ranges seen;
    std::uint64_t repeated = 0, payload_bytes = 0, links = 0, ips = 0;
    bool matches = true, full = true;
    Json rows = Json::array();
    for (const auto *p : selected) {
      Json row = p->fields;
      const auto &bytes = p->payload;
      std::uint64_t a = static_cast<std::uint32_t>(
                        integer(row.at("sequence")) +
                        ((integer(row.at("flags")) & 2) ? 1 : 0) - base),
                    b = a + bytes.size();
      row["wire_begin"] = bytes.empty() ? Json(nullptr) : Json(a);
      row["wire_end"] = bytes.empty() ? Json(nullptr) : Json(b);
      row["payload_bytes"] = bytes.size();
      row["records"] = Json::array();
      row["retransmitted_ranges"] = Json::array();
      links += integer(row.at("link_bytes"));
      ips += integer(row.at("ip_bytes"));
      if (!bytes.empty()) {
        auto dup = overlap(seen, a, b);
        row["retransmitted_ranges"] = dup;
        row["retransmitted_record_ranges"] = Json::array();
        for (const auto &[lo, hi] : dup)
          for (const auto &part : mapping(frame_list, lo, hi))
            row["retransmitted_record_ranges"].push_back(part);
        repeated += length(dup);
        merge(seen, a, b);
        payload_bytes += bytes.size();
        full = full && b <= expected.size() &&
               std::equal(bytes.begin(), bytes.end(),
                          expected.begin() +
                              static_cast<std::ptrdiff_t>(
                                  std::min<std::uint64_t>(a, expected.size())));
        auto stop = std::min(b, need);
        if (a < stop)
          matches =
              matches &&
              std::equal(bytes.begin(),
                         bytes.begin() + static_cast<std::ptrdiff_t>(stop - a),
                         expected.begin() + static_cast<std::ptrdiff_t>(a));
        row["records"] = mapping(frame_list, a, b);
      }
      rows.push_back(std::move(row));
    }
    bool complete = need == 0 || (!seen.empty() && seen.front().first == 0 &&
                                  seen.front().second >= need);
    result[direction] = {
        {"availability", complete && matches ? "available" : "missing"},
        {"reason", complete && matches
                       ? Json(nullptr)
                       : Json("stream_coverage_or_bytes_mismatch")},
        {"initial_sequence", initial},
        {"required_stream_bytes", need},
        {"unique_payload_bytes", length(seen)},
        {"payload_bytes", payload_bytes},
        {"retransmitted_payload_bytes", repeated},
        {"link_bytes", links},
        {"ip_bytes", ips},
        {"packet_count", selected.size()},
        {"stream_matches", matches},
        {"coverage_complete", complete},
        {"full_stream_matches", full},
        {"full_coverage_complete",
         seen == (expected.empty() ? Ranges{} : Ranges{{0, expected.size()}})},
        {"packets", rows}};
  }
  // ACK claims are about the named packet copy, not its original transmission,
  // peer TLS processing, or application reads. A short ACK is inconclusive.
  for (auto direction : {"client_to_server", "server_to_client"}) {
    auto opposite = std::string(direction) == "client_to_server"
                        ? "server_to_client"
                        : "client_to_server";
    auto &out = result.at(direction);
    const auto &peer = result.at(opposite);
    auto base = peer.at("initial_sequence").get<std::uint32_t>() + 1u;
    auto need = required.at(opposite);
    const auto rs = parse_records(std::span(streams.at(opposite)).first(need));
    for (auto &pkt : out.at("packets")) {
      pkt["opposite_records_cumulatively_acked"] = Json::array();
      pkt["sack_stream_ranges"] = Json::array();
      if (!(integer(pkt.at("flags")) & 16))
        continue;
      auto ack = pkt.at("ack").get<std::uint32_t>() - base;
      // Reject ambiguous wrap/coordinates beyond observed payload (+FIN).
      if (ack > streams.at(opposite).size() + 1 || ack >= 0x80000000u)
        continue;
      pkt["ack_stream_offset"] = ack;
      for (const auto &block : pkt.at("sack_blocks")) {
        auto lo = block[0].get<std::uint32_t>() - base,
             hi = block[1].get<std::uint32_t>() - base;
        if (lo < hi && hi <= streams.at(opposite).size())
          pkt["sack_stream_ranges"].push_back({lo, hi});
      }
      if (out.at("availability") != "available" ||
          peer.at("availability") != "available" ||
          !integer(pkt.at("payload_bytes")))
        continue;
      for (const auto &r : rs)
        if (integer(r.at("wire_end")) <= ack)
          pkt["opposite_records_cumulatively_acked"].push_back(r.at("number"));
    }
  }
  return result;
#endif
}
Json probe(const std::string &interface) {
#ifdef TURTLE_NO_PCAP
  (void)interface;
  return {{"availability", "unsupported"}, {"reason", "pcap_not_built"}};
#else
  char err[PCAP_ERRBUF_SIZE]{};
  Handle h(pcap_create(interface.c_str(), err), pcap_close);
  if (!h)
    return {{"availability", "unsupported"}, {"reason", err}};
  if (pcap_set_snaplen(h.get(), 262144) ||
      pcap_set_immediate_mode(h.get(), 1) ||
      pcap_set_tstamp_precision(h.get(), PCAP_TSTAMP_PRECISION_NANO) ||
      pcap_activate(h.get()) < 0)
    return {{"availability", "unsupported"}, {"reason", pcap_geterr(h.get())}};
  if (pcap_datalink(h.get()) != DLT_EN10MB ||
      pcap_get_selectable_fd(h.get()) < 0)
    return {{"availability", "unsupported"},
            {"reason", "capture_interface_unsupported"}};
  return {{"availability", "available"}, {"reason", nullptr}};
#endif
}
int collect(const std::string &interface, const std::filesystem::path &output,
            const std::filesystem::path &status, unsigned server_port) {
#ifdef TURTLE_NO_PCAP
  (void)interface;
  (void)output;
  (void)server_port;
  artifact::save(
      status, {{"availability", "unsupported"}, {"reason", "pcap_not_built"}});
  return 1;
#else
  Json state = {{"availability", "missing"},
                {"kernel_dropped", nullptr},
                {"reason", nullptr},
                {"library", pcap_lib_version()}};
  try {
    char err[PCAP_ERRBUF_SIZE]{};
    Handle h(pcap_create(interface.c_str(), err), pcap_close);
    if (!h)
      throw std::runtime_error(err);
    if (pcap_set_snaplen(h.get(), 262144) ||
        pcap_set_buffer_size(h.get(), 8 * 1024 * 1024) ||
        pcap_set_timeout(h.get(), 50) || pcap_set_immediate_mode(h.get(), 1) ||
        pcap_set_tstamp_precision(h.get(), PCAP_TSTAMP_PRECISION_NANO))
      throw std::runtime_error("pcap_configuration_failed");
    if (pcap_activate(h.get()) < 0)
      throw std::runtime_error(pcap_geterr(h.get()));
    if (pcap_datalink(h.get()) != DLT_EN10MB)
      throw std::runtime_error("ethernet_capture_required");
    bpf_program filter{};
    if (server_port > 65535)
      throw std::runtime_error("invalid_capture_port");
    auto expression =
        server_port ? "tcp port " + std::to_string(server_port) : "tcp";
    if (pcap_compile(h.get(), &filter, expression.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) < 0)
      throw std::runtime_error(pcap_geterr(h.get()));
    int code = pcap_setfilter(h.get(), &filter);
    pcap_freecode(&filter);
    if (code < 0)
      throw std::runtime_error(pcap_geterr(h.get()));
    std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)> dump(
        pcap_dump_open(h.get(), output.c_str()), pcap_dump_close);
    if (!dump)
      throw std::runtime_error(pcap_geterr(h.get()));
    if (pcap_setnonblock(h.get(), 1, err) < 0)
      throw std::runtime_error(err);
    int fd = pcap_get_selectable_fd(h.get());
    if (fd < 0)
      throw std::runtime_error("pcap_selectable_fd_unavailable");
    std::cout << "READY\n" << std::flush;
    bool stopping = false;
    int quiet = 0;
    std::uint64_t count = 0;
    while (!stopping || quiet < 4) {
      std::array<pollfd, 2> f{
          {{fd, POLLIN, 0}, {stopping ? -1 : STDIN_FILENO, POLLIN, 0}}};
      if (::poll(f.data(), f.size(), 50) < 0) {
        if (errno == EINTR)
          continue;
        throw std::runtime_error("capture_poll_failed");
      }
      if (f[1].revents) {
        char b[64];
        auto n = ::read(STDIN_FILENO, b, sizeof(b));
        (void)n;
        stopping = true;
      }
      pcap_pkthdr *header = nullptr;
      const unsigned char *bytes = nullptr;
      int n = 0, batch = 0;
      while ((n = pcap_next_ex(h.get(), &header, &bytes)) == 1) {
        pcap_dump(reinterpret_cast<unsigned char *>(dump.get()), header, bytes);
        ++count;
        ++batch;
      }
      if (n < 0)
        throw std::runtime_error(pcap_geterr(h.get()));
      quiet = batch ? 0 : quiet + 1;
    }
    if (pcap_dump_flush(dump.get()))
      throw std::runtime_error("pcap_flush_failed");
    pcap_stat stats{};
    if (pcap_stats(h.get(), &stats))
      throw std::runtime_error("pcap_statistics_missing");
    state.update(
        {{"packets_written", count},
         {"received", stats.ps_recv},
         {"kernel_dropped", stats.ps_drop},
         {"interface_dropped", stats.ps_ifdrop},
         {"timestamp_precision", "nanoseconds"},
         {"availability",
          stats.ps_drop == 0 && stats.ps_ifdrop == 0 ? "available" : "missing"},
         {"reason", stats.ps_drop == 0 && stats.ps_ifdrop == 0
                        ? Json(nullptr)
                        : Json("capture_drops")}});
  } catch (const std::exception &e) {
    state["reason"] = e.what();
  }
  artifact::save(status, state);
  return state.at("availability") == "available" ? 0 : 1;
#endif
}
} // namespace turtle::capture
