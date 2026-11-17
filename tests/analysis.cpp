#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include "profiling/profiling.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
using turtle::artifact::Bytes;
using turtle::artifact::integer;
using turtle::artifact::Json;
namespace {
void require(bool ok, const char *reason) {
  if (!ok)
    throw std::runtime_error(reason);
}
Bytes unhex(const std::string &s) {
  Bytes b;
  for (std::size_t i = 0; i < s.size(); i += 2)
    b.push_back(
        static_cast<unsigned char>(std::stoul(s.substr(i, 2), nullptr, 16)));
  return b;
}
void phases(const std::filesystem::path &fixtures) {
  auto source = turtle::artifact::load(fixtures / "phases.json");
  turtle::analysis::Endpoints eps;
  for (const auto &[role, e] : source.at("endpoints").items()) {
    turtle::analysis::Endpoint ep;
    ep.summary = e.at("summary");
    ep.events = e.at("events");
    ep.records = e.at("records");
    for (const auto &[d, s] : e.at("streams").items())
      ep.streams[d] = unhex(s);
    eps.emplace(role, std::move(ep));
  }
  auto actual = turtle::analysis::phases(
      eps, Json::object(), {{"availability", "not_collected"}}, true);
  if (actual != source.at("expected")) {
    std::cerr << Json::diff(source.at("expected"), actual).dump(2) << '\n';
    throw std::runtime_error("phase_reference_mismatch");
  }
  eps.at("client").summary["negotiated"]["profile"] = 0;
  auto missing = turtle::analysis::phases(
      eps, Json::object(), {{"availability", "not_collected"}}, true);
  require(missing.at("complete") == false && missing.at("roles").empty(),
          "undeclared_profile");
}
void append(Bytes &b, std::uint64_t n, unsigned count, bool little = false) {
  for (unsigned i = 0; i < count; ++i)
    b.push_back(
        static_cast<unsigned char>(n >> (8 * (little ? i : count - 1 - i))));
}
Bytes frame(unsigned n, const std::string &s) {
  Bytes b{'T', 'U'};
  append(b, n, 2);
  b.push_back(23);
  append(b, 0x303, 2);
  append(b, s.size(), 2);
  b.insert(b.end(), s.begin(), s.end());
  return b;
}
Bytes packet(bool forward, std::uint32_t seq, unsigned flags,
             const Bytes &body = {}) {
  Bytes b(12, 0);
  append(b, 0x0800, 2);
  b.push_back(0x45);
  b.push_back(0);
  append(b, 40 + body.size(), 2);
  append(b, 0, 4);
  b.push_back(64);
  b.push_back(6);
  append(b, 0, 2);
  std::array<unsigned char, 4> c{192, 0, 2, 2}, s{198, 51, 100, 2};
  auto src = forward ? c : s, dst = forward ? s : c;
  b.insert(b.end(), src.begin(), src.end());
  b.insert(b.end(), dst.begin(), dst.end());
  append(b, forward ? 1234 : 4433, 2);
  append(b, forward ? 4433 : 1234, 2);
  append(b, seq, 4);
  append(b, 0, 4);
  b.push_back(0x50);
  b.push_back(static_cast<unsigned char>(flags));
  append(b, 65535, 2);
  append(b, 0, 4);
  b.insert(b.end(), body.begin(), body.end());
  return b;
}
void capture(const std::filesystem::path &root) {
  auto wire = frame(1, "abcdefg"), second = frame(2, "123456789"),
       other = frame(1, "pong");
  wire.insert(wire.end(), second.begin(), second.end());
  auto part = [&](std::size_t a, std::size_t b) {
    return Bytes(wire.begin() + static_cast<std::ptrdiff_t>(a),
                 wire.begin() + static_cast<std::ptrdiff_t>(b));
  };
  std::uint32_t initial = 0xfffffff0;
  std::vector<Bytes> packets{
      packet(true, initial, 2),
      packet(false, 100, 18),
      packet(true, initial + 1, 16, part(0, 3)),
      packet(true, initial + 4, 16, part(3, 14)),
      packet(true, initial + 7, 16, part(6, 25)),
      packet(true, initial + 26, 16, part(25, wire.size())),
      packet(true, initial + 13, 16, part(12, 17)),
      packet(false, 101, 16, other)};
  for (bool little : {false, true}) {
    Bytes pcap;
    append(pcap, 0xa1b23c4d, 4, little);
    append(pcap, 2, 2, little);
    append(pcap, 4, 2, little);
    append(pcap, 0, 8, little);
    append(pcap, 65535, 4, little);
    append(pcap, 1, 4, little);
    unsigned i = 0;
    for (const auto &p : packets) {
      append(pcap, 2000000000, 4, little);
      append(pcap, 123456789 + i++, 4, little);
      append(pcap, p.size(), 4, little);
      append(pcap, p.size(), 4, little);
      pcap.insert(pcap.end(), p.begin(), p.end());
    }
    auto file = root / (little ? "little.pcap" : "big.pcap");
    turtle::artifact::write_text(file, std::string(pcap.begin(), pcap.end()));
    auto r = turtle::capture::analyze(
        file, {{"client_to_server", wire}, {"server_to_client", other}},
        {{"client_to_server", wire.size()}, {"server_to_client", other.size()}},
        "192.0.2.2", "198.51.100.2");
    const auto &out = r.at("client_to_server");
    require(out.at("availability") == "available", "pcap_coverage");
    require(out.at("retransmitted_payload_bytes") == 13,
            "partial_retransmission");
    require(out.at("unique_payload_bytes") == wire.size(), "union_bytes");
    require(out.at("packets")[0].at("timestamp_ns") == 2000000000123456789ULL,
            "pcap_timestamp_integer");
    require(r.at("server_to_client").at("retransmitted_payload_bytes") == 0,
            "zero_retransmission");
    require(out.at("packets")[3].at("records").back().at("record") == 2,
            "multiple_frames");
  }
  auto f = frame(1, "TU-inside-body");
  auto records = turtle::capture::records(f);
  require(records.size() == 1, "TU_in_payload");
  auto tls = Bytes(f.begin() + 4, f.end());
  turtle::capture::verify_tls(f, tls);
}
void perf() {
  Json a = {{"available", true},
            {"cycles", 1ULL << 60},
            {"instructions", 1ULL << 58},
            {"time_enabled_ns", 100},
            {"time_running_ns", 100}},
       b = a;
  b["cycles"] = integer(a.at("cycles")) + 1001;
  b["instructions"] = integer(a.at("instructions")) + 77;
  b["time_enabled_ns"] = 200;
  b["time_running_ns"] = 200;
  auto r = turtle::analysis::counter_delta(a, b, "available");
  require(r.at("cycles").at("value") == 1001, "counter_integer");
  b["time_running_ns"] = 199;
  r = turtle::analysis::counter_delta(a, b, "available");
  require(r.at("cycles").at("value").is_null() &&
              r.at("cycles_raw").at("value") == 1001,
          "counter_no_scaling");
  b["cycles"] = a.at("cycles");
  b["time_running_ns"] = 200;
  require(turtle::analysis::counter_delta(a, b, "available")
                  .at("cycles")
                  .at("value") == 0,
          "counter_zero");
  auto absent = turtle::analysis::counter_delta(
      {{"available", false}}, {{"available", false}}, "unsupported");
  require(absent.at("cycles").at("availability") == "unsupported",
          "counter_unavailable");
  auto parsed = turtle::profiling::parse_samples(
      "12/12 2000000000.123456789: 100 cycles:u: abc foo (/a)\n12/12 "
      "2000000000.123456790: 300 cycles:u: def bar (/a)\n");
  require(parsed.at("unparsed_or_lost").empty(), "sample_parser");
  auto samples = parsed.at("samples");
  require(samples[0].at("wall_ns") == 2000000000123456789ULL, "sample_integer");
  require(turtle::profiling::distribution(samples).at("functions")[0].at(
              "period_fraction") == .75,
          "period_weights");
  require(turtle::profiling::window(samples, integer(samples[0].at("wall_ns")),
                                    integer(samples[1].at("wall_ns")))
                  .at("sample_count") == 1,
          "half_open_window");
  require(!turtle::profiling::parse_samples("PERF_RECORD_LOST 3\n")
               .at("unparsed_or_lost")
               .empty(),
          "lost_samples");
}
} // namespace
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("fixtures output required");
    std::filesystem::create_directories(argv[2]);
    phases(argv[1]);
    capture(argv[2]);
    perf();
    std::cout
        << "Deterministic phase, pcap, counter and sample checks passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
