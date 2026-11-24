#include "native-packets-fixture.hpp"
#include "native/packets.hpp"
#include <iostream>
#include <unistd.h>

using namespace packet_fixture;
using turtle::artifact::Json;
namespace fs = std::filesystem;

namespace {
void check(bool ok, const char *why) {
  if (!ok)
    throw std::runtime_error(why);
}
std::string hex(const Bytes &b) {
  constexpr char d[] = "0123456789abcdef";
  std::string s;
  for (auto x : b) {
    s += d[x >> 4];
    s += d[x & 15];
  }
  return s;
}
Bytes record(size_t n, char body) {
  Bytes b{23, 3, 3};
  append(b, n, 2);
  b.resize(n + 5, body);
  return b;
}
} // namespace
int main() try {
  char name[] = "/tmp/turtle-native-packets.XXXXXX";
  check(mkdtemp(name) != nullptr, "mkdtemp");
  struct Cleanup {
    fs::path dir;
    ~Cleanup() {
      std::error_code ec;
      fs::remove_all(dir, ec);
    }
  } tmp{name};
  auto dir = tmp.dir;
  unsigned cp = 1234, sp = 4433, cb = 1001, sb = 3001;
  Json raw = {{"run_id", "r"},
              {"connection_id", "c"},
              {"pid", {{"client", 3}, {"server", 4}}},
              {"port", sp}};
  auto trial = raw;
  trial["v"] = 1;
  trial["mode"] = "netem";
  const char *cip = "192.0.2.2", *sip = "198.51.100.2";
  Json socket = {{"pid", 3},         {"inode", 17},      {"local_ip", cip},
                 {"local_port", cp}, {"remote_ip", sip}, {"remote_port", sp}};
  trial["connected"]["client"] = socket;
  socket.update(Json{{"pid", 4},
                     {"inode", 22},
                     {"local_ip", sip},
                     {"local_port", sp},
                     {"remote_ip", cip},
                     {"remote_port", cp}});
  trial["connected"]["server"] = socket;
  socket["inode"] = 20;
  trial["server_listener"] = socket;
  Json health = {{"ready_before_connect", true},
                 {"returncode", 0},
                 {"interface", "eth0"},
                 {"packets_written", 6},
                 {"timestamp_precision", "nanoseconds"},
                 {"availability", "available"},
                 {"kernel_dropped", 0},
                 {"interface_dropped", 0},
                 {"server_port", sp}};
  trial["capture"] = {{"client", health}, {"server", health}};
  const auto cf = record(20, 'c'), sf = record(20, 's'), sad = record(21, 'g');
  auto sw = sf;
  sw.insert(sw.end(), sad.begin(), sad.end());
  Json parts;
  for (auto role : {"client", "server"}) {
    bool client = role == std::string_view("client");
    auto &p = parts[role], &w = p["wire"];
    auto &stream = client ? cf : sw;
    p["status"] = "verified";
    p["metrics"] = {{"profile", true}, {"authentication", true}};
    p["message_events"] = Json::array();
    if (!client)
      p["message_events"].push_back(
          {{"message", "SAD1"}, {"name", "write_accepted"}, {"length", 4}});
    w["sender_extent"] = {{"run_id", "r"},          {"connection_id", "c"},
                          {"role", role},           {"end_seq", 20},
                          {"bytes", stream.size()}, {"hex", hex(stream)}};
    w["flights"]
     [client ? "client_protected_flight" : "server_protected_flight"] = {
         {"end", client ? cf.size() : sf.size()}, {"aead_tag_bytes", 16}};
  }
  auto packets = [&](unsigned ack) {
    return std::vector<Bytes>{
        packet(true, cb - 1, 2),
        packet(false, sb - 1, 18, {}, cb),
        packet(false, sb, 16, sw, cb),
        packet(true, cb, 16, cf, sb),
        packet(true, cb, 16, cf, ack),
        packet(true, cb + cf.size(), 16, {}, sb + sw.size())};
  };
  auto run = [&](const Json &t, const std::vector<Bytes> &pk, const Json &p) {
    turtle::artifact::save(dir / "trial.json", t);
    for (auto site : {"client", "server"}) {
      turtle::artifact::save(dir / (std::string(site) + ".capture.json"),
                             health);
      write_pcap(dir / (std::string(site) + ".pcap"), pk, false);
    }
    return turtle::native::analyze_packets(dir, raw, p);
  };
  auto pk = packets(sb + sw.size());
  auto yes = run(trial, pk, parts);
  check(yes["capture_verified"] == true && yes["tcp_ack"] == true &&
            yes["ack_witnesses"].size() == 2,
        "confirmed copy");
  check(yes["ack_witnesses"][0]["packet_id"] == 5 &&
            yes["ack_witnesses"][0]["direction"] == "client_to_server",
        "must be retransmitted copy");
  check(yes["locations"]["client"]["client_to_server"]
           ["retransmitted_payload_bytes"] == cf.size(),
        "retransmitted record mapping");
  check(turtle::native::analyze_packets(dir, raw, parts) == yes,
        "offline determinism");
  auto insufficient = run(trial, packets(sb + sw.size() - 1), parts);
  check(insufficient["capture_verified"] == true &&
            insufficient["tcp_ack"].is_null(),
        "partial/later pure ACK not proof");
  auto wrong = trial;
  wrong["connected"]["client"]["local_port"] = 4321;
  wrong["connected"]["server"]["remote_port"] = 4321;
  check(run(wrong, pk, parts)["capture_verified"] == false, "wrong flow");
  auto damaged = pk;
  damaged[4].back() ^= 1;
  check(run(trial, damaged, parts)["capture_verified"] == false,
        "conflicting duplicate payload");
  damaged = pk;
  damaged.erase(damaged.begin());
  check(run(trial, damaged, parts)["capture_verified"] == false,
        "missing opening SYN");
  auto missing = parts;
  missing["client"]["wire"].erase("sender_extent");
  auto present_only = run(trial, pk, missing);
  check(present_only["capture_verified"].is_null() &&
            present_only["capture_present"]["client"] == true,
        "missing actual sender extent");
  auto reverse_order = pk;
  reverse_order[2] = packet(true, cb, 16, cf, sb);
  reverse_order[3] = packet(false, sb, 16, sw, cb + cf.size());
  reverse_order[4] = packet(true, cb + cf.size(), 16, {}, sb + sw.size());
  auto reverse_witness = run(trial, reverse_order, parts);
  check(reverse_witness["tcp_ack"] == true &&
            reverse_witness["ack_witnesses"].size() == 2 &&
            reverse_witness["ack_witnesses"][0]["packet_id"] == 4 &&
            reverse_witness["ack_witnesses"][0]["direction"] ==
                "server_to_client",
        "client protected record precedes this greeting copy");
  wrong = trial;
  wrong["capture"]["server"]["kernel_dropped"] = 1;
  check(run(wrong, pk, parts)["capture_verified"] == false,
        "drops not admitted");
  std::cout << "native capture replay and copy-specific evidence passed\n";
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
