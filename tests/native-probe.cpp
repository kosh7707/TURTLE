// No fabricated benchmark: unit vectors for the positive evidence threshold.
#include "native/pre_cf.hpp"
#include <iostream>
using turtle::artifact::Json;
using namespace turtle::native;
namespace {
void ck(bool b) {
  if (!b)
    throw std::runtime_error("pre-CF prefix assertion");
}
Json base(const char *source) {
  return {{"status", "unknown"},
          {"events",
           Json::array({{{"kind", "coverage"},
                         {"source", source},
                         {"active", true},
                         {"seq", 1}},
                        {{"kind", "event"}, {"name", "ready"}, {"seq", 2}}})},
          {"message_events", Json::array()},
          {"lifecycle", Json::object()}};
}
Json io(unsigned seq, bool sent, std::string data) {
  return {{"kind", "io"},         {"source", "library_io"},
          {"sent", sent},         {"peek", false},
          {"seq", seq},           {"ns", seq * 10 + 1},
          {"begin_ns", seq * 10}, {"result", data.size() / 2},
          {"hex", data}};
}
} // namespace
int main() try {
  auto c = base("library_io"), s = base("library_io");
  const std::string head = "160303000102", sad = "1703030003abcdef";
  c["events"].push_back(io(3, false, head));
  c["lifecycle"]["probe_paused"] = {{"seq", 4}, {"ns", 41}};
  s["events"].push_back(io(3, true, head));
  s["events"].push_back(io(5, true, sad));
  s["message_events"] = {{{"name", "write_attempt"},
                          {"message", "SAD1"},
                          {"seq", 4},
                          {"offset", 0},
                          {"length", 3}},
                         {{"name", "write_accepted"},
                          {"message", "SAD1"},
                          {"seq", 6},
                          {"offset", 0},
                          {"length", 3}}};
  auto e = pre_cf_extent(c, s, 3, true);
  ck(e["client_consumed_bytes"] == 6 && e["server_terminal_bytes"] == 14 &&
     e["required_queue_bytes"] == 8);
  ck(pre_cf_arrived(e, 8) && !pre_cf_arrived(e, 7) && !pre_cf_arrived(e, 1));
  auto delivered = c;
  delivered["lifecycle"]["probe_resumed"] = {{"seq", 5}};
  delivered["events"].push_back(io(6, false, sad));
  delivered["timeline"]["SAD1"]["validated"] = {{"seq", 7}};
  ck(pre_cf_delivery(delivered, s, e, 8)["needed_from_queue"] == 8);
  ck(pre_cf_delivery(delivered, s, e, 7).is_null());
  auto no_wire = s;
  no_wire["events"] =
      Json::array({{{"kind", "event"}, {"name", "ready"}, {"seq", 2}}});
  auto rx = pre_cf_extent(c, no_wire, 3, false);
  ck(rx.is_object() && rx["server_source"].is_null());
  ck(pre_cf_delivery(delivered, no_wire, rx, 8)["needed_from_queue"] == 8);
  ck(pre_cf_delivery(delivered, no_wire, rx, 7).is_null());
  // Library writes can be buffered: only the frozen receiver's validated
  // greeting can prove delivery, never the submitted BIO byte count.
  auto buffered = pre_cf_extent(c, s, 3, false);
  ck(buffered == rx);
  ck(pre_cf_delivery(delivered, s, buffered, 8).is_object());
  ck(pre_cf_delivery(delivered, s, buffered, 1).is_null());
  auto not_received = delivered;
  not_received["timeline"]["SAD1"]["validated"] = nullptr;
  ck(pre_cf_delivery(not_received, s, buffered, 8).is_null());
  auto header_only = base("header");
  header_only["message_events"] = s["message_events"];
  auto header = Json{{"kind", "header"}, {"sent", true}, {"seq", 3},
                     {"offset", 0}, {"hex", head.substr(0, 10)}};
  header_only["events"].push_back(header);
  ck(pre_cf_extent(c, header_only, 3, false) == rx);
  auto wrong_header = header_only;
  wrong_header["events"].back()["hex"] = "1703030001";
  ck(pre_cf_extent(c, wrong_header, 3, false).is_null());
  auto socket = s;
  for (auto &event : socket["events"])
    if (event.contains("source"))
      event["source"] = "socket";
  auto socket_extent = pre_cf_extent(c, socket, 3, false);
  ck(socket_extent["server_source"] == "socket" &&
     socket_extent["required_queue_bytes"] == 8);
  auto both = socket;
  auto &events = both["events"];
  events.insert(events.begin(), s["events"][0]);
  events.push_back(io(7, true, head + sad));
  ck(pre_cf_extent(c, both, 3, true) == socket_extent);
  events.back()["hex"] = head + "1703030003abcdee";
  ck(pre_cf_extent(c, both, 3, true).is_null());
  socket["events"][2]["hex"] = nullptr;
  ck(pre_cf_extent(c, socket, 3, false).is_null());
  auto rebound = s;
  auto &ev = rebound["events"];
  // Pre-READY changes do not interrupt the tested interval.
  auto release = ev[0], rebind = ev[0];
  release["active"] = false;
  ev.insert(ev.begin() + 1, release);
  ev.insert(ev.begin() + 2, rebind);
  ck(pre_cf_extent(c, rebound, 3, true) == e);
  auto interrupted = s;
  interrupted["events"].push_back(release);
  ck(pre_cf_extent(c, interrupted, 3, true).is_null());
  ck(pre_cf_extent(c, interrupted, 3, false).is_null());
  auto incomplete = s;
  incomplete["events"][2]["hex"] = nullptr;
  ck(pre_cf_extent(c, incomplete, 3, false)
         .is_null()); // don't mask a supplied, defective source
  auto peek = c;
  peek["events"][2]["peek"] = true;
  ck(pre_cf_extent(peek, s, 3, true).is_null());
  auto conflict = c;
  conflict["events"][2]["hex"] = "160303000103";
  ck(pre_cf_extent(conflict, s, 3, true).is_null());
  auto extra = delivered;
  extra["events"][3]["hex"] = "1703030003abcdee";
  ck(pre_cf_delivery(extra, s, e, 8).is_null());
  ck(pre_cf_delivery(extra, s, buffered, 8).is_null());
  std::cout
      << "sender/receiver and receiver-only pre-CF exact thresholds verified\n";
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
