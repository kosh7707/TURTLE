#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include <set>
#include <sstream>
#include <stdexcept>
namespace turtle::analysis {
using artifact::integer;
using artifact::measurement;
std::string flow(const std::string &role, const std::string &direction) {
  return (role == "client") == (direction == "send") ? "client_to_server"
                                                     : "server_to_client";
}
const Json &handshake(const Endpoint &ep) {
  for (const auto &e : ep.events)
    if (e.at("kind") == "call" && e.at("operation") == "handshake" &&
        e.at("success") == true)
      return e;
  throw std::runtime_error("successful_handshake_call_missing");
}
Endpoint endpoint(const std::filesystem::path &root) {
  Endpoint ep;
  ep.summary = artifact::load(root / "endpoint.json");
  auto &s = ep.summary;
  if (s.at("schema") != "turtle.endpoint.v3")
    throw std::runtime_error("unsupported_endpoint_schema");
  ep.events = Json::array();
  std::istringstream lines(artifact::read_text(root / "events.jsonl"));
  std::string line;
  while (std::getline(lines, line)) {
    auto e = Json::parse(line);
    if (e.at("id") != ep.events.size() + 1)
      throw std::runtime_error("event_ids_missing");
    ep.events.push_back(std::move(e));
  }
  for (const auto &e : ep.events) {
    if (e.at("schema") != "turtle.event.v2" ||
        e.at("run_id") != s.at("run_id") || e.at("role") != s.at("role") ||
        e.at("connection_id") != s.at("connection_id"))
      throw std::runtime_error("event_identity_mismatch");
    for (auto k : clocks) {
      if (e.at("begin").at(k).is_null() || e.at("end").at(k).is_null())
        continue;
      auto a = integer(e.at("begin").at(k)), b = integer(e.at("end").at(k));
      if (b < a || integer(e.at("duration").at(k)) != b - a)
        throw std::runtime_error("event_clock_mismatch");
      auto parent = integer(e.at("parent"));
      if (parent) {
        const auto &p = ep.events.at(parent - 1);
        if (integer(p.at("begin").at(k)) > a || integer(p.at("end").at(k)) < b)
          throw std::runtime_error("event_parent_interval_mismatch");
      }
    }
  }
  ep.records = Json::object();
  ep.metrics = Json::object();
  ep.links = Json::array();
  for (auto direction : {"send", "receive"}) {
    auto wire = artifact::read_bytes(
             root / (std::string("wire_") + direction + ".bin")),
         tls = artifact::read_bytes(root /
                                    (std::string("tls_") + direction + ".bin"));
    if (s.at("streams").at(std::string("wire_") + direction).at("bytes") !=
            wire.size() ||
        s.at("streams").at(std::string("tls_") + direction).at("bytes") !=
            tls.size())
      throw std::runtime_error("stream_size_mismatch");
    std::span<const unsigned char> w(wire), t(tls);
    try {
      capture::verify_tls(w, t);
    } catch (const std::exception &) {
      if (s.at("status") != "ok")
        throw;
      auto wn = integer(s.at("scenario")
                            .at(std::string("wire_") + direction + "_bytes")),
           tn = integer(
               s.at("scenario").at(std::string("tls_") + direction + "_bytes"));
      if (wn > w.size() || tn > t.size())
        throw std::runtime_error("scenario_stream_size_mismatch");
      w = w.first(wn);
      t = t.first(tn);
      capture::verify_tls(w, t);
    }
    auto rs = capture::records(w);
    for (auto &r : rs) {
      r["key"] = {{"run", s.at("run_id")},
                  {"connection", s.at("connection_id")},
                  {"direction", flow(s.at("role"), direction)},
                  {"record", r.at("number")}};
      r["event_ids"] = Json::array();
      std::set<std::uint64_t> calls;
      for (const auto &e : ep.events)
        if (e.at("kind") != "call" && e.at("direction") == direction &&
            integer(e.at("wire_begin")) < integer(r.at("wire_end")) &&
            integer(e.at("wire_end")) > integer(r.at("wire_begin"))) {
          r["event_ids"].push_back(e.at("id"));
          calls.insert(integer(e.at("call_id")));
        }
      r["call_ids"] = calls;
    }
    ep.records[direction] = std::move(rs);
    ep.streams[direction] = std::move(wire);
  }
  for (auto clock : clocks) {
    for (auto op : {"prepare", "handshake"}) {
      Json n = nullptr;
      for (const auto &e : ep.events)
        if (e.at("kind") == "call" && e.at("operation") == op &&
            e.at("success") == true) {
          n = e.at("duration").at(clock);
          break;
        }
      ep.metrics[std::string(op) + "_" + clock] =
          measurement(n, n.is_null() ? "missing" : "available");
    }
    auto n = s.at("scenario").at("duration").at(clock),
         a = ep.metrics.at(std::string("prepare_") + clock).at("value");
    ep.metrics[std::string("scenario_") + clock] = measurement(
        n, !n.is_null() && s.at("scenario").at("complete") == true ? "available"
                                                                   : "missing");
    ep.metrics[std::string("first_use_") + clock] =
        measurement(a.is_null() || n.is_null() ? Json(nullptr)
                                               : Json(integer(a) + integer(n)),
                    a.is_null() || n.is_null() ? "missing" : "available");
    for (auto kind : {"frame", "socket"}) {
      std::uint64_t total = 0;
      bool available = true;
      for (const auto &e : ep.events)
        if (e.at("kind") == kind &&
            ep.events.at(integer(e.at("call_id")) - 1).at("operation") !=
                "shutdown") {
          auto v = e.at("duration").at(clock);
          if (v.is_null())
            available = false;
          else
            total += integer(v);
        }
      ep.metrics[std::string(kind) + "_" + clock] =
          measurement(available ? Json(total) : Json(nullptr),
                      available ? "available" : "missing");
    }
  }
  for (auto layer : {"tls", "wire"})
    for (auto direction : {"send", "receive"}) {
      auto name = std::string(layer) + "_" + direction + "_bytes";
      ep.metrics[name] = measurement(s.at("scenario").at(name));
    }
  for (auto name : {"retransmitted_send_bytes", "tcp_send_payload_bytes",
                    "captured_send_link_bytes"})
    ep.metrics[name] = measurement(nullptr, "not_collected");
  for (const auto &e : ep.events) {
    if (e.at("kind") == "call")
      continue;
    Json keys = Json::array();
    bool shared = false;
    auto related = [&](const Json &id) {
      Json out = Json::array();
      for (const auto &r : ep.records.at(e.at("direction").get<std::string>()))
        if (std::find(r.at("event_ids").begin(), r.at("event_ids").end(), id) !=
            r.at("event_ids").end())
          out.push_back(r.at("key"));
      return out;
    };
    keys = related(e.at("id"));
    if (keys.empty() && e.at("kind") == "frame") {
      keys = related(e.at("parent"));
      shared = true;
    }
    ep.links.push_back(
        {{"event_id", e.at("id")},
         {"record_keys", keys},
         {"basis", shared ? "enclosing_transport" : "byte_overlap"}});
  }
  return ep;
}
} // namespace turtle::analysis
