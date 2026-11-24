#include "analysis/analysis.hpp"
#include <set>
#include <stdexcept>
namespace turtle::analysis {
using artifact::integer;
using artifact::measurement;
namespace {
constexpr std::array<const char *, 6> fields{
    "cycles",           "instructions",    "cycles_raw",
    "instructions_raw", "time_enabled_ns", "time_running_ns"};
Json add(const Json &rows) {
  Json result = Json::object();
  for (auto field : fields) {
    std::uint64_t total = 0;
    Json missing = nullptr;
    for (const auto &row : rows) {
      const auto &m = row.at(field);
      if (m.at("availability") != "available")
        missing = m;
      else
        total += integer(m.at("value"));
    }
    result[field] = missing.is_null() ? measurement(total) : missing;
  }
  return result;
}
} // namespace
Json counter_delta(const Json &begin, const Json &end,
                   const std::string &availability, Json reason) {
  Json r = Json::object();
  if (!begin.value("available", false) || !end.value("available", false)) {
    for (auto f : fields)
      r[f] = measurement(
          nullptr,
          availability == "unsupported" || availability == "not_collected"
              ? availability
              : "missing",
          reason.is_null() ? Json("counter_snapshot_unavailable") : reason);
    return r;
  }
  Json deltas = Json::object();
  for (auto f :
       {"cycles", "instructions", "time_enabled_ns", "time_running_ns"}) {
    auto a = integer(begin.at(f)), b = integer(end.at(f));
    if (b < a)
      throw std::runtime_error("counter_value_reversed");
    deltas[f] = b - a;
  }
  auto enabled = integer(deltas.at("time_enabled_ns")),
       running = integer(deltas.at("time_running_ns"));
  if (running > enabled)
    throw std::runtime_error("counter_running_exceeds_enabled");
  bool complete = running > 0 && running == enabled;
  for (auto f : {"time_enabled_ns", "time_running_ns"})
    r[f] = measurement(deltas.at(f));
  for (auto f : {"cycles", "instructions"}) {
    r[std::string(f) + "_raw"] =
        running ? measurement(deltas.at(f))
                : measurement(nullptr, "missing", "counter_zero_running_time");
    r[f] = measurement(complete ? deltas.at(f) : Json(nullptr),
                       complete ? "available" : "missing",
                       complete ? Json(nullptr)
                                : Json("counter_not_continuously_scheduled"));
  }
  return r;
}
Json counters(const std::filesystem::path &root, const Endpoint &ep) {
  bool requested = ep.summary.at("collection").value("perf_counters", false);
  Json result = {{"requested", requested},
                 {"availability", "not_collected"},
                 {"reason", nullptr},
                 {"complete", false},
                 {"operations", Json::object()},
                 {"phases", Json::object()},
                 {"events", Json::array()},
                 {"outside_transport", Json::array()}};
  if (!requested)
    return result;
  try {
    if (ep.summary.at("collection").at("counters_file") != "counters.json")
      throw std::runtime_error("counters_file_not_declared");
    auto source = artifact::load(root / "counters.json");
    const bool strict = ep.summary.at("collection").value("role_contract", "") == "pull.v1";
    if (source.at("schema") != (strict ? "turtle.counters.v2" : "turtle.counters.v1") ||
        source.at("requested") != true)
      throw std::runtime_error("counter_contract_mismatch");
    for (auto k : {"run_id", "role", "pid", "tid"})
      if (source.at(k) != ep.summary.at(k))
        throw std::runtime_error("counter_identity_mismatch");
    result.update({{"availability", source.at("availability")},
                   {"reason", source.at("reason")},
                   {"errno", source.at("errno")}});
    std::string availability = source.at("availability");
    Json reason = source.at("reason");
    if (strict && (source.at("collector") != "linux_perf_event_open_group" ||
                   source.at("inherit") != false || source.at("exclude_kernel") != true ||
                   source.at("exclude_hv") != true || source.at("scaled") != false))
      throw std::runtime_error("counter_scope_mismatch");
    if (strict && availability == "available" && source.at("owner_tid") != source.at("tid"))
      throw std::runtime_error("counter_owner_thread_mismatch");
    const auto &snapshots = source.at("events");
    if (snapshots.size() != ep.events.size())
      throw std::runtime_error("counter_event_ids_mismatch");
    std::map<std::uint64_t, Json> metrics;
    std::set<std::pair<std::uint64_t, std::uint64_t>> reads;
    auto check_read = [&](const Json &p) {
      if (p.at("available") == true) {
        if (strict && (p.at("tid") != source.at("owner_tid") || integer(p.at("tid")) == 0))
          throw std::runtime_error("counter_thread_mismatch");
        auto a = integer(p.at("read_begin_ns")),
             b = integer(p.at("read_end_ns"));
        if (integer(p.at("wall_ns")) > a || a > b)
          throw std::runtime_error("counter_read_clock_mismatch");
        reads.emplace(a, b);
      }
    };
    for (std::size_t i = 0; i < ep.events.size(); ++i) {
      const auto &e = ep.events[i];
      const auto &pair = snapshots[i];
      if (pair.at("id") != e.at("id"))
        throw std::runtime_error("counter_event_ids_mismatch");
      for (auto edge : {"begin", "end"}) {
        for (auto k : clocks)
          if (pair.at(edge).at(k) != e.at(edge).at(k))
            throw std::runtime_error("counter_event_clock_mismatch");
        check_read(pair.at(edge));
      }
      auto m =
          counter_delta(pair.at("begin"), pair.at("end"), availability, reason);
      metrics[integer(e.at("id"))] = m;
      result["events"].push_back({{"event_id", e.at("id")}, {"metrics", m}});
      if (e.at("kind") == "call" && e.at("success") == true &&
          (e.at("operation") == "prepare" || e.at("operation") == "handshake"))
        result["operations"][e.at("operation").get<std::string>()] = m;
    }
    const auto &scenario = source.at("scenario");
    for (auto edge : {"begin", "end"}) {
      for (auto k : clocks)
        if (scenario.at(edge).at(k) != ep.summary.at("scenario").at(edge).at(k))
          throw std::runtime_error("counter_scenario_clock_mismatch");
      check_read(scenario.at(edge));
      if (strict && ep.summary.at("scenario").at(std::string(edge) + "_event").is_number()) {
        auto id = integer(ep.summary.at("scenario").at(std::string(edge) + "_event"));
        if (scenario.at(edge) != snapshots.at(id - 1).at(edge))
          throw std::runtime_error("counter_scenario_boundary_mismatch");
      }
    }
    result["operations"]["scenario"] = counter_delta(
        scenario.at("begin"), scenario.at("end"), availability, reason);
    if (result["operations"].contains("prepare"))
      result["operations"]["first_use"] = add(Json::array(
          {result["operations"]["prepare"], result["operations"]["scenario"]}));
    if (ep.summary.at("schema") == "turtle.endpoint.v4") {
      const Json *first = nullptr, *last = nullptr;
      for (const auto &event : ep.events) {
        if (event.at("kind") != "call")
          continue;
        if (!first && (event.at("operation") == "handshake" ||
                       event.at("operation") == "server_first"))
          first = &event;
        if (event.at("operation") == "handshake" && event.at("success") == true)
          last = &event;
      }
      if (first && last)
        result["operations"]["handshake"] = counter_delta(
            snapshots.at(integer(first->at("id")) - 1).at("begin"),
            snapshots.at(integer(last->at("id")) - 1).at("end"), availability,
            reason);
      result["complete"] = result.at("operations")
                               .at("scenario")
                               .at("cycles")
                               .at("availability") == "available";
      if (strict && !result.at("complete").get<bool>() && reason.is_null())
        result["reason"] = result.at("operations").at("scenario").at("cycles_raw").at("reason").is_null()
            ? result.at("operations").at("scenario").at("cycles").at("reason")
            : result.at("operations").at("scenario").at("cycles_raw").at("reason");
      return result;
    }
    for (const auto &phase : ep.phases.value("rows", Json::array())) {
      const auto &refs = phase.at("interval_event_boundaries");
      auto point = [&](const char *edge) -> const Json & {
        const auto &ref = refs.at(edge);
        return snapshots.at(integer(ref.at("event_id")) - 1)
            .at(ref.at("edge").get<std::string>());
      };
      result["phases"][phase.at("phase").get<std::string>()] =
          counter_delta(point("begin"), point("end"), availability, reason);
    }
    const auto &call = handshake(ep);
    auto transports = select(ep.events, [&](const Json &e) {
      return e.at("kind") == "transport" && e.at("call_id") == call.at("id");
    });
    Json transport_metrics = Json::array();
    auto begin = snapshots.at(integer(call.at("id")) - 1).at("begin");
    for (std::size_t i = 0; i <= transports.size(); ++i) {
      auto end =
          i < transports.size()
              ? snapshots.at(integer(transports[i].at("id")) - 1).at("begin")
              : snapshots.at(integer(call.at("id")) - 1).at("end");
      result["outside_transport"].push_back(
          counter_delta(begin, end, availability, reason));
      if (i < transports.size()) {
        auto id = integer(transports[i].at("id"));
        begin = snapshots.at(id - 1).at("end");
        transport_metrics.push_back(metrics.at(id));
      }
    }
    result["accounting"] = {
        {"transport", add(transport_metrics)},
        {"outside_transport", add(result.at("outside_transport"))}};
    if (result.at("phases").size() == 4)
      for (auto f : {"cycles_raw", "instructions_raw", "time_enabled_ns",
                     "time_running_ns"}) {
        std::uint64_t total = 0;
        bool have = true;
        for (const auto &p : result.at("phases")) {
          const auto &m = p.at(f);
          if (m.at("availability") != "available")
            have = false;
          else
            total += integer(m.at("value"));
        }
        const auto &h = result.at("operations").at("handshake").at(f);
        if (have && h.at("availability") == "available") {
          auto n = integer(h.at("value"));
          if (total != n ||
              integer(
                  result.at("accounting").at("transport").at(f).at("value")) +
                      integer(result.at("accounting")
                                  .at("outside_transport")
                                  .at(f)
                                  .at("value")) !=
                  n)
            throw std::runtime_error("counter_partition_mismatch");
        }
      }
    std::uint64_t cost = 0;
    for (auto [a, b] : reads)
      cost += b - a;
    result["counter_read_wall_ns"] = reads.empty() ? Json(nullptr) : Json(cost);
    result["counter_read_count"] = reads.size();
    bool complete = availability == "available" &&
                    result.at("operations").size() == 4 &&
                    result.at("phases").size() == 4;
    for (auto group : {"operations", "phases"})
      for (const auto &m : result.at(group))
        for (auto field : {"cycles", "instructions"})
          complete = complete && m.at(field).at("availability") == "available";
    result["complete"] = complete;
  } catch (const std::exception &e) {
    result.update({{"availability", "missing"},
                   {"complete", false},
                   {"reason", e.what()},
                   {"events", Json::array()},
                   {"operations", Json::object()},
                   {"phases", Json::object()}});
  }
  return result;
}
} // namespace turtle::analysis
