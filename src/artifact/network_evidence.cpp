#include "artifact/network_evidence.hpp"
#include <algorithm>
#include <cmath>
#include <string_view>
namespace turtle::artifact {
namespace {
void require(bool test, const char *why) {
  if (!test)
    throw std::runtime_error(why);
}
void keys(const Json &j, std::initializer_list<std::string_view> allowed) {
  require(j.is_object(), "netem_object_required");
  for (const auto &[k, v] : j.items())
    if (std::find(allowed.begin(), allowed.end(), k) == allowed.end())
      throw std::runtime_error("unknown_netem_option:" + k);
}
double number(const Json &n, double max) {
  require(n.is_number(), "netem_number_required");
  auto d = n.get<double>();
  require(std::isfinite(d) && d >= 0 && d <= max, "invalid_netem_value");
  return d;
}
const Json &single(const Json &rows, const char *field, const char *value) {
  const Json *found = nullptr;
  require(rows.is_array(), "netem_rows_missing");
  for (const auto &r : rows)
    if (r.at(field) == value) {
      require(!found, "netem_duplicate_interface");
      found = &r;
    }
  require(found, "netem_interface_missing");
  return *found;
}
void near(double actual, double expected, double unit) {
  // tc prints rounded decimal values; nanosecond / uint32 probability
  // resolution and its decimal precision are not differences in requested
  // conditions.
  require(std::isfinite(actual) && (actual == 0) == (expected == 0) &&
              std::abs(actual - expected) <=
                  std::max(unit, std::abs(expected) * 0.000005),
          "netem_setting_mismatch");
}
double field(const Json &opts, const char *key, const char *sub) {
  return opts.contains(key) ? number(opts.at(key).at(sub), 1e18) : 0;
}
const Json &queue(const Json &at, const char *dev, const Json &rule) {
  const auto &q = single(at.at("middle").at("qdisc"), "dev", dev);
  require(q.at("kind") == "netem" && q.at("root") == true,
          "netem_qdisc_missing");
  const auto &opts = q.at("options");
  require(integer(opts.at("limit")) ==
              integer(rule.value("limit", Json(10000))),
          "netem_limit_mismatch");
  near(field(opts, "delay", "delay"), rule.value("delay_ms", 0.) / 1000., 1e-9);
  near(field(opts, "loss-random", "loss"), rule.value("loss_pct", 0.) / 100.,
       1. / 4294967295.);
  near(field(opts, "rate", "rate"), rule.value("rate_mbit", 0.) * 125000., 0.5);
  if (rule.contains("seed"))
    require(opts.at("seed") == rule.at("seed"), "netem_seed_mismatch");
  // Only conditions this collector actually configures are supportable. In
  // particular, do not admit a qdisc with jitter/reordering or burst losses.
  keys(opts, {"limit", "delay", "loss-random", "rate", "ecn", "gap", "seed"});
  if (opts.contains("delay")) {
    keys(opts.at("delay"), {"delay", "jitter", "correlation"});
    require(opts.at("delay").value("jitter", 0.) == 0 &&
                opts.at("delay").value("correlation", 0.) == 0,
            "netem_unrequested_delay");
  }
  if (opts.contains("loss-random")) {
    keys(opts.at("loss-random"), {"loss", "correlation"});
    require(opts.at("loss-random").value("correlation", 0.) == 0,
            "netem_unrequested_correlation");
  }
  if (opts.contains("rate")) {
    keys(opts.at("rate"),
         {"rate", "packetoverhead", "cellsize", "celloverhead"});
    for (auto key : {"packetoverhead", "cellsize", "celloverhead"})
      require(opts.at("rate").value(key, 0.) == 0, "netem_unrequested_rate");
  }
  require(opts.value("ecn", false) == false && opts.value("gap", 0) == 0,
          "netem_unrequested_option");
  return q;
}
} // namespace
Json normalized_netem(Json req) {
  keys(req,
       {"mtu", "additional_rtt_ms", "client_to_server", "server_to_client"});
  const auto mtu = integer(req.value("mtu", Json(1500)));
  require(mtu >= 576 && mtu <= 65535, "invalid_netem_mtu");
  const bool split = req.contains("additional_rtt_ms");
  double half = split ? number(req.at("additional_rtt_ms"), 120000.) / 2. : 0.;
  for (auto dir : {"client_to_server", "server_to_client"}) {
    if (!req.contains(dir) && !split)
      continue;
    auto rule = req.value(dir, Json::object());
    keys(rule, {"delay_ms", "loss_pct", "rate_mbit", "limit", "seed"});
    if (split) {
      require(!rule.contains("delay_ms"), "ambiguous_netem_delay");
      rule["delay_ms"] = half;
    }
    number(rule.value("delay_ms", Json(0)), 60000);
    number(rule.value("loss_pct", Json(0)), 20);
    number(rule.value("rate_mbit", Json(0)), 1000000);
    auto lim = integer(rule.value("limit", Json(10000)));
    require(lim > 0 && lim <= UINT32_MAX, "invalid_netem_limit");
    require(integer(rule.value("seed", Json(0))) <= UINT32_MAX,
            "invalid_netem_seed");
    req[dir] = rule;
  }
  req.erase("additional_rtt_ms");
  return req;
}
void verify_netem(const Json &req, const Json &net) {
  require(net.at("availability") == "available" &&
              net.at("topology") == "client-middle-server" &&
              net.at("requested") == req && !net.contains("snapshot_error") &&
              net.at("cleanup_errors").is_array() &&
              net.at("cleanup_errors").empty(),
          "netem_topology_unverified");
  auto mtu = integer(req.value("mtu", Json(1500)));
  for (auto stage : {"before", "after"}) {
    const auto &snapshot = net.at(stage);
    for (auto role : {"client", "server"}) {
      const auto mid = std::string_view(role) == "client" ? "mc" : "ms";
      const auto &endpoint =
          single(snapshot.at(role).at("links"), "ifname", "eth0");
      const auto &middle =
          single(snapshot.at("middle").at("links"), "ifname", mid);
      require(integer(endpoint.at("ifindex")) ==
                      integer(middle.at("link_index")) &&
                  integer(middle.at("ifindex")) ==
                      integer(endpoint.at("link_index")),
              "netem_veth_peer_mismatch");
      for (const Json *link : {&endpoint, &middle}) {
        const auto &flags = link->at("flags");
        require(link->at("linkinfo").at("info_kind") == "veth" &&
                    integer(link->at("mtu")) == mtu && flags.is_array() &&
                    std::find(flags.begin(), flags.end(), "UP") != flags.end(),
                "netem_link_mismatch");
      }
    }
  }
  for (auto dir : {"client_to_server", "server_to_client"}) {
    auto dev = std::string_view(dir) == "client_to_server" ? "ms" : "mc";
    auto rule = req.value(dir, Json::object());
    const auto &a = queue(net.at("before"), dev, rule),
               &b = queue(net.at("after"), dev, rule);
    require(!a.at("handle").get_ref<const std::string &>().empty() &&
                a.at("handle") == b.at("handle"),
            "netem_queue_replaced");
    for (auto key : {"packets", "bytes", "drops"}) {
      const auto before = integer(a.at(key)), after = integer(b.at(key));
      require(std::string_view(key) == "drops" ? after >= before
                                               : after > before,
              "netem_counters_unverified");
    }
  }
}
} // namespace turtle::artifact
