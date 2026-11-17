#include "control/network.hpp"
#include <array>
#include <sys/random.h>
#include <unistd.h>
namespace turtle::control {
using artifact::Json;
std::string identifier() {
  std::array<unsigned char, 16> bytes{};
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    auto n = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (n <= 0)
      throw std::runtime_error("getrandom_failed");
    offset += static_cast<std::size_t>(n);
  }
  std::string r;
  for (auto b : bytes) {
    r += "0123456789abcdef"[b >> 4];
    r += "0123456789abcdef"[b & 15];
  }
  return r;
}
Topology::Topology(std::filesystem::path root, Json settings, std::string exe,
                   int cancel)
    : root_(std::move(root)), settings_(std::move(settings)),
      executable_(std::move(exe)), cancel_(cancel) {
  auto id = identifier().substr(0, 10);
  for (auto role : {"client", "middle", "server"})
    names_[role] = "tu-" + id + "-" + role[0];
  state_ = {{"availability", "missing"}, {"topology", "client-middle-server"},
            {"names", names_},           {"requested", settings_},
            {"commands", Json::array()}, {"before", Json::object()},
            {"after", Json::object()},   {"capture", Json::object()}};
}
Topology::~Topology() { finish(); }
Args Topology::prefix(const std::string &role) const {
  return {"ip", "netns", "exec", names_.at(role)};
}
std::string Topology::invoke(const Args &args, bool check, bool cleanup) {
  auto r = command(args, 15, {{"LC_ALL", "C"}}, cleanup ? -1 : cancel_);
  state_["commands"].push_back(r);
  if (check && r.at("returncode") != 0)
    throw std::runtime_error("network_command_failed:" +
                             r.at("stderr").get<std::string>());
  return r.at("stdout");
}
std::string Topology::inside(const std::string &role, const Args &args,
                             bool cleanup) {
  auto a = prefix(role);
  a.insert(a.end(), args.begin(), args.end());
  return invoke(a, true, cleanup);
}
Json Topology::snapshot(bool cleanup) {
  Json r = Json::object();
  for (const auto &role : created_) {
    r[role] = {
        {"links", Json::parse(inside(role, {"ip", "-j", "-d", "link", "show"},
                                     cleanup))},
        {"qdisc",
         Json::parse(
             inside(role, {"tc", "-j", "-s", "-d", "qdisc", "show"}, cleanup))},
        {"offload", Json::object()}};
    for (const auto &iface : role == "middle"
                                 ? std::vector<std::string>{"mc", "ms"}
                                 : std::vector<std::string>{"eth0"})
      r[role]["offload"][iface] =
          inside(role, {"ethtool", "-k", iface}, cleanup);
  }
  return r;
}
void Topology::start() {
  for (auto role : {"client", "middle", "server"}) {
    invoke({"ip", "netns", "add", names_.at(role)});
    created_.emplace_back(role);
    inside(role, {"ip", "link", "set", "lo", "up"});
  }
  for (auto role : {"client", "server"}) {
    bool client = std::string(role) == "client";
    std::string mid = client ? "mc" : "ms",
                address = client ? client_ip : server_ip,
                gateway = client ? "192.0.2.1" : "198.51.100.1";
    inside(role, {"ip", "link", "add", "eth0", "type", "veth", "peer", "name",
                  mid, "netns", names_.at("middle")});
    for (bool endpoint : {true, false}) {
      std::string ns = endpoint ? role : "middle",
                  iface = endpoint ? "eth0" : mid,
                  ip = endpoint ? address : gateway;
      inside(ns, {"ip", "addr", "add", ip + "/30", "dev", iface});
      inside(ns, {"ip", "link", "set", "dev", iface, "mtu",
                  std::to_string(
                      artifact::integer(settings_.value("mtu", Json(1500)))),
                  "up"});
      inside(ns, {"ethtool", "-K", iface, "tso", "off", "gso", "off", "gro",
                  "off"});
    }
    inside(role, {"ip", "route", "add", "default", "via", gateway});
  }
  inside("middle", {"sysctl", "-qw", "net.ipv4.ip_forward=1"});
  for (const auto &[direction, iface] : std::map<std::string, std::string>{
           {"client_to_server", "ms"}, {"server_to_client", "mc"}}) {
    auto rule = settings_.value(direction, Json::object());
    Args a = {"tc",
              "qdisc",
              "add",
              "dev",
              iface,
              "root",
              "netem",
              "limit",
              rule.value("limit", Json(10000)).dump(),
              "delay",
              rule.value("delay_ms", Json(0)).dump() + "ms",
              "loss",
              "random",
              rule.value("loss_pct", Json(0)).dump() + "%"};
    if (rule.contains("rate_mbit") && rule.at("rate_mbit") != 0) {
      a.push_back("rate");
      a.push_back(rule.at("rate_mbit").dump() + "mbit");
    }
    if (rule.contains("seed")) {
      a.push_back("seed");
      a.push_back(rule.at("seed").dump());
    }
    inside("middle", a);
  }
  state_["before"] = snapshot();
  state_["availability"] = "available";
  artifact::save(root_ / "network.json", state_);
}
void Topology::start_capture() {
  for (auto role : {"client", "server"}) {
    auto a = prefix(role);
    a.insert(a.end(),
             {executable_, "__capture", "eth0",
              (root_ / (std::string(role) + ".pcap")).string(),
              (root_ / (std::string(role) + ".capture.json")).string()});
    auto child = std::make_unique<Child>(
        a, Environment{}, root_ / (std::string(role) + ".capture.log"));
    captures_[role] = std::move(child);
    if (captures_.at(role)->line(deadline(10), cancel_) != "READY")
      throw std::runtime_error("capture_not_ready");
  }
}
void Topology::finish() noexcept {
  if (finished_)
    return;
  finished_ = true;
  state_["cleanup_errors"] = Json::array();
  for (auto &[role, p] : captures_) {
    try {
      p->send("STOP\n");
      p->close_input();
      int code = p->wait(deadline(5));
      auto status = artifact::load(root_ / (role + ".capture.json"));
      status["returncode"] = code;
      if (code)
        status["availability"] = "missing";
      state_["capture"][role] = status;
    } catch (const std::exception &e) {
      p->stop();
      state_["capture"][role] = {{"availability", "missing"},
                                 {"reason", e.what()}};
    }
  }
  captures_.clear();
  try {
    state_["after"] = snapshot(true);
  } catch (const std::exception &e) {
    state_["snapshot_error"] = e.what();
  }
  for (auto it = created_.rbegin(); it != created_.rend(); ++it)
    try {
      invoke({"ip", "netns", "del", names_.at(*it)}, true, true);
    } catch (const std::exception &e) {
      state_["cleanup_errors"].push_back(e.what());
    }
  created_.clear();
  try {
    artifact::save(root_ / "network.json", state_);
  } catch (...) { /* Destructor cannot replace the original failure. Explicit
                     analysis detects missing state. */
  }
}
} // namespace turtle::control
