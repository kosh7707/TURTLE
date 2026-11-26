#include "native/network.hpp"
#include "artifact/network_evidence.hpp"
#include "native/packets.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <set>
#include <sstream>
namespace turtle::native {
using artifact::Json;
namespace fs = std::filesystem;
namespace {
std::pair<std::string, unsigned> address(const std::string &word) {
  if (word.size() != 13 || word[8] != ':')
    throw std::runtime_error("invalid_proc_tcp_endpoint");
  in_addr addr{
      static_cast<uint32_t>(std::stoul(word.substr(0, 8), nullptr, 16))};
  char ip[INET_ADDRSTRLEN]{};
  if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
    throw std::runtime_error("invalid_proc_address");
  return {ip, static_cast<unsigned>(std::stoul(word.substr(9), nullptr, 16))};
}
} // namespace
Json owned_socket(pid_t pid, const char *host, unsigned port, bool listener,
                  bool server) {
  const auto base = "/proc/" + std::to_string(pid);
  std::set<std::string> owned;
  std::error_code ec;
  for (auto &entry : fs::directory_iterator(base + "/fd", ec)) {
    auto path = fs::read_symlink(entry.path(), ec).string();
    if (path.starts_with("socket:[") && path.back() == ']')
      owned.insert(path.substr(8, path.size() - 9));
  }
  if (owned.empty())
    return nullptr;
  std::ifstream table(base + "/net/tcp");
  std::string line;
  Json result = nullptr;
  while (std::getline(table, line)) {
    std::istringstream in(line);
    std::string sl, local, remote, state, queues, timer, retries, uid, timeout,
        inode;
    if (!(in >> sl >> local >> remote >> state >> queues >> timer >> retries >>
          uid >> timeout >> inode) ||
        state != (listener ? "0A" : "01") || !owned.contains(inode))
      continue;
    auto [lip, lp] = address(local);
    auto [rip, rp] = address(remote);
    const auto &ip = server ? lip : rip;
    if ((ip != host && !(listener && ip == "0.0.0.0")) ||
        (server ? lp : rp) != port)
      continue;
    if (!result.is_null())
      throw std::runtime_error("ambiguous_native_connection");
    result = {{"pid", pid},
              {"inode", std::stoull(inode)},
              {"local_ip", lip},
              {"local_port", lp},
              {"remote_ip", rip},
              {"remote_port", rp},
              {"recv_queue",
               std::stoull(queues.substr(queues.find(':') + 1), nullptr, 16)}};
  }
  return result;
}
NetworkTrial::NetworkTrial(const Json &p, const fs::path &dir, const Json &raw,
                           int cancel)
    : dir_(dir / "network"),
      impaired_(p.value("network", "loopback") == "netem"),
      capture_(p.at("measurement").value("capture", false)), cancel_(cancel),
      record_({{"v", 1},
               {"run_id", raw.at("run_id")},
               {"connection_id", raw.at("connection_id")},
               {"port", raw.at("port")},
               {"mode", p.value("network", "loopback")},
               {"server_listener", nullptr},
               {"connected", Json::object()},
               {"capture", Json::object()}}) {}
std::string NetworkTrial::netns(const std::string &who) const {
  return topology_ ? topology_->namespace_path(who) : "";
}
void NetworkTrial::start(const Json &p) {
  if (!active())
    return;
  fs::create_directory(dir_);
  if (impaired_) {
    topology_ =
        std::make_unique<control::Topology>(dir_, p.at("netem"), cancel_);
    topology_->start();
  }
  if (capture_) {
    for (const std::string who : {"client", "server"}) {
      auto &capture = captures_[who];
      capture = std::make_unique<control::Capture>(dir_, who);
      try {
        capture->start(topology_ ? topology_->prefix(who) : process::Args{},
                       fs::canonical("/proc/self/exe"),
                       impaired_ ? "eth0" : "lo", record_.at("port").get<unsigned>(), cancel_);
      } catch (const std::exception &e) {
        // An optional missing capture cannot prevent the native application
        // exchange; required metrics are still checked on replay.
        record_["capture_errors"][who] = e.what();
      }
    }
  }
}
void NetworkTrial::listen(pid_t pid, unsigned port) {
  if (active())
    record_["server_listener"] = owned_socket(pid, host(), port, true, true);
}
void NetworkTrial::sample(const std::string &who, pid_t pid, unsigned port) {
  if (active() && !record_["connected"].contains(who)) {
    auto sock = owned_socket(pid, host(), port, false, who == "server");
    if (!sock.is_null())
      record_["connected"][who] = std::move(sock);
  }
}
void NetworkTrial::finish(const Json &pids) {
  if (!active())
    return;
  for (auto &[who, c] : captures_)
    record_["capture"][who] = c->finish();
  if (topology_)
    topology_->finish();
  record_["pid"] = pids;
  artifact::save(dir_ / "trial.json", record_);
}
Json assess_network(const Json &p, const Json &raw, const fs::path &dir,
                    const Json &participants) {
  const bool impaired = p.value("network", "loopback") == "netem";
  const bool captured = p.at("measurement").value("capture", false);
  Json result = {{"mode", p.value("network", "loopback")},
                 {"verified", nullptr},
                 {"capture_verified", nullptr},
                 {"tcp_ack", nullptr}};
  if (!impaired && !captured)
    return result;
  try {
    const auto ndir = dir / "network";
    const auto trial = artifact::load(ndir / "trial.json");
    if (trial.at("run_id") != raw.at("run_id") ||
        trial.at("connection_id") != raw.at("connection_id") ||
        trial.at("mode") != p.at("network") ||
        trial.at("port") != raw.at("port") ||
        trial.at("pid") != raw.value("pid", Json::object()))
      throw std::runtime_error("network_trial_identity_mismatch");
    if (impaired) {
      const auto network = artifact::load(ndir / "network.json");
      artifact::verify_netem(p.at("netem"), network);
      const auto &ls = trial.at("server_listener");
      const auto &c = trial.at("connected").at("client");
      const auto &s = trial.at("connected").at("server");
      if (ls.at("pid") != raw.at("pid").at("server") ||
          c.at("pid") != raw.at("pid").at("client") ||
          s.at("pid") != raw.at("pid").at("server") ||
          ls.at("local_port") != raw.at("port") ||
          (ls.at("local_ip") != control::Topology::server_ip &&
           ls.at("local_ip") != "0.0.0.0") ||
          c.at("local_ip") != control::Topology::client_ip ||
          c.at("remote_ip") != control::Topology::server_ip ||
          c.at("remote_port") != raw.at("port") ||
          c.at("remote_port") != s.at("local_port") ||
          c.at("remote_ip") != s.at("local_ip") ||
          c.at("local_ip") != s.at("remote_ip") ||
          c.at("local_port") != s.at("remote_port"))
        throw std::runtime_error("netem_participant_tuple_unverified");
      result["verified"] = true;
      result["requested"] = network.at("requested");
    }
    if (captured)
      result.update(analyze_packets(ndir, raw, participants));
  } catch (const std::exception &e) {
    result["verified"] = false;
    result["reason"] = e.what();
  }
  return result;
}

} // namespace turtle::native
