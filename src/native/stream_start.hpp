#pragma once
#include "native/start_packet.hpp"
#include "native/stream_process.hpp"
#include <sys/random.h>

namespace turtle::native::detail {
using artifact::Json;
// This is the ONLY ordinary control edge. The app explicitly opts in with
// a datagram from its own PID. Silence/exit/timeouts are not READY.
class PreparedStart {
  process::Deadline deadline_;
  bool released_ = false, finished_ = false;
  Json &record_;

public:
  static std::string time_namespace(pid_t pid) {
    std::error_code ec;
    auto value = std::filesystem::read_symlink(
        "/proc/" + std::to_string(pid) + "/ns/time", ec);
    return ec ? "" : value.string();
  }
  PreparedStart(Json &raw, process::Deadline end)
      : deadline_(std::min(Clock::now() + std::chrono::milliseconds(250),
                           Clock::now() + (end - Clock::now()) / 4)),
        record_(raw["prepared_start"]) {
    record_ = {{"v", 1},
               {"run_id", raw.at("run_id")},
               {"connection_id", raw.at("connection_id")},
               {"outcome", "pending"},
               {"host_time_namespace", time_namespace(getpid())},
               {"roles", Json::object()}};
  }
  void service(App &client, App &server, std::vector<pollfd> &fds) {
    if (finished_)
      return;
    bool unavailable = false;
    for (auto [role, a] : {std::pair{"client", &client}, {"server", &server}}) {
      auto &side = record_["roles"][role];
      side["pid"] = a->pid;
      if (side.contains(released_ ? "ack_received_ns" : "ready_received_ns"))
        continue;
      StartPacket payload{};
      alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(ucred))]{};
      iovec io{payload.data(), payload.size()};
      msghdr msg{};
      msg.msg_iov = &io;
      msg.msg_iovlen = 1;
      msg.msg_control = ancillary;
      msg.msg_controllen = sizeof ancillary;
      auto n = recvmsg(a->start.fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
      if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
        fds.push_back({a->start.fd, POLLIN, 0});
        continue;
      }
      ucred cred{};
      bool expected =
          n == static_cast<ssize_t>(payload.size()) && start_stamp(payload) &&
          payload[0] == (released_ ? 'A' : 'R') &&
          !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
          start_token(payload) == side.value("release_token", uint64_t(0));
      for (auto c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
            c->cmsg_len == CMSG_LEN(sizeof cred))
          std::memcpy(&cred, CMSG_DATA(c), sizeof cred);
        else {
          expected = false;
          if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
            for (size_t i = 0; i + sizeof(int) <= c->cmsg_len - CMSG_LEN(0);
                 i += sizeof(int)) {
              int fd;
              std::memcpy(&fd, CMSG_DATA(c) + i, sizeof fd);
              close(fd);
            }
        }
      }
      if (expected && cred.pid == a->pid) {
        side[released_ ? "ack_received_ns" : "ready_received_ns"] = ns();
        side[released_ ? "ack_sender_pid" : "sender_pid"] = cred.pid;
        if (released_)
          side["ack_token"] = start_token(payload);
        side[released_ ? "participant_ack_ns" : "participant_ready_ns"] =
            start_stamp(payload);
        auto domain = time_namespace(a->pid);
        if (!domain.empty())
          side["time_namespace"] = domain;
      } else
        unavailable = true;
    }
    if (released_) {
      if (record_["roles"]["client"].contains("ack_received_ns") &&
          record_["roles"]["server"].contains("ack_received_ns")) {
        record_["outcome"] = "joint_release";
        finished_ = true;
      } else if (unavailable) {
        record_["outcome"] = "release_not_acknowledged";
        finished_ = true;
      }
      return;
    }
    bool both = record_["roles"]["client"].contains("ready_received_ns") &&
                record_["roles"]["server"].contains("ready_received_ns");
    if (!both && !unavailable && Clock::now() < deadline_)
      return;
    std::array<uint64_t, 2> tokens{};
    if (both && (getrandom(tokens.data(), sizeof tokens, GRND_NONBLOCK) !=
                     sizeof tokens ||
                 !tokens[0] || !tokens[1] || tokens[0] == tokens[1]))
      both = false;
    const char answer = both ? 'G' : 'U';
    bool delivered = true;
    for (auto [role, a] : {std::pair{"client", &client}, {"server", &server}}) {
      auto &side = record_["roles"][role];
      side["release_begin_ns"] = ns();
      auto token =
          both ? tokens[std::string_view(role) == "client" ? 0 : 1] : 0;
      side["release_token"] = token;
      auto packet = start_packet(answer, 0, token);
      bool sent = send(a->start.fd, packet.data(), packet.size(),
                       MSG_DONTWAIT | MSG_NOSIGNAL) ==
                  static_cast<ssize_t>(packet.size());
      delivered &= sent;
      side["release"] = sent ? Json(std::string(1, answer)) : Json(nullptr);
    }
    released_ = both && delivered;
    record_["outcome"] = released_ ? "awaiting_ack" : "unsynchronized_fallback";
    finished_ = !released_;
  }
};
inline Json prepared_start_proof(const Json &raw, const Json &participants) {
  Json facts = Json::object();
  uint64_t ready_max = 0, entry_min = UINT64_MAX;
  bool full = true, valid = true, late = false, release_conflict = false;
  for (auto role : {"client", "server"}) {
    const auto &p = participants.at(role);
    if (p.at("status") == "invalid")
      valid = false;
    auto events = p.value("lifecycle", Json::object());
    for (auto key : {"ready", "hs_begin"}) {
      auto e = events.value(key, Json(nullptr));
      if (e.is_null()) {
        full = false;
        facts[role][key] = nullptr;
        continue;
      }
      facts[role][key] = {
          {"pid", e.at("pid")}, {"seq", e.at("seq")}, {"ns", e.at("ns")}};
      auto t = artifact::integer(e.at("ns"));
      if (std::string_view(key) == "ready")
        ready_max = std::max(ready_max, t);
      else
        entry_min = std::min(entry_min, t);
    }
  }
  auto domains = raw.value("time_namespaces", Json::object());
  auto client = domains.value("client", ""),
       server = domains.value("server", "");
  auto linux_clock = [](std::string_view id) {
    if (!id.starts_with("time:[") || !id.ends_with("]") || id.size() < 8)
      return false;
    return id.substr(6, id.size() - 7).find_first_not_of("0123456789") ==
           id.npos;
  };
  bool comparable = linux_clock(client) && client == server;
  late = comparable && entry_min != UINT64_MAX && ready_max > entry_min;
  bool joint = false;
  Json outcome = nullptr;
  if (raw.contains("prepared_start")) {
    const auto &r = raw.at("prepared_start");
    outcome = r.at("outcome");
    if (r.at("v") != 1 || r.at("run_id") != raw.at("run_id") ||
        r.at("connection_id") != raw.at("connection_id"))
      throw std::runtime_error("wrong_prepared_start_binding");
    if (outcome == "joint_release") {
      uint64_t got = 0, released = UINT64_MAX;
      for (auto role : {"client", "server"}) {
        auto &s = r.at("roles").at(role);
        auto pid = raw.at("pid").at(role);
        if (s.at("pid") != pid || s.at("sender_pid") != pid ||
            s.at("ack_sender_pid") != pid || s.at("release") != "G" ||
            artifact::integer(s.at("release_token")) == 0 ||
            s.at("ack_token") != s.at("release_token") ||
            artifact::integer(s.at("ack_received_ns")) <
                artifact::integer(s.at("release_begin_ns")))
          throw std::runtime_error("invalid_prepared_release");
        auto ready = artifact::integer(s.at("ready_received_ns")),
             go = artifact::integer(s.at("release_begin_ns"));
        if (!ready || !go)
          throw std::runtime_error("invalid_prepared_release_time");
        got = std::max(got, ready);
        released = std::min(released, go);
        auto &f = facts.at(role);
        auto local_r = artifact::integer(s.at("participant_ready_ns")),
             local_a = artifact::integer(s.at("participant_ack_ns"));
        if (!local_r || local_r > local_a)
          throw std::runtime_error("invalid_participant_start_order");
        if ((!f.at("ready").is_null() &&
             artifact::integer(f.at("ready").at("ns")) > local_r) ||
            (!f.at("hs_begin").is_null() &&
             artifact::integer(f.at("hs_begin").at("ns")) < local_a))
          release_conflict = true;
        auto domain = domains.value(role, "");
        if (!domain.empty() && domain == r.value("host_time_namespace", "")) {
          bool early_entry = !f.at("hs_begin").is_null() &&
                             artifact::integer(f.at("hs_begin").at("ns")) < go;
          bool late_ready = !f.at("ready").is_null() &&
                            artifact::integer(f.at("ready").at("ns")) > ready;
          release_conflict |= early_entry || late_ready;
        }
      }
      if (got > released)
        throw std::runtime_error("release_before_both_ready");
      joint = !release_conflict;
    }
  }
  bool natural = comparable && full && ready_max < entry_min;
  Json value = !valid                     ? Json(nullptr)
               : late || release_conflict ? Json(false)
               : joint || natural         ? Json(true)
                                          : Json(nullptr);
  return {{"verified", value},
          {"basis", value != true ? "none"
                    : joint       ? "prepared_rendezvous"
                                  : "both_ready_before_first_entry"},
          {"reason", value == true ? Json(nullptr)
                     : !valid      ? Json("invalid_report")
                     : late        ? Json("handshake_preceded_joint_readiness")
                     : release_conflict
                         ? Json("reported_boundary_conflicts_with_release")
                         : Json("joint_prepared_start_unobserved")},
          {"clock_domains", domains},
          {"rendezvous", outcome},
          {"native_anchors", facts}};
}
} // namespace turtle::native::detail
