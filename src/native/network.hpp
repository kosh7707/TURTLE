#pragma once
#include "control/network.hpp"
namespace turtle::native {
artifact::Json assess_network(const artifact::Json &p,
                              const artifact::Json &raw,
                              const std::filesystem::path &dir,
                              const artifact::Json &participants);
class NetworkTrial {
  using Json = artifact::Json;
  const std::filesystem::path dir_;
  bool impaired_, capture_;
  int cancel_;
  std::unique_ptr<control::Topology> topology_;
  std::map<std::string, std::unique_ptr<control::Capture>> captures_;
  Json record_;

public:
  NetworkTrial(const Json &profile, const std::filesystem::path &dir,
               const Json &raw, int cancel);
  bool active() const { return impaired_ || capture_; }
  const char *host() const {
    return impaired_ ? control::Topology::server_ip : "127.0.0.1";
  }
  std::string netns(const std::string &role) const;
  void start(const Json &profile);
  void listen(pid_t pid, unsigned port);
  void sample(const std::string &role, pid_t pid, unsigned port);
  void finish(const Json &pids);
};
// Return null unless a matching LISTEN or established socket belongs to pid.
// Addresses and ports are obtained directly from the participant's namespace.
artifact::Json owned_socket(pid_t pid, const char *host, unsigned port,
                            bool listener, bool server);
} // namespace turtle::native
