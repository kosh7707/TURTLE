#pragma once

#include <csignal>
#include <filesystem>
#include <memory>
#include <string>

namespace turtle::submission {

class Network {
public:
  static constexpr const char *server_ip = "192.0.2.2";
  static constexpr const char *client_ip = "192.0.2.1";

  Network(const std::filesystem::path &case_dir, double additional_rtt_ms,
          double loss_pct, const volatile std::sig_atomic_t *stop = nullptr);
  ~Network();
  Network(const Network &) = delete;
  Network &operator=(const Network &) = delete;

  // Call only in a child before executing a role.
  void enter(bool server) const;
  void begin_samples();
  void finish_samples();
  const std::string &sample_counter_status() const;
  bool probes_valid() const;

private:
  struct State;
  std::unique_ptr<State> state_;
};

} // namespace turtle::submission
