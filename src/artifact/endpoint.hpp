#pragma once
#include "measure/recorder.hpp"
#include <string>
#include <turtle/implementation.h>
namespace turtle::artifact {
struct Result {
  std::string run_id, connection_id = "1", implementation, role, invalid_reason;
  std::string cipher, group, purpose, measured_role, recording, auth, scenario;
  std::size_t begin_event = 0, end_event = 0;
  std::size_t plaintext_sent = 0, plaintext_received = 0, request_bytes = 0, response_bytes = 0, greeting_bytes = 0;
  std::uint64_t server_submitted = 0, queued_before_resume = 0;
  bool client_paused = false, server_presend = false, content_verified = false;
  int peer_verified = -1, record_policy = 0;
  std::string shutdown = "not_attempted", shutdown_reason;
  std::string observation_reason;
  unsigned version = 0;
  turtle_handshake_profile profile = TURTLE_PROFILE_UNSPECIFIED;
  int resumed = -1;
  bool scenario_complete = false, scenario_observations_complete = false;
  bool cpu_samples = false;
  measure::Stamp begin, end;
  std::uint64_t scenario_tls_send = 0, scenario_tls_receive = 0;
  std::uint64_t scenario_wire_send = 0, scenario_wire_receive = 0;
  std::size_t chunk = 0;
};
void write(const std::string &directory, const measure::Recorder &,
           const Result &);
} // namespace turtle::artifact
