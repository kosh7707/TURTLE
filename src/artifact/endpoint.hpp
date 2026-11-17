#pragma once
#include "measure/recorder.hpp"
#include <string>
#include <turtle/implementation.h>
namespace turtle::artifact {
struct Result {
  std::string run_id, connection_id = "1", implementation, role, invalid_reason;
  std::string cipher, group;
  std::string shutdown = "not_attempted";
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
