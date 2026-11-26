#pragma once
#include "artifact/json_value.hpp"
#include <cstdint>
#include <string>
namespace turtle::native {
inline constexpr char endpoint_contract_id[] = "endpoint.v1";
inline constexpr uint64_t buffered_evidence_version = 2;
// No marker is the archived native-stream contract, not a current default.
bool uses_endpoint_contract(const turtle::artifact::Json &context);
turtle::artifact::Json analyze_evidence(const std::string &ndjson,
                                const turtle::artifact::Json &context);
// Called after both roles have incorporated same-connection numeric evidence.
void qualify_flights(turtle::artifact::Json &report, bool mutual,
                     const turtle::artifact::Json &peer_full_handshake_auth);
}
