#pragma once
#include <nlohmann/json.hpp>
#include <string>
namespace turtle::native {
inline constexpr char endpoint_contract_id[] = "endpoint.v1";
// No marker is the archived native-stream contract, not a current default.
bool uses_endpoint_contract(const nlohmann::json &context);
nlohmann::json analyze_evidence(const std::string &ndjson,
                                const nlohmann::json &context);
// Called after both roles have incorporated same-connection numeric evidence.
void qualify_flights(nlohmann::json &report, bool mutual,
                     const nlohmann::json &peer_full_handshake_auth);
}
