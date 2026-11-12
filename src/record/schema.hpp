#pragma once

#include <nlohmann/json.hpp>
#include <stdexcept>

namespace turtle::record {

inline bool supported_measurement_contract(int revision) {
    return revision == 3 || revision == 4;
}

// Offline readers share the current TLS record contract. Service, packet and
// report schemas have independent versions and do not pass through this check.
inline void require_tls_sample(const nlohmann::json& header) {
    if (header.value("type", "") != "sample" || header.value("schema", 0) != 3)
        throw std::runtime_error("TLS raw input requires schema 3");
    if (!supported_measurement_contract(header.value("measurement_contract_revision", 0)))
        throw std::runtime_error("TLS raw input requires measurement contract revision 3 or 4");
}

} // namespace turtle::record
