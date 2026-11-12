#pragma once

#include <nlohmann/json.hpp>

namespace turtle::report::detail {

inline bool observed_socket_settings(const nlohmann::json& settings) {
    if (!settings.is_array() || settings.empty())
        return false;
    for (const auto& socket : settings) {
        if (!socket.is_object())
            return false;
        for (const auto* key : {"nonblocking", "tcp_nodelay", "kernel_timestamps"})
            if (!socket.contains(key) || !socket.at(key).is_boolean())
                return false;
        for (const auto* key : {"send_buffer", "receive_buffer"})
            if (!socket.contains(key) || !socket.at(key).is_number_integer() || socket.at(key) <= 0)
                return false;
    }
    return true;
}

inline bool comparison_condition(const nlohmann::json& dimensions, bool group_eligible) {
    if (!group_eligible || dimensions.value("mode", "") != "timing" ||
        dimensions.value("timing_interpretation", "performance") != "performance" ||
        !dimensions.value("automatic_comparison_identity_complete", false) ||
        !dimensions.value("peer_verified", false) || !dimensions.value("peer_valid", false))
        return false;
    if (!observed_socket_settings(dimensions.value("socket_settings", nlohmann::json(nullptr))) ||
        !observed_socket_settings(
            dimensions.value("peer_socket_settings", nlohmann::json(nullptr))))
        return false;
    for (const char* field : {"context_identity", "peer_context_identity"})
        if (!dimensions.contains(field) || !dimensions.at(field).is_object() ||
            !dimensions.at(field).contains("hash") || dimensions.at(field).at("hash").is_null())
            return false;
    return true;
}

} // namespace turtle::report::detail
