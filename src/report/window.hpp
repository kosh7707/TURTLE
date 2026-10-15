#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string_view>
#include <vector>

namespace turtle::report {

inline constexpr std::string_view alternate_elapsed =
    "client_hello_to_finished_send_elapsed_ns";
inline constexpr std::string_view alternate_thread_cpu =
    "client_hello_to_finished_send_thread_cpu_ns";
inline constexpr std::string_view alternate_cycles =
    "client_hello_to_finished_send_cycles";
inline constexpr std::string_view common_window_name =
    "handshake_call_begin_to_application_complete";
inline constexpr std::string_view common_elapsed =
    "handshake_call_begin_to_application_complete_elapsed_ns";
inline constexpr std::string_view common_thread_cpu =
    "handshake_call_begin_to_application_complete_thread_cpu_ns";

std::optional<nlohmann::json>
alternate_window(const nlohmann::json& header, const std::vector<nlohmann::json>& events,
                 const nlohmann::json& decoded_connection);
bool native_stream_unobserved(const nlohmann::json& header);
bool channel_observer_enabled(const nlohmann::json& header);

} // namespace turtle::report
