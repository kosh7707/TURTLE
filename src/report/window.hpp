#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
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
inline constexpr std::string_view server_window_name =
    "server_client_hello_to_finished_send";
inline constexpr std::string_view server_window_definition =
    "server_client_hello_receive_return_to_server_finished_send_return";
inline constexpr std::string_view server_window_elapsed =
    "server_client_hello_to_finished_send_elapsed_ns";
inline constexpr std::string_view server_window_thread_cpu =
    "server_client_hello_to_finished_send_thread_cpu_ns";
inline constexpr std::string_view server_window_cycles =
    "server_client_hello_to_finished_send_cycles";

std::optional<nlohmann::json>
alternate_window(const nlohmann::json& header, const std::vector<nlohmann::json>& events,
                 const nlohmann::json& decoded_connection);
bool native_stream_unobserved(const nlohmann::json& header);
bool channel_observer_enabled(const nlohmann::json& header);
std::optional<std::string> io_events_unavailable_reason(const nlohmann::json& header);
nlohmann::json unavailable_record_computation_attribution(std::string_view reason);
nlohmann::json unavailable_server_client_hello_to_finished_send_window(
    std::string_view reason);
nlohmann::json record_computation_attribution(
    const nlohmann::json& header, const std::vector<nlohmann::json>& events,
    const nlohmann::json& decoded_connection,
    const nlohmann::json& partitioned_connection);
nlohmann::json server_client_hello_to_finished_send_window(
    const nlohmann::json& header, const std::vector<nlohmann::json>& events,
    const nlohmann::json& decoded_connection);

} // namespace turtle::report
