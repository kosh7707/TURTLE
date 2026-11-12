#include "report/prototype.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <tuple>

namespace turtle::report {
using Json = nlohmann::json;
namespace {
Json absent(const char* status, const char* reason) {
    return {{"status", status},
            {"reason", reason},
            {"elapsed_ns", nullptr},
            {"thread_cpu_ns", nullptr}};
}
Json interval(const Json* begin, const Json* end) {
    if (!begin || !end)
        return absent("missing", "boundary_not_observed");
    if (end->at("monotonic_ns") < begin->at("monotonic_ns"))
        return absent("missing", "boundary_order_invalid");
    Json result = {{"status", "available"},
                   {"reason", nullptr},
                   {"begin_sequence", begin->at("sequence")},
                   {"end_sequence", end->at("sequence")}};
    result["elapsed_ns"] = end->at("monotonic_ns").get<std::uint64_t>() -
                           begin->at("monotonic_ns").get<std::uint64_t>();
    result["thread_cpu_ns"] = nullptr;
    result["thread_cpu_reason"] = nullptr;
    if (!begin->contains("thread_cpu_ns") || !end->contains("thread_cpu_ns") ||
        begin->at("thread_cpu_ns").is_null() || end->at("thread_cpu_ns").is_null()) {
        result["thread_cpu_reason"] = "thread_cpu_snapshot_missing";
    } else {
        const auto a = begin->at("thread_cpu_ns").get<std::uint64_t>();
        const auto b = end->at("thread_cpu_ns").get<std::uint64_t>();
        if (b >= a)
            result["thread_cpu_ns"] = b - a;
        else
            result["thread_cpu_reason"] = "thread_cpu_regression";
    }
    return result;
}
const Json* message_submit(const std::vector<const Json*>& events, const Json* decoded,
                           const char* direction, const char* message) {
    if (!decoded || !decoded->value("decryption_complete", false))
        return nullptr;
    std::uint64_t end = 0;
    for (const auto& item : decoded->at(direction).at("messages")) {
        if (item.value("name", "") != message)
            continue;
        for (const auto& range : item.at("record_stream_ranges"))
            end = std::max(end, range.at("end").get<std::uint64_t>());
    }
    if (!end)
        return nullptr;
    for (const auto* event : events)
        if (event->value("kind", "") == "IO_SEND_RETURN" && event->value("transferred", 0ULL) > 0 &&
            event->at("stream_begin").get<std::uint64_t>() < end &&
            event->at("stream_end").get<std::uint64_t>() >= end)
            return event;
    return nullptr;
}
Json transmit_observations(const Json& header, const std::vector<const Json*>& events,
                           std::size_t connection) {
    if (!header.at("config").value("tx_timestamps", false))
        return {{"status", "unsupported"}, {"reason", "tx_timestamp_collection_not_requested"}};
    const Json* socket = nullptr;
    for (const auto& item : header.at("connections"))
        if (item.at("index") == connection && item.at("socket").is_object())
            socket = &item.at("socket");
    if (!socket || !socket->value("kernel_tx_timestamps", false))
        return {{"status", "unsupported"},
                {"reason", "socket_timestamping_not_configured"},
                {"system_error", socket ? socket->value("kernel_tx_timestamp_error", 0) : 0}};
    Json observations = Json::array();
    std::map<std::string, unsigned> counts;
    std::uint64_t submitted = 0, acknowledged = 0;
    bool matched = true;
    for (const auto* event : events) {
        const auto kind = event->value("kind", "");
        if (kind == "IO_SEND_RETURN")
            submitted = std::max(submitted, event->at("stream_end").get<std::uint64_t>());
        if (kind != "KERNEL_TX_SCHED" && kind != "KERNEL_TX_SND" && kind != "KERNEL_TX_ACK")
            continue;
        const auto end = event->at("stream_end").get<std::uint64_t>();
        Json submission = nullptr;
        for (const auto* send : events)
            if (send->at("kind") == "IO_SEND_RETURN" && send->value("transferred", 0ULL) &&
                send->at("stream_begin").get<std::uint64_t>() < end &&
                send->at("stream_end").get<std::uint64_t>() >= end) {
                submission = send->at("sequence");
                break;
            }
        matched &= !submission.is_null();
        ++counts[kind];
        if (kind == "KERNEL_TX_ACK")
            acknowledged = std::max(acknowledged, end);
        observations.push_back({{"kind", kind},
                                {"sequence", event->at("sequence")},
                                {"raw_realtime_ns", event->at("raw_timestamp_ns")},
                                {"collection_monotonic_ns", event->at("monotonic_ns")},
                                {"timestamp_id", event->at("timestamp_id")},
                                {"request_last_byte_end", end},
                                {"socket_submit_sequence", submission}});
    }
    const int error = socket->value("kernel_tx_drain_error", 0);
    const bool complete = matched && !error && counts["KERNEL_TX_SCHED"] &&
                          counts["KERNEL_TX_SND"] && counts["KERNEL_TX_ACK"];
    return {{"status", complete ? "available" : "missing"},
            {"reason", complete ? Json(nullptr) : Json("required_stage_or_byte_mapping_missing")},
            {"drain_system_error", error},
            {"stage_counts", counts},
            {"events", observations},
            {"last_submission_acknowledged", submitted > 0 && acknowledged >= submitted},
            {"submitted_bytes", submitted},
            {"acknowledged_prefix_end", acknowledged},
            {"clock_start", header.value("clock_start", Json(nullptr))},
            {"clock_end", header.value("clock_end", Json(nullptr))},
            {"coverage", "request last byte; ACK cumulative; not exact packet or record coverage"},
            {"collection",
             "nonblocking error queue; final drain up to 100ms after both scenarios complete"}};
}
} // namespace
Json prototype_observations(const Json& header, const std::vector<Json>& input,
                            std::size_t connection, const Json* decoded) {
    if (!header.contains("config") || !header.at("config").contains("tls"))
        return {{"status", "missing"}, {"reason", "scenario_configuration_missing"}};
    std::vector<const Json*> events;
    for (const auto& event : input)
        if (event.at("connection") == connection)
            events.push_back(&event);
    const auto first = [&](const char* kind) -> const Json* {
        for (const auto* event : events)
            if (event->at("kind") == kind)
                return event;
        return nullptr;
    };
    const auto call = [&](const char* operation) -> const Json* {
        for (const auto* event : events)
            if (event->at("kind") == "CALL_BEGIN" && event->at("call") == operation)
                return event;
        return nullptr;
    };
    const bool client = header.at("role") == "client";
    const auto& tls = header.at("config").at("tls");
    const auto scenario = tls.value("scenario", "client-request");
    const auto support = header.at("declaration").value("internal_events", Json::array());
    const bool io_observed =
        tls.value("framework_io", true) && header.at("config").value("channel_observer", true);
    const auto socket_interval = [&](const Json* begin, const Json* end) {
        return io_observed ? interval(begin, end) : absent("unsupported", "socket_io_not_observed");
    };
    Json windows = Json::object();
    for (auto [name, start, end] :
         {std::tuple{"module_load", "MODULE_BEGIN", "MODULE_END"},
          {"context_setup", "SETUP_BEGIN", "SETUP_END"},
          {"connection_prepare", "OPEN_BEGIN", "OPEN_END"},
          {"payload_prepare", "PAYLOAD_PREPARE_BEGIN", "PAYLOAD_PREPARE_END"}}) {
        if (connection &&
            (std::string(name) == "module_load" || std::string(name) == "context_setup"))
            windows[name] =
                absent("not_applicable", "shared_context_setup_recorded_on_connection_zero");
        else if (std::string(name) == "module_load" &&
                 header.at("adapter_connection").value("mode", "") == "builtin")
            windows[name] =
                absent("not_applicable", "builtin_adapter_pre_entry_loading_unobserved");
        else if (scenario == "handshake" && std::string(name) == "payload_prepare")
            windows[name] = absent("not_applicable", "handshake_only");
        else
            windows[name] = interval(first(start), first(end));
    }
    windows[client ? "tcp_connect" : "accept_wait"] =
        interval(first(client ? "TCP_CONNECT_BEGIN" : "ACCEPT_BEGIN"),
                 first(client ? "TCP_CONNECT_END" : "ACCEPT_END"));
    windows["handshake_api"] = interval(call("handshake"), first("HANDSHAKE_COMPLETE"));
    const auto* finished =
        message_submit(events, decoded, client ? "client_sent" : "server_sent", "Finished");
    const auto* app =
        message_submit(events, decoded, client ? "client_sent" : "server_sent", "ApplicationData");
    if (client) {
        windows["open_to_client_finished_submit"] = socket_interval(first("OPEN_BEGIN"), finished);
        windows["tcp_to_client_finished_submit"] =
            socket_interval(first("TCP_CONNECT_BEGIN"), finished);
    } else {
        const Json* receive = nullptr;
        const Json* processed = nullptr;
        for (const auto* event : events) {
            if (!receive && event->at("kind") == "IO_RECV_RETURN" &&
                event->value("transferred", 0ULL))
                receive = event;
            if (event->at("kind") == "INTERNAL_END" &&
                event->value("trace_operation", Json(nullptr)) == "message_process" &&
                event->value("message_type", 0) == 20)
                processed = event;
        }
        windows["first_tls_receive_to_client_finished_processed"] =
            socket_interval(receive, processed);
        if (io_observed && !processed) {
            const bool enabled = header.at("mode") == "trace";
            const bool supported =
                std::find(support.begin(), support.end(), "message_process") != support.end();
            windows["first_tls_receive_to_client_finished_processed"] =
                absent(enabled && supported ? "missing" : "unsupported",
                       !enabled     ? "internal_trace_disabled"
                       : !supported ? "internal_processing_unsupported"
                                    : "finished_process_span_not_observed");
        }
    }
    if (scenario == "handshake") {
        windows["application"] = absent("not_applicable", "handshake_only");
    } else if (scenario == "client-request") {
        if (client) {
            windows["request_to_response_first_byte"] =
                interval(first("APPLICATION_WRITE_BEGIN"), first("APPLICATION_FIRST_BYTE"));
            windows["request_to_response_complete"] =
                interval(first("APPLICATION_WRITE_BEGIN"), first("APPLICATION_READ_END"));
        } else {
            windows["request_received_to_response_submit"] =
                socket_interval(first("APPLICATION_READ_END"), app);
        }
    } else if (client) {
        windows["ping_received_to_pong_submit"] =
            socket_interval(first("APPLICATION_READ_END"), app);
    } else {
        windows["ping_write_to_pong_received"] =
            interval(first("APPLICATION_WRITE_BEGIN"), first("APPLICATION_READ_END"));
    }
    Json spans = Json::array();
    std::map<std::pair<std::string, std::uint64_t>, const Json*> pending;
    bool complete = true;
    for (const auto* event : events) {
        const auto kind = event->value("kind", "");
        if (kind != "INTERNAL_BEGIN" && kind != "INTERNAL_END")
            continue;
        auto key = std::pair{event->at("trace_operation").get<std::string>(),
                             event->at("message_id").get<std::uint64_t>()};
        if (kind == "INTERNAL_BEGIN") {
            if (pending.contains(key))
                complete = false;
            pending[key] = event;
        } else {
            auto start = pending.find(key);
            if (start == pending.end()) {
                complete = false;
                continue;
            }
            auto span = interval(start->second, event);
            complete &= span.at("status") == "available";
            span["operation"] = key.first;
            span["message_id"] = key.second;
            span["message_type"] = event->at("message_type");
            span["result"] = event->at("result");
            spans.push_back(span);
            pending.erase(start);
        }
    }
    complete &= pending.empty();
    const bool enabled = header.at("mode") == "trace" && !support.empty();
    const auto span_status = !enabled                     ? "unsupported"
                             : spans.empty() || !complete ? "missing"
                                                          : "available";
    Json batch = absent("not_applicable", "scenario_does_not_request_finished_ping_batch");
    if (!client && scenario == "finished-ping") {
        batch = {{"status", finished && app ? "available" : "missing"},
                 {"same_output_batch", finished && app
                                           ? Json(finished->at("batch_id") == app->at("batch_id"))
                                           : Json(nullptr)},
                 {"tcp_segment_equivalence", false}};
    }
    return {{"scenario", scenario},
            {"windows", windows},
            {"internal_spans", spans},
            {"internal_spans_status", span_status},
            {"internal_spans_complete", enabled ? Json(complete && !spans.empty()) : Json(nullptr)},
            {"internal_support", support},
            {"internal_support_note", header.at("declaration").value("internal_events_note", "")},
            {"finished_ping_batch", batch},
            {"kernel_transmit", transmit_observations(header, events, connection)},
            {"mapping", "decoded record envelopes to successful socket submission; shared record "
                        "costs remain shared"}};
}
} // namespace turtle::report
