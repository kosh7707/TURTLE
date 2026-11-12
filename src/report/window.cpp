#include "report/window.hpp"
#include "report/report.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace turtle::report {
using Json = nlohmann::json;

namespace {
std::uint64_t time(const Json& event) {
    return event.at("monotonic_ns").get<std::uint64_t>();
}

bool successful_send(const Json& event) {
    return event.value("kind", "") == "IO_SEND_RETURN" &&
           event.value("transferred", std::uint64_t{0}) > 0 &&
           event.value("stream_end", std::uint64_t{0}) >
               event.value("stream_begin", std::uint64_t{0});
}

bool overlaps(const Json& event, const Json& range) {
    const auto begin = event.at("stream_begin").get<std::uint64_t>();
    const auto end = event.at("stream_end").get<std::uint64_t>();
    return range.at("begin").get<std::uint64_t>() < end &&
           range.at("end").get<std::uint64_t>() > begin;
}

const Json* one_message(const Json& direction, std::string_view name) {
    const Json* found = nullptr;
    for (const auto& message : direction.at("messages")) {
        if (message.value("name", "") != name) {
            continue;
        }
        if (found != nullptr) {
            return nullptr;
        }
        found = &message;
    }
    return found;
}
} // namespace

std::optional<Json> alternate_window(const Json& header, const std::vector<Json>& events,
                                     const Json& decoded_connection) {
    if (header.at("role") != "client" || !decoded_connection.value("decryption_complete", false) ||
        !decoded_connection.contains("client_sent")) {
        return std::nullopt;
    }
    const auto& direction = decoded_connection.at("client_sent");
    if (!direction.value("decryption_complete", false) || !direction.contains("messages")) {
        return std::nullopt;
    }
    const auto* client_hello = one_message(direction, "ClientHello");
    const auto* finished = one_message(direction, "Finished");
    if (client_hello == nullptr || finished == nullptr ||
        !client_hello->contains("record_stream_ranges") ||
        client_hello->at("record_stream_ranges").empty() ||
        !finished->contains("record_stream_ranges") ||
        finished->at("record_stream_ranges").empty()) {
        return std::nullopt;
    }

    const auto connection = decoded_connection.at("connection").get<std::size_t>();
    const Json* start = nullptr;
    const Json* end = nullptr;
    std::uint64_t finished_envelope_end = 0;
    for (const auto& range : finished->at("record_stream_ranges")) {
        finished_envelope_end =
            std::max(finished_envelope_end, range.at("end").get<std::uint64_t>());
    }
    for (const auto& event : events) {
        if (event.at("connection") != connection || !successful_send(event)) {
            continue;
        }
        if (start == nullptr) {
            for (const auto& range : client_hello->at("record_stream_ranges")) {
                if (overlaps(event, range)) {
                    start = &event;
                    break;
                }
            }
        }
        const auto stream_begin = event.at("stream_begin").get<std::uint64_t>();
        const auto stream_end = event.at("stream_end").get<std::uint64_t>();
        if (stream_begin < finished_envelope_end && stream_end >= finished_envelope_end) {
            end = &event;
            break;
        }
    }
    if (start == nullptr || end == nullptr || time(*end) < time(*start)) {
        return std::nullopt;
    }

    Json result = {
        {"definition", "client_hello_send_return_to_client_finished_send_return"},
        {"start_event_sequence", start->at("sequence")},
        {"end_event_sequence", end->at("sequence")},
        {"elapsed_ns", time(*end) - time(*start)},
        {"thread_cpu_ns", nullptr},
        {"cycles", nullptr},
        {"mapping", "record_envelope_overlap"},
        {"client_hello_bundled", client_hello->value("bundled", false)},
        {"finished_bundled", finished->value("bundled", false)},
        {"separate_plaintext_message_cpu_time_available", false},
        {"limitation",
         "The boundaries map I/O events to TLS record envelopes. A record or I/O return may "
         "contain multiple plaintext messages, so this is not separate plaintext-message CPU "
         "time."},
    };
    for (const char* metric : {"thread_cpu_ns", "cycles"}) {
        const bool supported =
            std::string_view(metric) == "thread_cpu_ns" || header.value("perf_complete", false);
        if (!supported || !start->contains(metric) || !end->contains(metric) ||
            start->at(metric).is_null() || end->at(metric).is_null()) {
            continue;
        }
        const auto first = start->at(metric).get<std::uint64_t>();
        const auto last = end->at(metric).get<std::uint64_t>();
        if (last >= first) {
            result[metric] = last - first;
        }
    }
    return result;
}

namespace {
bool boundary(const Json& e) {
    const auto l = e.at("location").get<std::string>();
    return l == "implementation_boundary" || l == "framework";
}
} // namespace

bool native_stream_unobserved(const Json& header) {
    return header.value("observation_level", std::string()) == "library-only" ||
           (header.contains("config") && header.at("config").contains("tls") &&
            !header.at("config").at("tls").value("framework_io", true));
}

namespace {
bool channel_observer_disabled(const Json& header) {
    return header.value("observation_level", std::string()) == "observer-disabled" ||
           (header.contains("config") && header.at("config").is_object() &&
            !header.at("config").value("channel_observer", true));
}
} // namespace

bool channel_observer_enabled(const Json& header) {
    return !channel_observer_disabled(header);
}

std::optional<std::string> io_events_unavailable_reason(const Json& header) {
    if (header.contains("availability") && header.at("availability").is_object() &&
        header.at("availability").contains("io_events") &&
        header.at("availability").at("io_events").is_object()) {
        const auto& availability = header.at("availability").at("io_events");
        if (availability.value("available", false))
            return std::nullopt;
        if (availability.contains("reason") && availability.at("reason").is_string() &&
            !availability.at("reason").get<std::string>().empty())
            return availability.at("reason").get<std::string>();
        return "io_events_not_observed";
    }
    if (native_stream_unobserved(header))
        return "native_socket_io_not_observed";
    if (channel_observer_disabled(header))
        return "channel_observer_disabled";
    return std::nullopt;
}

namespace {
bool io_events_observed(const Json& header) {
    return !io_events_unavailable_reason(header);
}
} // namespace

namespace {
std::optional<std::uint64_t> nonnegative_integer(const Json& value) {
    if (value.is_number_unsigned())
        return value.get<std::uint64_t>();
    if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value >= 0)
            return static_cast<std::uint64_t>(signed_value);
    }
    return std::nullopt;
}
std::string kind(const Json& e) {
    return e.at("kind").get<std::string>();
}
Json common_window(const Json& header, const Json& connection,
                   const std::vector<const Json*>& events) {
    Json result = {{"definition", common_window_name},
                   {"available", false},
                   {"reason", nullptr},
                   {"start_event_sequence", nullptr},
                   {"end_event_sequence", nullptr},
                   {"elapsed_ns", nullptr},
                   {"thread_cpu_ns", nullptr},
                   {"thread_cpu_reason", nullptr}};
    auto unavailable = [&](std::string_view reason) {
        result["reason"] = reason;
        return result;
    };
    if (!connection.value("application_verified", false))
        return unavailable("application_not_verified");
    if (!header.contains("config") || !header.at("config").is_object() ||
        !header.at("config").contains("tls") || !header.at("config").at("tls").is_object() ||
        !header.at("config").at("tls").contains("application_bytes"))
        return unavailable("application_bytes_missing");
    const auto& tls = header.at("config").at("tls");
    const bool server_first = tls.value("scenario", "client-request") == "server-ping" ||
                              tls.value("scenario", "client-request") == "finished-ping";
    const auto expected_value = nonnegative_integer(
        tls.value(server_first ? "client_application_bytes" : "server_application_bytes",
                  tls.at("application_bytes")));
    if (!expected_value || *expected_value == 0)
        return unavailable("application_bytes_invalid");
    const auto expected = *expected_value;

    const Json* start = nullptr;
    const Json* end = nullptr;
    std::uint64_t transferred = 0;
    std::optional<std::uint64_t> previous_sequence;
    std::optional<std::uint64_t> previous_time;
    bool target_call_active = false;
    const auto target = (header.at("role") == "client") != server_first ? "app_recv" : "app_send";
    for (const auto* event : events) {
        if (!event->contains("sequence") || !event->contains("monotonic_ns"))
            return unavailable("boundary_event_fields_missing");
        const auto sequence_value = nonnegative_integer(event->at("sequence"));
        const auto timestamp_value = nonnegative_integer(event->at("monotonic_ns"));
        if (!sequence_value || !timestamp_value)
            return unavailable("boundary_event_fields_missing");
        const auto sequence = *sequence_value;
        const auto timestamp = *timestamp_value;
        if ((previous_sequence && sequence <= *previous_sequence) ||
            (previous_time && timestamp < *previous_time))
            return unavailable("boundary_event_order_or_time_regression");
        previous_sequence = sequence;
        previous_time = timestamp;

        const auto event_kind = kind(*event);
        const auto call = event->value("call", std::string());
        if (!start && event_kind == "CALL_BEGIN" && call == "handshake")
            start = event;
        if (call != target)
            continue;
        if (event_kind == "CALL_BEGIN") {
            if (target_call_active)
                return unavailable("application_call_order_invalid");
            target_call_active = true;
            continue;
        }
        if (event_kind != "CALL_END")
            continue;
        if (!target_call_active)
            return unavailable("application_call_order_invalid");
        target_call_active = false;
        if (!event->contains("transferred"))
            return unavailable("application_progress_missing");
        const auto progress_value = nonnegative_integer(event->at("transferred"));
        if (!progress_value)
            return unavailable("application_progress_missing");
        const auto progress = *progress_value;
        const auto call_result = event->value("result", -1);
        if ((progress == 0 && call_result != 0 && call_result != 1) ||
            (progress > 0 && call_result != 2))
            return unavailable("application_call_unsuccessful");
        if (progress > expected - std::min(expected, transferred))
            return unavailable("application_progress_invalid");
        transferred += progress;
        if (transferred == expected) {
            if (call_result != 2 || progress == 0)
                return unavailable("application_completion_not_successful");
            end = event;
        }
    }
    if (target_call_active)
        return unavailable("application_call_end_missing");
    if (start == nullptr)
        return unavailable("handshake_call_begin_missing");
    if (end == nullptr || transferred != expected)
        return unavailable("application_completion_missing");
    if (end->at("sequence").get<std::uint64_t>() <= start->at("sequence").get<std::uint64_t>() ||
        time(*end) < time(*start))
        return unavailable("common_boundary_order_or_time_regression");

    result.update({{"available", true},
                   {"reason", nullptr},
                   {"start_event_sequence", start->at("sequence")},
                   {"end_event_sequence", end->at("sequence")},
                   {"elapsed_ns", time(*end) - time(*start)}});
    if (!start->contains("thread_cpu_ns") || !end->contains("thread_cpu_ns") ||
        start->at("thread_cpu_ns").is_null() || end->at("thread_cpu_ns").is_null()) {
        result["thread_cpu_reason"] = "thread_cpu_snapshot_missing";
    } else {
        const auto first = nonnegative_integer(start->at("thread_cpu_ns"));
        const auto last = nonnegative_integer(end->at("thread_cpu_ns"));
        if (!first || !last)
            result["thread_cpu_reason"] = "thread_cpu_snapshot_invalid";
        else if (*last < *first)
            result["thread_cpu_reason"] = "thread_cpu_regression";
        else
            result["thread_cpu_ns"] = *last - *first;
    }
    return result;
}

const Json* decoded_direction(const Json& decoded_connection, std::string_view key) {
    if (!decoded_connection.contains(key) || !decoded_connection.at(key).is_object())
        return nullptr;
    const auto& direction = decoded_connection.at(key);
    if (!direction.value("decryption_complete", false) || !direction.contains("records") ||
        !direction.at("records").is_array() || !direction.contains("messages") ||
        !direction.at("messages").is_array())
        return nullptr;
    return &direction;
}

std::vector<std::uint64_t> completed_records(const Json& direction, const Json& event) {
    std::vector<std::uint64_t> indices;
    if (event.value("kind", "") != "IO_RECV_RETURN" ||
        event.value("result", std::int64_t{-1}) != 0 ||
        event.value("transferred", std::uint64_t{0}) == 0)
        return indices;
    const auto begin = event.value("stream_begin", std::uint64_t{0});
    const auto end = event.value("stream_end", std::uint64_t{0});
    if (end <= begin)
        return indices;
    for (const auto& record : direction.at("records")) {
        if (!record.contains("index") || !record.contains("stream_end"))
            continue;
        const auto index = nonnegative_integer(record.at("index"));
        const auto record_end = nonnegative_integer(record.at("stream_end"));
        if (index && record_end && *record_end > begin && *record_end <= end)
            indices.push_back(*index);
    }
    return indices;
}

std::vector<std::uint64_t> overlapping_records(const Json& direction, const Json& event) {
    std::vector<std::uint64_t> indices;
    if (event.value("kind", "") != "IO_SEND_RETURN" ||
        event.value("result", std::int64_t{-1}) != 0 ||
        event.value("transferred", std::uint64_t{0}) == 0)
        return indices;
    const auto begin = event.value("stream_begin", std::uint64_t{0});
    const auto end = event.value("stream_end", std::uint64_t{0});
    if (end <= begin)
        return indices;
    for (const auto& record : direction.at("records")) {
        if (!record.contains("index") || !record.contains("stream_begin") ||
            !record.contains("stream_end"))
            continue;
        const auto index = nonnegative_integer(record.at("index"));
        const auto record_begin = nonnegative_integer(record.at("stream_begin"));
        const auto record_end = nonnegative_integer(record.at("stream_end"));
        if (index && record_begin && record_end && *record_begin < end && *record_end > begin)
            indices.push_back(*index);
    }
    return indices;
}

bool contains_record(const Json& message, std::uint64_t index) {
    if (!message.contains("records") || !message.at("records").is_array())
        return false;
    for (const auto& value : message.at("records")) {
        const auto candidate = nonnegative_integer(value);
        if (candidate && *candidate == index)
            return true;
    }
    return false;
}

Json record_boundary(std::string_view boundary_kind, const Json& boundary_event,
                     const Json& io_return, const Json& direction,
                     const std::vector<std::uint64_t>& record_indices) {
    Json names = Json::array();
    for (const auto& message : direction.at("messages")) {
        bool selected = false;
        for (const auto index : record_indices)
            selected = selected || contains_record(message, index);
        if (!selected || !message.contains("name") || !message.at("name").is_string())
            continue;
        names.push_back(message.at("name"));
    }
    return {{"kind", boundary_kind},
            {"boundary_event_sequence", boundary_event.at("sequence")},
            {"io_return_event_sequence", io_return.at("sequence")},
            {"record_indices", record_indices},
            {"names", names},
            {"bundled", names.size() > 1},
            {"mapping", "record_envelope"}};
}

Json call_boundary(std::string_view boundary_kind, const Json& event) {
    return {{"kind", boundary_kind},
            {"boundary_event_sequence", event.at("sequence")},
            {"io_return_event_sequence", nullptr},
            {"record_indices", Json::array()},
            {"names", Json::array()},
            {"bundled", false},
            {"mapping", "boundary_event"}};
}

const Json* matching_send_return(const std::vector<const Json*>& events, std::size_t enter_index) {
    const auto& enter = *events.at(enter_index);
    if (!enter.contains("connection") || !enter.contains("call_id") || !enter.contains("sequence"))
        return nullptr;
    for (std::size_t i = enter_index + 1; i < events.size(); ++i) {
        const auto& candidate = *events[i];
        if (candidate.value("kind", "") == "IO_SEND_ENTER")
            return nullptr;
        if (candidate.value("kind", "") != "IO_SEND_RETURN")
            continue;
        if (candidate.contains("connection") && candidate.contains("call_id") &&
            candidate.contains("sequence") &&
            candidate.at("connection") == enter.at("connection") &&
            candidate.at("call_id") == enter.at("call_id") &&
            candidate.at("sequence") > enter.at("sequence")) {
            if (candidate.value("result", std::int64_t{-1}) == 0 &&
                candidate.value("transferred", std::uint64_t{0}) > 0 &&
                candidate.value("stream_end", std::uint64_t{0}) >
                    candidate.value("stream_begin", std::uint64_t{0}))
                return &candidate;
            return nullptr;
        }
    }
    return nullptr;
}

void segment_cpu(Json& segment, const Json& begin, const Json& end) {
    segment["thread_cpu_ns"] = nullptr;
    segment["thread_cpu_reason"] = nullptr;
    if (!begin.contains("thread_cpu_ns") || !end.contains("thread_cpu_ns") ||
        begin.at("thread_cpu_ns").is_null() || end.at("thread_cpu_ns").is_null()) {
        segment["thread_cpu_reason"] = "thread_cpu_snapshot_missing";
        return;
    }
    const auto first = nonnegative_integer(begin.at("thread_cpu_ns"));
    const auto last = nonnegative_integer(end.at("thread_cpu_ns"));
    if (!first || !last)
        segment["thread_cpu_reason"] = "thread_cpu_snapshot_invalid";
    else if (*last < *first)
        segment["thread_cpu_reason"] = "thread_cpu_regression";
    else
        segment["thread_cpu_ns"] = *last - *first;
}
} // namespace

Json unavailable_server_client_hello_to_finished_send_window(std::string_view reason) {
    return {{"definition", server_window_definition},
            {"available", false},
            {"reason", reason},
            {"start_event_sequence", nullptr},
            {"end_event_sequence", nullptr},
            {"elapsed_ns", nullptr},
            {"thread_cpu_ns", nullptr},
            {"thread_cpu_reason", reason},
            {"cycles", nullptr},
            {"mapping", "record_envelope_overlap"},
            {"client_hello_bundled", nullptr},
            {"finished_bundled", nullptr},
            {"limitation",
             "This server window ends when the server Finished record is sent; it does not "
             "mean that the client Finished or a mutual-authentication client certificate has "
             "been verified."}};
}

Json unavailable_record_computation_attribution(std::string_view reason) {
    return {{"available", false},
            {"reason", reason},
            {"scope", "primary_window_computation_segments"},
            {"segments", nullptr}};
}

Json record_computation_attribution(const Json& header, const std::vector<Json>& input,
                                    const Json& decoded_connection,
                                    const Json& partitioned_connection) {
    Json result = unavailable_record_computation_attribution("");
    if (const auto reason = io_events_unavailable_reason(header)) {
        result["reason"] = *reason;
        return result;
    }
    if (!decoded_connection.value("decryption_complete", false)) {
        result["reason"] = "decoded_sidecar_decryption_incomplete";
        return result;
    }
    const bool client = header.at("role") == "client";
    const auto* received =
        decoded_direction(decoded_connection, client ? "server_sent" : "client_sent");
    const auto* sent =
        decoded_direction(decoded_connection, client ? "client_sent" : "server_sent");
    if (received == nullptr || sent == nullptr) {
        result["reason"] = "decoded_record_mapping_unavailable";
        return result;
    }
    if (!partitioned_connection.contains("segments") ||
        !partitioned_connection.at("segments").is_array()) {
        result["reason"] = "primary_partition_unavailable";
        return result;
    }

    const auto connection = decoded_connection.at("connection").get<std::size_t>();
    std::vector<const Json*> events;
    for (const auto& event : input)
        if (event.value("connection", std::size_t(-1)) == connection && boundary(event))
            events.push_back(&event);

    Json attributed = Json::array();
    const auto& primary_segments = partitioned_connection.at("segments");
    for (std::size_t segment_index = 0; segment_index < primary_segments.size(); ++segment_index) {
        const auto& primary = primary_segments.at(segment_index);
        if (primary.value("kind", "") != "computation")
            continue;
        const Json* begin_event = nullptr;
        const Json* end_event = nullptr;
        std::size_t end_event_index = 0;
        for (std::size_t i = 1; i < events.size(); ++i) {
            if (time(*events[i - 1]) == primary.at("begin_ns").get<std::uint64_t>() &&
                time(*events[i]) == primary.at("end_ns").get<std::uint64_t>()) {
                begin_event = events[i - 1];
                end_event = events[i];
                end_event_index = i;
                break;
            }
        }
        if (begin_event == nullptr || end_event == nullptr) {
            result["reason"] = "primary_segment_event_mapping_unavailable";
            return result;
        }
        if (!begin_event->contains("sequence") || !end_event->contains("sequence")) {
            result["reason"] = "primary_segment_event_mapping_unavailable";
            return result;
        }

        Json segment = {{"segment_index", segment_index},
                        {"begin_event_sequence", begin_event->at("sequence")},
                        {"end_event_sequence", end_event->at("sequence")},
                        {"elapsed_ns", primary.at("elapsed_ns")},
                        {"thread_cpu_ns", nullptr},
                        {"thread_cpu_reason", nullptr},
                        {"start", nullptr},
                        {"end", nullptr}};
        segment_cpu(segment, *begin_event, *end_event);

        if (begin_event->value("kind", "") == "CALL_BEGIN") {
            segment["start"] = call_boundary("call_begin", *begin_event);
        } else if (begin_event->value("kind", "") == "IO_RECV_RETURN") {
            const auto indices = completed_records(*received, *begin_event);
            if (!indices.empty())
                segment["start"] = record_boundary("after_receive", *begin_event, *begin_event,
                                                   *received, indices);
        }

        if (end_event->value("kind", "") == "CALL_END") {
            segment["end"] = call_boundary("call_end", *end_event);
        } else if (end_event->value("kind", "") == "IO_SEND_ENTER") {
            if (const auto* returned = matching_send_return(events, end_event_index)) {
                const auto indices = overlapping_records(*sent, *returned);
                if (!indices.empty())
                    segment["end"] =
                        record_boundary("before_send", *end_event, *returned, *sent, indices);
            }
        }
        attributed.push_back(std::move(segment));
    }
    result["available"] = true;
    result["reason"] = nullptr;
    result["segments"] = std::move(attributed);
    return result;
}

Json server_client_hello_to_finished_send_window(const Json& header,
                                                 const std::vector<Json>& events,
                                                 const Json& decoded_connection) {
    if (header.value("role", "") != "server")
        return unavailable_server_client_hello_to_finished_send_window("server_role_required");
    if (const auto reason = io_events_unavailable_reason(header))
        return unavailable_server_client_hello_to_finished_send_window(*reason);
    if (!decoded_connection.value("decryption_complete", false))
        return unavailable_server_client_hello_to_finished_send_window(
            "decoded_sidecar_decryption_incomplete");
    const auto* received = decoded_direction(decoded_connection, "client_sent");
    const auto* sent = decoded_direction(decoded_connection, "server_sent");
    if (received == nullptr || sent == nullptr)
        return unavailable_server_client_hello_to_finished_send_window(
            "server_window_record_mapping_unavailable");
    const auto* client_hello = one_message(*received, "ClientHello");
    const auto* finished = one_message(*sent, "Finished");
    if (client_hello == nullptr || finished == nullptr ||
        !client_hello->contains("record_stream_ranges") ||
        client_hello->at("record_stream_ranges").empty() ||
        !finished->contains("record_stream_ranges") || finished->at("record_stream_ranges").empty())
        return unavailable_server_client_hello_to_finished_send_window(
            "server_window_record_mapping_unavailable");

    std::uint64_t client_hello_begin = std::numeric_limits<std::uint64_t>::max();
    for (const auto& range : client_hello->at("record_stream_ranges"))
        client_hello_begin = std::min(client_hello_begin, range.at("begin").get<std::uint64_t>());
    std::uint64_t finished_end = 0;
    for (const auto& range : finished->at("record_stream_ranges"))
        finished_end = std::max(finished_end, range.at("end").get<std::uint64_t>());

    const auto connection = decoded_connection.at("connection").get<std::size_t>();
    const Json* start = nullptr;
    const Json* end = nullptr;
    for (const auto& event : events) {
        if (event.value("connection", std::size_t(-1)) != connection || !boundary(event) ||
            !event.contains("sequence") || event.value("result", std::int64_t{-1}) != 0 ||
            event.value("transferred", std::uint64_t{0}) == 0 ||
            event.value("stream_end", std::uint64_t{0}) <=
                event.value("stream_begin", std::uint64_t{0}))
            continue;
        const auto begin = event.at("stream_begin").get<std::uint64_t>();
        const auto finish = event.at("stream_end").get<std::uint64_t>();
        if (start == nullptr && event.value("kind", "") == "IO_RECV_RETURN" &&
            begin <= client_hello_begin && client_hello_begin < finish)
            start = &event;
        if (event.value("kind", "") == "IO_SEND_RETURN" && begin < finished_end &&
            finish >= finished_end) {
            end = &event;
            break;
        }
    }
    if (start == nullptr || end == nullptr || time(*end) < time(*start))
        return unavailable_server_client_hello_to_finished_send_window(
            "server_window_io_boundary_unavailable");

    auto result = unavailable_server_client_hello_to_finished_send_window("");
    result.update({{"available", true},
                   {"reason", nullptr},
                   {"start_event_sequence", start->at("sequence")},
                   {"end_event_sequence", end->at("sequence")},
                   {"elapsed_ns", time(*end) - time(*start)},
                   {"thread_cpu_reason", nullptr},
                   {"client_hello_bundled", client_hello->value("bundled", false)},
                   {"finished_bundled", finished->value("bundled", false)}});
    if (!start->contains("thread_cpu_ns") || !end->contains("thread_cpu_ns") ||
        start->at("thread_cpu_ns").is_null() || end->at("thread_cpu_ns").is_null()) {
        result["thread_cpu_reason"] = "thread_cpu_snapshot_missing";
    } else {
        const auto first = nonnegative_integer(start->at("thread_cpu_ns"));
        const auto last = nonnegative_integer(end->at("thread_cpu_ns"));
        if (!first || !last)
            result["thread_cpu_reason"] = "thread_cpu_snapshot_invalid";
        else if (*last < *first)
            result["thread_cpu_reason"] = "thread_cpu_regression";
        else
            result["thread_cpu_ns"] = *last - *first;
    }
    if (header.value("perf_complete", false) && start->contains("cycles") &&
        end->contains("cycles") && !start->at("cycles").is_null() && !end->at("cycles").is_null()) {
        const auto first = nonnegative_integer(start->at("cycles"));
        const auto last = nonnegative_integer(end->at("cycles"));
        if (first && last && *last >= *first)
            result["cycles"] = *last - *first;
    }
    return result;
}

Json partition(const Json& header, const std::vector<Json>& input) {
    Json results = Json::array();
    for (const auto& conn : header.at("connections")) {
        if (conn.value("warmup", false))
            continue;
        const auto index = conn.at("index").get<std::size_t>();
        std::vector<const Json*> events;
        for (const auto& e : input)
            if (e.at("connection") == index && boundary(e))
                events.push_back(&e);
        const bool functional_valid = conn.value("scenario_completed", false);
        const auto common = common_window(header, conn, events);
        bool primary_observable = true;
        std::string primary_reason;
        if (conn.contains("primary_window") && conn.at("primary_window").is_object()) {
            primary_observable = conn.at("primary_window").value("available", false);
            if (!primary_observable && conn.at("primary_window").contains("reason") &&
                conn.at("primary_window").at("reason").is_string())
                primary_reason = conn.at("primary_window").at("reason").get<std::string>();
        } else if (header.at("role") == "server" &&
                   (native_stream_unobserved(header) || channel_observer_disabled(header))) {
            primary_observable = false;
            primary_reason = "server_first_receive_not_observed";
        }
        Json result = {{"connection", index}, {"valid", functional_valid}};
        result[std::string(common_window_name)] = common;
        result["primary_window"] = {{"available", primary_observable},
                                    {"reason", primary_observable || primary_reason.empty()
                                                   ? Json(nullptr)
                                                   : Json(primary_reason)}};
        if (!primary_observable) {
            result["reason"] = primary_reason;
            result["io_breakdown"] = {
                {"available", false},
                {"reason", io_events_observed(header)
                               ? Json(primary_reason.empty() ? "measurement_boundaries_incomplete"
                                                             : primary_reason)
                               : Json("io_events_not_observed")}};
            results.push_back(result);
            continue;
        }
        if (events.empty()) {
            result["valid"] = false;
            result["primary_window"] = {{"available", false},
                                        {"reason", "missing_boundary_events"}};
            result["reason"] = "missing boundary events";
            results.push_back(result);
            continue;
        }
        std::optional<std::uint64_t> start, end;
        const Json* start_event = nullptr;
        const Json* end_event = nullptr;
        const bool client = header.at("role") == "client";
        for (const auto* e : events) {
            const auto k = kind(*e);
            if (!start &&
                ((client && k == "CALL_BEGIN" && e->at("call") == "handshake") ||
                 (!client && k == "IO_RECV_RETURN" && e->value("transferred", 0ULL) > 0))) {
                start = time(*e);
                start_event = e;
            }
            if (conn.contains("end_sequence") && e->contains("sequence") &&
                e->at("sequence") == conn.at("end_sequence")) {
                end = time(*e);
                end_event = e;
            }
        }
        if (!start || !end || *end < *start ||
            (conn.contains("start_sequence") && !conn.at("start_sequence").is_null() &&
             start_event->value("sequence", Json(nullptr)) != conn.at("start_sequence"))) {
            result["valid"] = false;
            result["primary_window"] = {{"available", false},
                                        {"reason", "missing_successful_measurement_boundaries"}};
            result["reason"] = "missing successful measurement boundaries";
            results.push_back(result);
            continue;
        }
        const bool api_completion_contract = header.value("measurement_contract_revision", 3) == 4;
        if (api_completion_contract) {
            const auto scenario = header.at("config").at("tls").value("scenario", "client-request");
            const bool completion_matches =
                scenario == "handshake"
                    ? kind(*end_event) == "CALL_END" && end_event->value("call", "") == "handshake" &&
                          end_event->value("result", -1) == 2
                    : common.value("available", false) &&
                          common.at("end_event_sequence") == end_event->at("sequence");
            if (!completion_matches) {
                result["valid"] = false;
                result["primary_window"] = {{"available", false},
                                            {"reason", "scenario_completion_call_mismatch"}};
                result["reason"] = "scenario_completion_call_mismatch";
                results.push_back(result);
                continue;
            }
        }
        const char* end_definition = api_completion_contract
                                         ? "last_successful_scenario_call_return"
                                         : "scenario_complete";
        const bool io_observed = io_events_observed(header);
        result["start_event_sequence"] = start_event->value("sequence", Json(nullptr));
        result["end_event_sequence"] = end_event->value("sequence", Json(nullptr));
        if (!io_observed) {
            result.update(
                {{"valid", functional_valid},
                 {"start_ns", *start},
                 {"end_ns", *end},
                 {"elapsed_ns", *end - *start},
                 {"computation_ns", nullptr},
                 {"io_ns", nullptr},
                 {"wait_ns", nullptr},
                 {"gap_ns", nullptr},
                 {"segments", Json::array()},
                 {"end_definition", end_definition},
                 {"io_breakdown", {{"available", false}, {"reason", "io_events_not_observed"}}}});
            for (const char* metric : {"thread_cpu_ns", "cycles", "instructions"}) {
                result[metric] = nullptr;
                const bool supported =
                    std::string(metric) == "thread_cpu_ns" || header.value("perf_complete", false);
                if (supported && start_event->contains(metric) && end_event->contains(metric) &&
                    !start_event->at(metric).is_null() && !end_event->at(metric).is_null()) {
                    const auto a = start_event->at(metric).get<std::uint64_t>();
                    const auto b = end_event->at(metric).get<std::uint64_t>();
                    if (b >= a)
                        result[metric] = b - a;
                }
            }
            result["heap_peak_bytes"] = nullptr;
            results.push_back(result);
            continue;
        }
        result["io_breakdown"] = {{"available", true}, {"reason", nullptr}};
        std::uint64_t computation = 0, io = 0, wait = 0, gap = 0;
        bool in_call = false, in_io = false, in_wait = false, consistent = true;
        std::uint64_t previous = time(*events.front());
        Json segments = Json::array();
        for (const auto* e : events) {
            const auto now = time(*e);
            if (now < previous) {
                consistent = false;
                break;
            }
            const auto lo = std::max(previous, *start), hi = std::min(now, *end);
            const char* label = in_io ? "io" : in_wait ? "wait" : in_call ? "computation" : "gap";
            if (hi > lo) {
                auto* total = in_io ? &io : in_wait ? &wait : in_call ? &computation : &gap;
                *total += hi - lo;
                segments.push_back(
                    {{"kind", label}, {"begin_ns", lo}, {"end_ns", hi}, {"elapsed_ns", hi - lo}});
            }
            const auto k = kind(*e);
            if (k == "CALL_BEGIN") {
                if (in_call)
                    consistent = false;
                in_call = true;
            } else if (k == "CALL_END") {
                if (!in_call || in_io)
                    consistent = false;
                in_call = false;
            } else if (k == "IO_SEND_ENTER" || k == "IO_RECV_ENTER") {
                if (in_io)
                    consistent = false;
                in_io = true;
            } else if (k == "IO_SEND_RETURN" || k == "IO_RECV_RETURN") {
                if (!in_io)
                    consistent = false;
                in_io = false;
            } else if (k == "WAIT_BEGIN") {
                if (in_wait || in_io || in_call)
                    consistent = false;
                in_wait = true;
            } else if (k == "WAIT_END") {
                if (!in_wait)
                    consistent = false;
                in_wait = false;
            }
            previous = now;
        }
        const auto elapsed = *end - *start;
        consistent = consistent && !in_call && !in_io && !in_wait &&
                     computation + io + wait + gap == elapsed;
        // The partition can still conserve elapsed time when an entire I/O pair
        // is lost: it would charge that interval to computation. Check the raw
        // sequence, including library/kernel events omitted from the partition.
        if (start_event->contains("sequence") && end_event->contains("sequence")) {
            auto expected = start_event->at("sequence").get<std::uint64_t>();
            const auto last = end_event->at("sequence").get<std::uint64_t>();
            for (const auto& e : input) {
                if (e.at("connection") != index || !e.contains("sequence"))
                    continue;
                const auto sequence = e.at("sequence").get<std::uint64_t>();
                if (sequence < start_event->at("sequence").get<std::uint64_t>() || sequence > last)
                    continue;
                if (sequence != expected)
                    consistent = false;
                expected = sequence + 1;
            }
            consistent = consistent && expected == last + 1;
        }
        result.update({{"valid", functional_valid && consistent},
                       {"start_ns", *start},
                       {"end_ns", *end},
                       {"elapsed_ns", elapsed},
                       {"computation_ns", computation},
                       {"io_ns", io},
                       {"wait_ns", wait},
                       {"gap_ns", gap},
                       {"segments", segments},
                       {"end_definition", end_definition}});
        for (const char* metric : {"thread_cpu_ns", "cycles", "instructions"}) {
            result[metric] = nullptr;
            const bool supported =
                std::string(metric) == "thread_cpu_ns" || header.value("perf_complete", false);
            if (supported && start_event->contains(metric) && end_event->contains(metric) &&
                !start_event->at(metric).is_null() && !end_event->at(metric).is_null()) {
                const auto a = start_event->at(metric).get<std::uint64_t>();
                const auto b = end_event->at(metric).get<std::uint64_t>();
                if (b >= a)
                    result[metric] = b - a;
            }
        }
        result["heap_peak_bytes"] = nullptr;
        result["heap_peak_reason"] = "heap_not_observed";
        if (start_event->contains("heap") && !start_event->at("heap").is_null()) {
            auto peak = start_event->at("heap").at("live").get<std::uint64_t>();
            bool complete_heap = true;
            // Every meter read resets the interval peak, including non-boundary
            // snapshots. Sequence order also preserves intervals within one clock tick.
            for (const auto& e : input) {
                if (e.at("connection") != index || !e.contains("sequence") ||
                    e.at("sequence") <= start_event->at("sequence") ||
                    e.at("sequence") > end_event->at("sequence") ||
                    e.value("kind", "") == "KERNEL_RX")
                    continue;
                // KERNEL_RX shares its IO_RECV_RETURN snapshot; it is not a
                // second read. In particular, a copy of the start snapshot
                // must not bring the pre-window interval peak back in.
                if (!e.contains("heap") || e.at("heap").is_null()) {
                    complete_heap = false;
                    continue;
                }
                peak = std::max(peak, e.at("heap").at("interval_peak").get<std::uint64_t>());
            }
            if (complete_heap && consistent) {
                result["heap_peak_bytes"] = peak;
                result["heap_peak_reason"] = nullptr;
            } else {
                result["heap_peak_reason"] = "heap_snapshot_missing";
            }
        } else if (header.value("mode", "") == "memory" &&
                   header.value("capabilities", Json::object()).value("heap_tracking", false)) {
            result["heap_peak_reason"] = "heap_snapshot_missing";
        }
        if (!consistent) {
            result["reason"] = "boundary nesting/order or interval conservation failed";
            result["io_breakdown"] = {{"available", false},
                                       {"reason", "boundary_sequence_or_nesting_incomplete"}};
            for (const char* metric : {"computation_ns", "io_ns", "wait_ns", "gap_ns"})
                result[metric] = nullptr;
            result["segments"] = nullptr;
        }
        results.push_back(result);
    }
    return results;
}

} // namespace turtle::report
