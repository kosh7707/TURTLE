#include "report/window.hpp"
#include "report/report.hpp"

#include <algorithm>
#include <cstdint>
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
bool io_events_observed(const Json& header) {
    const bool has_availability =
        header.contains("availability") && header.at("availability").is_object() &&
        header.at("availability").contains("io_events") &&
        header.at("availability").at("io_events").is_object();
    return has_availability
               ? header.at("availability").at("io_events").value("available", false)
               : !native_stream_unobserved(header) && !channel_observer_disabled(header);
}
} // namespace

bool channel_observer_enabled(const Json& header) {
    return !channel_observer_disabled(header);
}

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
        !header.at("config").contains("tls") ||
        !header.at("config").at("tls").is_object() ||
        !header.at("config").at("tls").contains("application_bytes"))
        return unavailable("application_bytes_missing");
    const auto expected_value =
        nonnegative_integer(header.at("config").at("tls").at("application_bytes"));
    if (!expected_value || *expected_value == 0)
        return unavailable("application_bytes_invalid");
    const auto expected = *expected_value;

    const Json* start = nullptr;
    const Json* end = nullptr;
    std::uint64_t transferred = 0;
    std::optional<std::uint64_t> previous_sequence;
    std::optional<std::uint64_t> previous_time;
    bool target_call_active = false;
    const auto target = header.at("role") == "client" ? "app_recv" : "app_send";
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
    if (end->at("sequence").get<std::uint64_t>() <=
            start->at("sequence").get<std::uint64_t>() ||
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
} // namespace

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
        const bool functional_valid = conn.value("application_verified", false);
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
        result["primary_window"] =
            {{"available", primary_observable},
             {"reason", primary_observable || primary_reason.empty() ? Json(nullptr)
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
            result["primary_window"] =
                {{"available", false}, {"reason", "missing_boundary_events"}};
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
            if (k == "CALL_END" && e->at("call") == (client ? "app_recv" : "app_send") &&
                e->value("result", 0LL) == 2) {
                end = time(*e);
                end_event = e;
            }
        }
        if (!start || !end || *end < *start) {
            result["valid"] = false;
            result["primary_window"] =
                {{"available", false}, {"reason", "missing_successful_measurement_boundaries"}};
            result["reason"] = "missing successful measurement boundaries";
            results.push_back(result);
            continue;
        }
        const bool io_observed = io_events_observed(header);
        if (!io_observed) {
            result.update({{"valid", functional_valid},
                           {"start_ns", *start},
                           {"end_ns", *end},
                           {"elapsed_ns", *end - *start},
                           {"computation_ns", nullptr},
                           {"io_ns", nullptr},
                           {"wait_ns", nullptr},
                           {"gap_ns", nullptr},
                           {"segments", Json::array()},
                           {"end_definition", "successful_application_call_end"},
                           {"io_breakdown",
                            {{"available", false}, {"reason", "io_events_not_observed"}}}});
            for (const char* metric : {"thread_cpu_ns", "cycles", "instructions"}) {
                result[metric] = nullptr;
                const bool supported = std::string(metric) == "thread_cpu_ns" ||
                                       header.value("perf_complete", false);
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
        consistent = consistent && computation + io + wait + gap == elapsed;
        result.update({{"valid", functional_valid && consistent},
                       {"start_ns", *start},
                       {"end_ns", *end},
                       {"elapsed_ns", elapsed},
                       {"computation_ns", computation},
                       {"io_ns", io},
                       {"wait_ns", wait},
                       {"gap_ns", gap},
                       {"segments", segments},
                       {"end_definition", "successful_application_call_end"}});
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
        if (start_event->contains("heap") && !start_event->at("heap").is_null())
            result["heap_peak_bytes"] = start_event->at("heap").at("live");
        for (const auto* e : events) {
            if (time(*e) <= *start || time(*e) > *end || !e->contains("heap") ||
                e->at("heap").is_null())
                continue;
            const auto peak = e->at("heap").at("interval_peak").get<std::uint64_t>();
            if (result["heap_peak_bytes"].is_null() ||
                peak > result["heap_peak_bytes"].get<std::uint64_t>())
                result["heap_peak_bytes"] = peak;
        }
        if (!consistent)
            result["reason"] = "boundary nesting/order or interval conservation failed";
        results.push_back(result);
    }
    return results;
}

} // namespace turtle::report
