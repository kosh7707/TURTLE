#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace turtle::report::detail {

using Json = nlohmann::json;

inline bool perf_scope(const Json& value) {
    return value.is_string() &&
           (value.get_ref<const std::string&>() == "user" ||
            value.get_ref<const std::string&>() == "user+kernel");
}

inline Json value_or_null(const Json& object, std::string_view key) {
    const auto name = std::string(key);
    return object.contains(name) ? object.at(name) : Json(nullptr);
}

struct PerfCondition {
    Json controls;
    Json support;
    bool complete = false;
};

// Only stable requested/applied state belongs to a condition identity.  Error
// stage, errno and prose explain one attempt; they must not split report groups.
inline bool complete_perf_condition(const Json& controls, const Json& support) {
    if (!controls.is_object() || !support.is_object() ||
        !controls.contains("perf") || !controls.contains("perf_scope") ||
        !support.contains("perf_requested_scope") || !support.contains("perf_status") ||
        !support.contains("perf_effective_scope"))
        return false;
    const auto& enabled = controls.at("perf");
    const auto& requested = controls.at("perf_scope");
    const auto& measured_requested = support.at("perf_requested_scope");
    const auto& status = support.at("perf_status");
    const auto& effective = support.at("perf_effective_scope");
    if (!enabled.is_boolean() || !perf_scope(requested) ||
        !perf_scope(measured_requested) || requested != measured_requested)
        return false;

    if (status == "available")
        return enabled.get<bool>() && perf_scope(effective) && effective == requested;
    return effective.is_null() &&
           ((status == "disabled" && !enabled.get<bool>()) ||
            (status == "unsupported" && enabled.get<bool>()));
}

inline bool has_explicit_perf_condition(const Json& header) {
    const auto config = header.value("config", Json::object());
    const auto capabilities = header.value("capabilities", Json::object());
    return config.contains("perf_scope") || capabilities.contains("perf_requested_scope") ||
           capabilities.contains("perf_status") || capabilities.contains("perf_effective_scope");
}

inline PerfCondition perf_condition(const Json& header) {
    const auto config = header.value("config", Json::object());
    const auto capabilities = header.value("capabilities", Json::object());
    Json support = {{"perf_requested_scope", value_or_null(capabilities, "perf_requested_scope")},
                    {"perf_status", value_or_null(capabilities, "perf_status")}};
    // Keep the historical all-missing lookup shape byte-compatible, but do not turn a
    // partially declared contract's missing effective scope into an explicit null.
    if (capabilities.contains("perf_effective_scope") || !has_explicit_perf_condition(header))
        support["perf_effective_scope"] = value_or_null(capabilities, "perf_effective_scope");
    PerfCondition result{
        {{"perf", value_or_null(config, "perf")},
         {"perf_scope", value_or_null(config, "perf_scope")}},
        std::move(support), false};
    result.complete = complete_perf_condition(result.controls, result.support);
    return result;
}

inline Json stable_capabilities(const Json& header) {
    auto capabilities = header.value("capabilities", Json::object());
    if (!has_explicit_perf_condition(header))
        return capabilities;
    capabilities.erase("perf_failure_stage");
    capabilities.erase("perf_error_number");
    capabilities.erase("perf_note");
    return capabilities;
}

} // namespace turtle::report::detail
