#include "report/repeated_context.hpp"

#include "report/report.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <tuple>

namespace turtle::report {
namespace {
using Json = nlohmann::json;

Json statistics_json(const std::vector<double>& values) {
    if (values.empty())
        return nullptr;
    const auto s = statistics(values);
    return {{"count", s.count},       {"minimum", s.minimum}, {"maximum", s.maximum},
            {"stq1", s.stq[0]},      {"stq2", s.stq[1]},     {"stq3", s.stq[2]}};
}

void normalize_reasons(std::vector<std::string>& reasons) {
    std::sort(reasons.begin(), reasons.end());
    reasons.erase(std::unique(reasons.begin(), reasons.end()), reasons.end());
}

Json denominators(const RepeatedRunInput& run) {
    Json result = {{"requested", nullptr}, {"started", nullptr},
                   {"success", nullptr},   {"timeout", nullptr},
                   {"error", nullptr},     {"incomplete", nullptr},
                   {"not_attempted", nullptr}, {"missing_artifacts", nullptr}};
    if (!run.ledger)
        return result;
    result["requested"] = run.ledger->requested;
    if (run.ledger->partial)
        return result;
    for (const char* field : {"requested", "started", "success", "timeout", "error",
                              "incomplete", "not_attempted", "missing_artifacts"})
        result[field] = run.ledger->run_summary.at(field);
    return result;
}

struct MetricResult {
    Json json;
    std::optional<double> representative;
};

MetricResult metric(const RepeatedContextInput& input, const char* name,
                    bool execution_complete, bool aggregate_eligible) {
    if (!input.measured_connections) {
        return {{{"complete", false},
                 {"expected_count", nullptr},
                 {"available_count", 0},
                 {"missing_count", 0},
                 {"invalid_count", 0},
                 {"reasons", Json::array({"metric_incomplete"})},
                 {"values", Json::array()},
                 {"inner_statistics", nullptr}},
                std::nullopt};
    }
    Json values = Json::array();
    std::size_t available = 0, missing = 0, invalid = 0;
    std::map<std::size_t, const Json*> by_connection;
    std::set<std::size_t> duplicates;
    for (const auto& part : input.partitions) {
        if (!part.contains("connection") || !part.at("connection").is_number_integer() ||
            part.at("connection").get<std::int64_t>() < 0)
            continue;
        const auto index = part.at("connection").get<std::size_t>();
        if (!by_connection.emplace(index, &part).second)
            duplicates.insert(index);
    }
    std::vector<double> admitted;
    admitted.reserve(*input.measured_connections);
    std::vector<std::string> reasons;
    for (std::size_t offset = 0; offset < *input.measured_connections; ++offset) {
        const auto index = input.warmups + offset;
        Json value = nullptr;
        const auto found = by_connection.find(index);
        if (duplicates.contains(index)) {
            ++invalid;
            reasons.push_back("metric_invalid");
        } else if (found == by_connection.end() || !found->second->contains(name) ||
                   found->second->at(name).is_null()) {
            ++missing;
            reasons.push_back("metric_missing");
        } else if (!found->second->at(name).is_number()) {
            ++invalid;
            reasons.push_back("metric_invalid");
        } else {
            const auto number = found->second->at(name).get<double>();
            if (!std::isfinite(number) || number < 0) {
                ++invalid;
                reasons.push_back("metric_invalid");
            } else {
                value = number;
                admitted.push_back(number);
                ++available;
            }
        }
        values.push_back({{"connection", index}, {"value", value}});
    }
    const bool complete = execution_complete && *input.measured_connections > 0 &&
                          available == *input.measured_connections;
    if (!complete)
        reasons.push_back("metric_incomplete");
    auto stats = complete && aggregate_eligible ? statistics_json(admitted) : Json(nullptr);
    normalize_reasons(reasons);
    return {{{"complete", complete},
             {"expected_count", *input.measured_connections},
             {"available_count", available},
             {"missing_count", missing},
             {"invalid_count", invalid},
             {"reasons", reasons},
             {"values", values},
             {"inner_statistics", stats}},
            complete && aggregate_eligible
                ? std::optional<double>(stats.at("stq2").get<double>())
                : std::nullopt};
}

bool all_success(const RepeatedRunInput& run) {
    if (!run.ledger || run.ledger->partial)
        return false;
    const auto& summary = run.ledger->run_summary;
    return summary.at("success") == summary.at("requested") &&
           summary.at("missing_artifacts") == 0;
}

} // namespace

Json repeated_context_summary(std::string selection_scope,
                              std::vector<RepeatedStudyInput> studies,
                              std::vector<RepeatedRunInput> runs,
                              std::vector<RepeatedContextInput> inputs) {
    const auto path_order = [](const auto& a, const auto& b) {
        return a.root.string() < b.root.string();
    };
    std::sort(studies.begin(), studies.end(), path_order);
    std::sort(runs.begin(), runs.end(), path_order);
    std::sort(inputs.begin(), inputs.end(), [](const auto& a, const auto& b) {
        return std::tuple(a.run_root.string(), a.sample, a.role, a.source.string()) <
               std::tuple(b.run_root.string(), b.sample, b.role, b.source.string());
    });
    std::map<std::tuple<std::string, std::uint64_t, std::string>, std::size_t>
        context_identity_counts;
    for (const auto& input : inputs)
        ++context_identity_counts[{input.run_root.string(), input.sample, input.role}];

    Json result = {{"type", "turtle-repeated-context-summary"},
                   {"schema", 1},
                   {"aggregation_policy", "context-stq2-v1"},
                   {"estimand", "stq2_of_context_stq2"},
                   {"selection_scope", selection_scope},
                   {"studies", Json::array()},
                   {"runs", Json::array()},
                   {"contexts", Json::array()},
                   {"groups", Json::array()},
                   {"batch_diagnostics", Json::array()},
                   {"comparisons", Json::array()}};

    for (auto& study : studies) {
        normalize_reasons(study.reasons);
        Json listed = Json::array(), discovered = Json::array();
        for (const auto& path : study.listed_run_roots)
            listed.push_back(path.string());
        for (const auto& path : study.discovered_run_roots)
            discovered.push_back(path.string());
        result["studies"].push_back(
            {{"root", study.root.string()},
             {"manifest", study.manifest.string()},
             {"namespace_status", study.namespace_status},
             {"batch_namespace", study.batch_namespace
                                     ? Json(study.batch_namespace->string())
                                     : Json(nullptr)},
             {"listed_run_roots", listed},
             {"discovered_run_roots", discovered},
             {"coverage_complete", study.coverage_complete},
             {"reasons", study.reasons}});
    }

    std::map<std::string, std::size_t> run_indices;
    for (std::size_t i = 0; i < runs.size(); ++i)
        run_indices.emplace(runs[i].root.string(), i);

    struct ContextComputed {
        Json json;
        Json dimensions;
        std::string run_root;
        std::map<std::string, std::optional<double>> representatives;
    };
    std::vector<ContextComputed> computed;
    computed.reserve(inputs.size());
    for (const auto& input : inputs) {
        std::vector<std::string> reasons = input.reasons;
        const auto run_it = run_indices.find(input.run_root.string());
        const RepeatedRunInput* run = run_it == run_indices.end() ? nullptr : &runs[run_it->second];
        if (selection_scope == "partial" || selection_scope == "mixed")
            reasons.push_back("selection_scope_partial");
        if (!run || run->namespace_status == "unverified")
            reasons.push_back("batch_namespace_unverified");
        else if (run->namespace_status == "multiple")
            reasons.push_back("multiple_study_namespaces");
        if (!run || !input.parent_status)
            reasons.push_back("parent_status_unverified");
        else if (*input.parent_status != "success")
            reasons.push_back("parent_attempt_unsuccessful");
        if (!input.peer_verified || !input.peer_valid)
            reasons.push_back("missing_peer");
        if (!input.raw_valid)
            reasons.push_back("invalid_context");
        const bool duplicate_context_identity =
            context_identity_counts.at(
                {input.run_root.string(), input.sample, input.role}) > 1;
        if (duplicate_context_identity)
            reasons.push_back("invalid_context");
        if (input.lookup_scenario)
            reasons.push_back("unsupported_lookup_scenario");
        if (input.measured_connections && *input.measured_connections < 2)
            reasons.push_back("insufficient_connections");
        if (!input.measured_connections)
            reasons.push_back("incomplete_connections");

        std::set<std::size_t> expected;
        for (std::size_t i = 0; input.measured_connections && i < *input.measured_connections; ++i)
            expected.insert(input.warmups + i);
        std::set<std::size_t> observed;
        bool duplicate = false;
        bool extra = false;
        bool partitions_valid = true;
        for (const auto& part : input.partitions) {
            if (!part.contains("connection") || !part.at("connection").is_number_integer() ||
                part.at("connection").get<std::int64_t>() < 0)
                continue;
            const auto index = part.at("connection").get<std::size_t>();
            if (!expected.contains(index))
                extra = true;
            else if (!observed.insert(index).second)
                duplicate = true;
            if (expected.contains(index))
                partitions_valid = partitions_valid && part.value("valid", false);
        }
        if (duplicate)
            reasons.push_back("duplicate_connection");
        if (observed != expected || extra)
            reasons.push_back("incomplete_connections");
        normalize_reasons(reasons);
        const bool execution_complete = input.raw_valid && input.peer_verified && input.peer_valid &&
                                        input.parent_status && *input.parent_status == "success" &&
                                        input.measured_connections && observed == expected &&
                                        !extra && !duplicate && partitions_valid &&
                                        !duplicate_context_identity;
        const bool status_complete = execution_complete && !input.lookup_scenario &&
                                     *input.measured_connections >= 2;
        const auto elapsed = metric(input, "elapsed_ns", execution_complete, status_complete);
        const auto cpu = metric(input, "thread_cpu_ns", execution_complete, status_complete);
        Json dimensions = input.dimensions;
        dimensions.erase("connection");
        dimensions["aggregation_policy"] = "context-stq2-v1";
        dimensions["measured_connections"] = input.measured_connections
                                                   ? Json(*input.measured_connections)
                                                   : Json(nullptr);
        dimensions["warmups"] = input.warmups;
        dimensions["timeout_ms"] = dimensions.value("run_controls", Json::object())
                                         .value("timeout_ms", Json(nullptr));
        Json context = {
            {"id", {{"run_root", input.run_root.string()}, {"sample", input.sample},
                    {"role", input.role}}},
            {"source", input.source.string()},
            {"batch_namespace", run ? Json(run->batch_namespace.string()) : Json(nullptr)},
            {"batch", input.batch},
            {"measured_connections", input.measured_connections
                                         ? Json(*input.measured_connections)
                                         : Json(nullptr)},
            {"warmups", input.warmups},
            {"status", status_complete ? "complete" : "excluded"},
            {"execution_complete", execution_complete},
            {"reasons", reasons},
            {"metrics", {{"elapsed_ns", elapsed.json}, {"thread_cpu_ns", cpu.json}}}};
        computed.push_back({context, dimensions, input.run_root.string(),
                            {{"elapsed_ns", elapsed.representative},
                             {"thread_cpu_ns", cpu.representative}}});
        result["contexts"].push_back(std::move(context));
    }

    for (auto& run : runs) {
        std::vector<std::string> reasons = run.reasons;
        const auto expected = run.ledger ? Json(run.ledger->requested) : Json(nullptr);
        Json coverage = Json::object();
        bool raw_coverage = true;
        for (const char* role : {"client", "server"}) {
            std::size_t discovered = 0, execution = 0, elapsed = 0, cpu = 0;
            std::set<std::uint64_t> discovered_ids;
            bool duplicate_id = false;
            for (const auto& context : computed) {
                if (context.run_root != run.root.string() ||
                    context.json.at("id").at("role") != role)
                    continue;
                ++discovered;
                duplicate_id = duplicate_id ||
                               !discovered_ids
                                    .insert(context.json.at("id").at("sample").get<std::uint64_t>())
                                    .second;
                execution += context.json.at("execution_complete").get<bool>();
                elapsed += context.json.at("metrics").at("elapsed_ns").at("complete").get<bool>();
                cpu += context.json.at("metrics").at("thread_cpu_ns").at("complete").get<bool>();
            }
            if (run.ledger) {
                std::set<std::uint64_t> expected_ids;
                for (std::uint64_t id = 1; id <= run.ledger->requested; ++id)
                    expected_ids.insert(id);
                if (discovered_ids != expected_ids || duplicate_id ||
                    execution != run.ledger->requested)
                    raw_coverage = false;
            }
            coverage[role] = {{"expected_contexts", expected},
                              {"discovered_contexts", discovered},
                              {"execution_complete_contexts", execution},
                              {"metric_complete_contexts", {{"elapsed_ns", elapsed},
                                                             {"thread_cpu_ns", cpu}}}};
        }
        const bool complete = all_success(run) && raw_coverage;
        if (!raw_coverage)
            reasons.push_back("missing_raw");
        if (!complete)
            reasons.push_back("run_coverage_incomplete");
        normalize_reasons(reasons);
        result["runs"].push_back(
            {{"root", run.root.string()},
             {"ledger", run.ledger_path ? Json(run.ledger_path->string()) : Json(nullptr)},
             {"ledger_status", !run.ledger ? "absent" : run.ledger->partial ? "partial" : "complete"},
             {"namespace_status", run.namespace_status},
             {"batch_namespace", run.batch_namespace.string()},
             {"batch", run.batch ? Json(*run.batch) : Json(nullptr)},
             {"denominators", denominators(run)},
             {"coverage_complete", complete},
             {"reasons", reasons},
             {"role_coverage", coverage}});
    }

    // Study coverage includes every listed run's final ledger, bilateral raw, and K checks.
    for (auto& study : result["studies"]) {
        bool complete = study.at("coverage_complete").get<bool>();
        for (const auto& listed : study.at("listed_run_roots")) {
            const auto found = std::find_if(result["runs"].begin(), result["runs"].end(),
                                            [&](const Json& run) {
                                                return run.at("root") == listed;
                                            });
            complete = complete && found != result["runs"].end() &&
                       found->at("coverage_complete").get<bool>();
            if (found != result["runs"].end())
                complete = complete &&
                           std::find(found->at("reasons").begin(),
                                     found->at("reasons").end(),
                                     "study_manifest_mismatch") == found->at("reasons").end();
        }
        if (!complete) {
            auto reasons = study.at("reasons").get<std::vector<std::string>>();
            reasons.push_back("study_coverage_incomplete");
            normalize_reasons(reasons);
            study["reasons"] = reasons;
            study["coverage_complete"] = false;
        }
    }

    struct Group {
        Json dimensions;
        std::string batch_namespace;
        std::uint64_t batch = 0;
        std::vector<std::size_t> contexts;
    };
    std::map<std::string, Group> grouped;
    for (std::size_t i = 0; i < computed.size(); ++i) {
        const auto& context = computed[i];
        const auto batch_namespace = context.json.at("batch_namespace");
        if (batch_namespace.is_null())
            continue;
        const auto batch = context.json.at("batch").get<std::uint64_t>();
        const auto key = batch_namespace.dump() + ":" + std::to_string(batch) + ":" +
                         context.dimensions.dump();
        auto& group = grouped[key];
        group.dimensions = context.dimensions;
        group.batch_namespace = batch_namespace.get<std::string>();
        group.batch = batch;
        group.contexts.push_back(i);
    }

    std::size_t group_index = 0;
    for (const auto& [key, group] : grouped) {
        (void)key;
        Json item = {{"group_index", group_index},
                     {"batch_namespace", group.batch_namespace},
                     {"batch", group.batch},
                     {"dimensions", group.dimensions},
                     {"metrics", Json::object()}};
        for (const char* metric_name : {"elapsed_ns", "thread_cpu_ns"}) {
            std::vector<double> values;
            std::vector<std::string> exclusion;
            for (const auto context_index : group.contexts) {
                const auto& context = computed[context_index];
                if (const auto& value = context.representatives.at(metric_name); value)
                    values.push_back(*value);
                else
                    exclusion.push_back("metric_incomplete");
                if (!inputs[context_index].comparison_condition_complete) {
                    exclusion.insert(exclusion.end(),
                                     inputs[context_index].comparison_exclusion_reasons.begin(),
                                     inputs[context_index].comparison_exclusion_reasons.end());
                    if (inputs[context_index].comparison_exclusion_reasons.empty())
                        exclusion.push_back("invalid_context");
                }
                const auto run_index = run_indices.find(context.run_root);
                if (run_index == run_indices.end() ||
                    !result["runs"][run_index->second].at("coverage_complete").get<bool>())
                    exclusion.push_back("run_coverage_incomplete");
                if (run_index == run_indices.end() ||
                    runs[run_index->second].namespace_status == "unverified")
                    exclusion.push_back("batch_namespace_unverified");
                else if (runs[run_index->second].namespace_status == "multiple")
                    exclusion.push_back("multiple_study_namespaces");
            }
            if (values.size() < 2)
                exclusion.push_back("insufficient_contexts");
            if (selection_scope != "study_root")
                exclusion.push_back("selection_scope_partial");
            if (group.batch_namespace.empty())
                exclusion.push_back("batch_namespace_unverified");
            const auto study = std::find_if(result["studies"].begin(),
                                            result["studies"].end(), [&](const Json& item) {
                                                return item.at("batch_namespace").is_string() &&
                                                       item.at("batch_namespace") ==
                                                           group.batch_namespace;
                                            });
            if (study != result["studies"].end() &&
                !study->at("coverage_complete").get<bool>())
                exclusion.push_back("study_coverage_incomplete");
            normalize_reasons(exclusion);
            item["metrics"][metric_name] = {
                {"candidate_contexts", group.contexts.size()},
                {"eligible_contexts", values.size()},
                {"excluded_contexts", group.contexts.size() - values.size()},
                {"context_values", values},
                {"outer_statistics", statistics_json(values)},
                {"automatic_comparison_eligible", exclusion.empty()},
                {"comparison_exclusion_reasons", exclusion}};
        }
        result["groups"].push_back(std::move(item));
        ++group_index;
    }

    // Batch diagnostics compare descriptive StQ2 values only; no pooled confidence interval.
    std::map<std::string, Json> diagnostics;
    for (std::size_t gi = 0; gi < result["groups"].size(); ++gi) {
        const auto& group = result["groups"][gi];
        for (const char* metric : {"elapsed_ns", "thread_cpu_ns"}) {
            auto dimensions = group.at("dimensions");
            dimensions.erase("batch");
            const auto key = group.at("batch_namespace").dump() + dimensions.dump() + metric;
            auto& diagnostic = diagnostics[key];
            if (diagnostic.is_null())
                diagnostic = {{"dimensions", dimensions},
                              {"batch_namespace", group.at("batch_namespace")},
                              {"metric", metric}, {"batches", Json::array()},
                              {"batch_stq2_range", nullptr}};
            const auto& stats = group.at("metrics").at(metric).at("outer_statistics");
            diagnostic["batches"].push_back(
                {{"batch", group.at("batch")}, {"group_index", gi},
                 {"eligible_contexts", group.at("metrics").at(metric).at("eligible_contexts")},
                 {"stq2", stats.is_null() ? Json(nullptr) : stats.at("stq2")}});
        }
    }
    for (auto& [key, diagnostic] : diagnostics) {
        (void)key;
        std::vector<double> values;
        for (const auto& batch : diagnostic.at("batches"))
            if (!batch.at("stq2").is_null())
                values.push_back(batch.at("stq2").get<double>());
        if (!values.empty())
            diagnostic["batch_stq2_range"] =
                *std::max_element(values.begin(), values.end()) -
                *std::min_element(values.begin(), values.end());
        result["batch_diagnostics"].push_back(std::move(diagnostic));
    }

    for (std::size_t a = 0; a < result["groups"].size(); ++a) {
        for (std::size_t b = a + 1; b < result["groups"].size(); ++b) {
            auto da = result["groups"][a].at("dimensions");
            auto db = result["groups"][b].at("dimensions");
            if (result["groups"][a].at("batch_namespace") !=
                    result["groups"][b].at("batch_namespace") ||
                result["groups"][a].at("batch") != result["groups"][b].at("batch"))
                continue;
            const auto role = da.value("role", "");
            const char* own_adapter = role == "client" ? "client_adapter" : "server_adapter";
            for (const char* field : {own_adapter, "library", "library_version", "build_options"}) {
                da.erase(field);
                db.erase(field);
            }
            if (da != db)
                continue;
            for (const char* metric : {"elapsed_ns", "thread_cpu_ns"}) {
                const auto& ma = result["groups"][a].at("metrics").at(metric);
                const auto& mb = result["groups"][b].at("metrics").at(metric);
                if (!ma.at("automatic_comparison_eligible").get<bool>() ||
                    !mb.at("automatic_comparison_eligible").get<bool>())
                    continue;
                const auto av = ma.at("context_values").get<std::vector<double>>();
                const auto bv = mb.at("context_values").get<std::vector<double>>();
                const auto c = compare(av, bv, 1, 2000);
                result["comparisons"].push_back(
                    {{"group_a", a}, {"group_b", b}, {"metric", metric},
                     {"batch_namespace", result["groups"][a].at("batch_namespace")},
                     {"batch", result["groups"][a].at("batch")},
                     {"context_count_a", av.size()}, {"context_count_b", bv.size()},
                     {"difference_b_minus_a_ns", c.difference}, {"lower_95_ns", c.lower},
                     {"upper_95_ns", c.upper}, {"distinguishable", c.distinguishable},
                     {"method", "independent_context_percentile_bootstrap"},
                     {"resampling_unit", "context"}, {"seed", 1}, {"replicates", 2000},
                     {"estimand", "stq2_of_context_stq2"},
                     {"assumption", "independent_contexts_within_observed_batch"},
                     {"interpretation",
                      "exploratory_complete_execution_conditional_not_equivalence"}});
            }
        }
    }
    return result;
}

} // namespace turtle::report
