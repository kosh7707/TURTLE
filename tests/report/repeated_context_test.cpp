#include "report/repeated_context.hpp"
#include "report/report.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using J = nlohmann::json;
using turtle::report::RepeatedContextInput;

J dimensions() {
    return {{"role", "client"},
            {"profile_hash", "profile"},
            {"environment_hash", "environment"},
            {"mode", "timing"},
            {"client_adapter", "adapter-a"},
            {"server_adapter", "fixed-peer"},
            {"library", "library-a"},
            {"library_version", "1"},
            {"build_options", "fixture"},
            {"measurement_contract_revision", 2},
            {"peer_measurement_contract_revision", 2},
            {"peer_verified", true},
            {"peer_valid", true},
            {"automatic_comparison_identity_complete", true},
            {"run_controls", {{"channel_observer", true}, {"connections", 8}}}};
}

RepeatedContextInput context(const std::filesystem::path& run, std::uint64_t sample,
                             std::vector<double> elapsed, bool missing_cpu = false) {
    std::vector<J> partitions;
    for (std::size_t i = 0; i < elapsed.size(); ++i)
        partitions.push_back({{"connection", i}, {"valid", true}, {"elapsed_ns", elapsed[i]},
                              {"thread_cpu_ns", missing_cpu && i == 0 ? J(nullptr)
                                                                       : J(elapsed[i])}});
    return {run,
            run / ("sample-" + std::to_string(sample)) / "client.jsonl",
            sample,
            "client",
            1,
            elapsed.size(),
            0,
            true,
            true,
            true,
            false,
            true,
            {},
            std::string("success"),
            dimensions(),
            std::move(partitions),
            {}};
}

turtle::report::AuthoritativeLedger ledger(const std::filesystem::path& run,
                                            std::size_t requested) {
    turtle::report::AuthoritativeLedger value;
    value.root = run;
    value.requested = requested;
    for (std::size_t i = 1; i <= requested; ++i)
        value.attempts.emplace(i, turtle::report::NetworkAttempt{
                                      i, true, "success", J::array()});
    value.run_summary = {{"requested", requested}, {"started", requested},
                         {"success", requested},   {"timeout", 0},
                         {"error", 0},             {"incomplete", 0},
                         {"not_attempted", 0},     {"missing_artifacts", 0}};
    return value;
}
} // namespace

int main(int argc, char** argv) {
    using namespace turtle::report;
    assert(argc == 2);
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-repeated-context-" + std::to_string(getpid()));
    const auto study_root = root / "study";
    const auto run_root = study_root / "run";
    std::filesystem::create_directories(run_root);

    RepeatedStudyInput study{study_root,
                             study_root / "study.json",
                             "verified",
                             study_root,
                             {run_root},
                             {run_root},
                             true,
                             {}};
    RepeatedRunInput run{run_root,
                         run_root / "attempts.jsonl",
                         ledger(run_root, 2),
                         "verified",
                         study_root,
                         1,
                         1,
                         {}};
    auto a = context(run_root, 1, {1, 1, 1, 1, 1, 101, 101, 101});
    auto b = context(run_root, 2, {11, 11, 11, 11, 11, 11, 11, 11}, true);
    const auto summary = repeated_context_summary("study_root", {study}, {run}, {a, b});
    assert(summary["type"] == "turtle-repeated-context-summary");
    assert(summary["schema"] == 1 && summary["aggregation_policy"] == "context-stq2-v1");
    assert(summary["estimand"] == "stq2_of_context_stq2");
    assert(summary["selection_scope"] == "study_root");
    assert(summary["studies"].size() == 1 && summary["runs"].size() == 1);
    assert(summary["runs"][0]["denominators"]["requested"] == 2);
    assert(summary["contexts"].size() == 2);
    assert(summary["contexts"][0]["metrics"]["elapsed_ns"]["expected_count"] == 8);
    assert(summary["contexts"][0]["metrics"]["elapsed_ns"]["values"][0]["connection"] == 0);
    assert(summary["contexts"][0]["metrics"]["elapsed_ns"]["inner_statistics"]["stq2"] == 1);
    assert(summary["contexts"][1]["metrics"]["elapsed_ns"]["inner_statistics"]["stq2"] == 11);
    assert(summary["contexts"][1]["metrics"]["thread_cpu_ns"]["complete"] == false);
    assert(summary["contexts"][1]["metrics"]["thread_cpu_ns"]["missing_count"] == 1);
    assert(summary["contexts"][1]["metrics"]["thread_cpu_ns"]["inner_statistics"].is_null());
    assert(summary["groups"].size() == 1);
    const auto& elapsed = summary["groups"][0]["metrics"]["elapsed_ns"];
    assert(elapsed["candidate_contexts"] == 2 && elapsed["eligible_contexts"] == 2);
    assert(elapsed["context_values"] == J::array({1, 11}));
    assert(elapsed["outer_statistics"]["stq2"] == 6);
    assert(elapsed["outer_statistics"]["count"] == 2);
    assert(summary["groups"][0]["metrics"]["thread_cpu_ns"]["eligible_contexts"] == 1);
    assert(summary["comparisons"].empty());
    assert(summary["batch_diagnostics"][0].contains("batch_stq2_range"));

    // A verified study namespace permits only context-unit, fixed-peer comparisons.
    const auto run_b_root = study_root / "run-b";
    auto study_pair = study;
    study_pair.listed_run_roots = {run_root, run_b_root};
    study_pair.discovered_run_roots = {run_root, run_b_root};
    auto run_a = run;
    auto run_b = run;
    run_b.root = run_b_root;
    run_b.ledger_path = run_b_root / "attempts.jsonl";
    run_b.ledger = ledger(run_b_root, 2);
    auto a1 = context(run_root, 1, {1, 1});
    auto a2 = context(run_root, 2, {3, 3});
    auto b1 = context(run_b_root, 1, {5, 5});
    auto b2 = context(run_b_root, 2, {7, 7});
    for (auto* candidate : {&b1, &b2}) {
        candidate->dimensions["client_adapter"] = "adapter-b";
        candidate->dimensions["library"] = "library-b";
    }
    auto server_context = [](RepeatedContextInput value) {
        value.role = "server";
        value.source.replace_filename("server.jsonl");
        value.dimensions["role"] = "server";
        return value;
    };
    const auto paired = repeated_context_summary(
        "study_root", {study_pair}, {run_a, run_b},
        {a1, a2, b1, b2, server_context(a1), server_context(a2), server_context(b1),
         server_context(b2)});
    const std::vector<double> expected_a{1, 3}, expected_b{5, 7};
    const auto expected_compare = compare(expected_a, expected_b, 1, 2000);
    bool saw_elapsed = false;
    for (const auto& comparison : paired["comparisons"]) {
        assert(comparison["resampling_unit"] == "context");
        assert(comparison["seed"] == 1 && comparison["replicates"] == 2000);
        assert(comparison["assumption"] == "independent_contexts_within_observed_batch");
        if (comparison["metric"] == "elapsed_ns") {
            assert(comparison["context_count_a"] == 2 && comparison["context_count_b"] == 2);
            assert(comparison["difference_b_minus_a_ns"] == expected_compare.difference);
            assert(comparison["lower_95_ns"] == expected_compare.lower);
            assert(comparison["upper_95_ns"] == expected_compare.upper);
            saw_elapsed = true;
        }
    }
    assert(saw_elapsed);
    const auto partial_pair = repeated_context_summary(
        "partial", {study_pair}, {run_a, run_b},
        {a1, a2, b1, b2, server_context(a1), server_context(a2), server_context(b1),
         server_context(b2)});
    assert(partial_pair["comparisons"].empty());
    for (const auto& candidate : partial_pair["contexts"])
        assert(std::find(candidate["reasons"].begin(), candidate["reasons"].end(),
                         "selection_scope_partial") != candidate["reasons"].end());
    for (const auto& group : partial_pair["groups"])
        for (const auto& metric : group["metrics"])
            assert(metric["automatic_comparison_eligible"] == false);

    // K=1 remains visible but is never silently promoted into repeated-context statistics.
    auto singleton = context(run_root, 1, {0});
    auto singleton_run = run;
    singleton_run.ledger = ledger(run_root, 1);
    const auto one = repeated_context_summary("run_root", {}, {singleton_run}, {singleton});
    assert(one["contexts"][0]["status"] == "excluded");
    assert(one["contexts"][0]["execution_complete"] == true);
    assert(one["contexts"][0]["reasons"] == J::array({"insufficient_connections"}));
    assert(one["contexts"][0]["metrics"]["elapsed_ns"]["values"][0]["value"] == 0);
    assert(one["contexts"][0]["metrics"]["elapsed_ns"]["complete"] == true);
    assert(one["contexts"][0]["metrics"]["elapsed_ns"]["inner_statistics"].is_null());
    assert(one["groups"][0]["metrics"]["elapsed_ns"]["context_values"].empty());

    auto lookup = context(run_root, 1, {4, 5});
    lookup.lookup_scenario = true;
    const auto lookup_view =
        repeated_context_summary("run_root", {}, {singleton_run}, {lookup});
    assert(lookup_view["contexts"][0]["status"] == "excluded");
    assert(lookup_view["contexts"][0]["metrics"]["elapsed_ns"]["complete"] == true);
    assert(lookup_view["contexts"][0]["metrics"]["elapsed_ns"]["inner_statistics"].is_null());

    auto unknown_k = context(run_root, 1, {4, 5});
    unknown_k.measured_connections.reset();
    const auto unknown_view =
        repeated_context_summary("run_root", {}, {singleton_run}, {unknown_k});
    assert(unknown_view["contexts"][0]["measured_connections"].is_null());
    assert(unknown_view["contexts"][0]["metrics"]["elapsed_ns"]["expected_count"].is_null());
    assert(unknown_view["contexts"][0]["metrics"]["elapsed_ns"]["values"].empty());

    auto warmed = context(run_root, 1, {4, 5});
    warmed.warmups = 1;
    warmed.partitions[0]["connection"] = 1;
    warmed.partitions[1]["connection"] = 2;
    const auto warmed_view =
        repeated_context_summary("run_root", {}, {singleton_run}, {warmed});
    assert(warmed_view["contexts"][0]["metrics"]["elapsed_ns"]["values"][0]
                              ["connection"] == 1);
    assert(warmed_view["contexts"][0]["metrics"]["elapsed_ns"]["values"][1]
                              ["connection"] == 2);

    auto extra = context(run_root, 1, {4, 5});
    extra.partitions.push_back({{"connection", 99}, {"valid", true}, {"elapsed_ns", 6},
                                {"thread_cpu_ns", 6}});
    const auto extra_view =
        repeated_context_summary("run_root", {}, {singleton_run}, {extra});
    assert(extra_view["contexts"][0]["status"] == "excluded");
    assert(std::find(extra_view["contexts"][0]["reasons"].begin(),
                     extra_view["contexts"][0]["reasons"].end(),
                     "incomplete_connections") != extra_view["contexts"][0]["reasons"].end());

    auto diagnostic_only = context(run_root, 1, {4, 5});
    diagnostic_only.comparison_condition_complete = false;
    auto diagnostic_run = singleton_run;
    diagnostic_run.ledger = ledger(run_root, 1);
    const auto diagnostic =
        repeated_context_summary("run_root", {}, {diagnostic_run}, {diagnostic_only});
    assert(!diagnostic["groups"][0]["metrics"]["elapsed_ns"]
                          ["outer_statistics"].is_null());
    assert(diagnostic["groups"][0]["metrics"]["elapsed_ns"]
                     ["automatic_comparison_eligible"] == false);

    const auto quoted = std::string("\"") + argv[1] + "\"";
    const auto stderr_path = root / "usage.stderr";
    int status = std::system((quoted + " x y --unknown 2>\"" + stderr_path.string() +
                              "\" >/dev/null")
                                 .c_str());
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 2);
    std::ifstream usage_file(stderr_path);
    const std::string usage((std::istreambuf_iterator<char>(usage_file)),
                            std::istreambuf_iterator<char>());
    assert(usage.find("[--repeated-context]") != std::string::npos);

    std::filesystem::remove_all(root);
}
