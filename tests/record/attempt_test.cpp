#include "record/record.hpp"

#include <array>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

int main() {
    using namespace turtle;
    const auto directory = std::filesystem::temp_directory_path() /
                           ("turtle-attempt-record-" + std::to_string(getpid()));
    std::filesystem::create_directory(directory);
    {
        record::AttemptWriter writer(directory.string(), 3,
                                     model::FailurePolicy::FixedAttempts);
        record::AttemptEntry success;
        success.attempt_id = 1;
        success.requested_count = 3;
        success.started = true;
        success.final_status = model::AttemptStatus::Success;
        success.failure_phase = model::FailurePhase::None;
        success.measurement_deadline_monotonic_ns = 1234;
        success.participants = {model::ParticipantKind::TlsClient,
                                model::ParticipantKind::TlsServer,
                                model::ParticipantKind::MockCa};
        success.artifact_names = {"server.jsonl", "client.jsonl", "lookup.jsonl",
                                  "ca.jsonl"};
        success.artifact_status = {model::ArtifactStatus::Complete,
                                   model::ArtifactStatus::Complete,
                                   model::ArtifactStatus::Complete,
                                   model::ArtifactStatus::Complete};
        success.connections = {0};
        writer.started(success);
        {
            std::ifstream durable(directory / record::attempts_filename);
            std::string config_line, started_line;
            assert(std::getline(durable, config_line));
            assert(std::getline(durable, started_line));
            assert(nlohmann::json::parse(started_line)["record_kind"] == "attempt_started");
        }
        writer.finished(success);

        record::AttemptEntry timeout = success;
        timeout.attempt_id = 2;
        timeout.final_status = model::AttemptStatus::Timeout;
        timeout.failure_phase = model::FailurePhase::Scenario;
        timeout.reason = "measurement deadline exceeded";
        timeout.secondary_reasons = {"forced child reap"};
        timeout.artifact_status[2] = model::ArtifactStatus::Partial;
        timeout.artifact_status[3] = model::ArtifactStatus::Missing;
        writer.started(timeout);
        writer.finished(timeout);

        record::AttemptEntry not_attempted;
        not_attempted.attempt_id = 3;
        not_attempted.requested_count = 3;
        const std::array entries{success, timeout, not_attempted};
        writer.summary(entries);
    }

    const auto ledger_path = directory / record::attempts_filename;
    std::ifstream before_input(ledger_path, std::ios::binary);
    const std::string before((std::istreambuf_iterator<char>(before_input)), {});
    bool exclusive_create_failed = false;
    try {
        record::AttemptWriter duplicate(directory.string(), 3,
                                        model::FailurePolicy::FixedAttempts);
    } catch (const std::runtime_error&) {
        exclusive_create_failed = true;
    }
    assert(exclusive_create_failed);
    std::ifstream after_input(ledger_path, std::ios::binary);
    const std::string after((std::istreambuf_iterator<char>(after_input)), {});
    assert(after == before);

    std::ifstream input(ledger_path);
    std::vector<nlohmann::json> rows;
    std::string line;
    while (std::getline(input, line))
        rows.push_back(nlohmann::json::parse(line));
    assert(rows.size() == 6);
    assert(rows.front()["record_kind"] == "run_config");
    assert(rows.front()["requested_count"] == 3);
    assert(rows[1]["record_kind"] == "attempt_started");
    assert(rows[1]["artifact_status"].size() == 4);
    assert(rows[1]["artifacts"]["server.jsonl"] == "complete");
    assert(rows[1]["artifacts"]["client.jsonl"] == "complete");
    assert(rows[4]["artifacts"]["lookup.jsonl"] == "partial");
    assert(rows[4]["artifacts"]["ca.jsonl"] == "missing");
    assert(rows[4]["reason"] == "measurement deadline exceeded");
    assert(rows[4]["secondary_reasons"][0] == "forced child reap");
    const auto& summary = rows.back();
    assert(summary["requested"] == 3 && summary["started"] == 2);
    assert(summary["success"] == 1 && summary["timeout"] == 1);
    assert(summary["error"] == 0 && summary["incomplete"] == 0);
    assert(summary["not_attempted"] == 1 && summary["missing_artifacts"] == 1);
    assert(summary["missing_artifact_rows"][0]["artifact_name"] == "ca.jsonl");
    assert(summary["missing_artifact_rows"][0]["artifact_index"] == 3);

    const auto legacy_directory = directory / "legacy";
    std::filesystem::create_directory(legacy_directory);
    {
        record::AttemptWriter legacy(legacy_directory.string(), 1,
                                     model::FailurePolicy::FailFast);
        record::AttemptEntry entry;
        entry.attempt_id = 1;
        entry.requested_count = 1;
        entry.started = true;
        entry.final_status = model::AttemptStatus::Incomplete;
        entry.participants = {model::ParticipantKind::MockCa};
        entry.artifact_status = {model::ArtifactStatus::Missing};
        legacy.started(entry);
        legacy.finished(entry);
        const std::array entries{entry};
        legacy.summary(entries);
    }
    std::ifstream legacy_input(legacy_directory / record::attempts_filename);
    std::vector<nlohmann::json> legacy_rows;
    while (std::getline(legacy_input, line))
        legacy_rows.push_back(nlohmann::json::parse(line));
    const auto& legacy_missing = legacy_rows.back()["missing_artifact_rows"][0];
    assert(legacy_missing["artifact_index"] == 0);
    assert(!legacy_missing.contains("artifact_name"));
    assert(!legacy_missing.contains("participant"));

    const auto invalid_directory = directory / "invalid";
    std::filesystem::create_directory(invalid_directory);
    record::AttemptWriter invalid(invalid_directory.string(), 1,
                                  model::FailurePolicy::FailFast);
    record::AttemptEntry bad;
    bad.started = true;
    bad.final_status = model::AttemptStatus::NotAttempted;
    bool threw = false;
    try {
        invalid.summary({&bad, 1});
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    assert(threw);

    const auto mismatch_directory = directory / "mismatch";
    std::filesystem::create_directory(mismatch_directory);
    record::AttemptWriter mismatch(mismatch_directory.string(), 1,
                                   model::FailurePolicy::FailFast);
    record::AttemptEntry mismatch_entry;
    mismatch_entry.started = true;
    mismatch_entry.artifact_names = {"client.jsonl"};
    bool mismatch_threw = false;
    try {
        mismatch.started(mismatch_entry);
    } catch (const std::invalid_argument&) {
        mismatch_threw = true;
    }
    assert(mismatch_threw);

    std::filesystem::remove_all(directory);
}
