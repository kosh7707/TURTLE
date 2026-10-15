#include "lifecycle/lifecycle.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fixture {
using nlohmann::json;

enum class SendFault {
    None,
    DelaySampleTwoResponse,
    DelayAbortFlush,
    RejectFlushed,
    DelaySampleTwoResponseRejectFlushed
};

pid_t director_pid = -1;
int fork_call = 0;
int fail_fork_call = 0;
bool check_attempt_boundary = false;
SendFault send_fault = SendFault::None;
bool force_nonzero_after_flushed = false;
bool child_sent_flushed = false;
bool obscure_one_normal_reap = false;
bool obscured_reap = false;
bool rewrite_ca_footer_after_reap = false;
bool ca_footer_rewritten = false;
std::filesystem::path ca_footer_path;
std::vector<pid_t> owned;
struct HeaderPrefix {
    std::array<unsigned char, 16> bytes{};
    std::size_t used = 0;
    bool unrelated = false;
    bool delayed = false;
};
std::array<HeaderPrefix, 4096> received_prefixes{};

void require(bool value, const std::string& reason) {
    if (!value) throw std::runtime_error(reason);
}

std::uint16_t read_u16(const unsigned char* p) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(p[0]) << 8U) | p[1]);
}

std::uint64_t read_u64(const unsigned char* p) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i != 8; ++i) value = (value << 8U) | p[i];
    return value;
}

void require_gone(pid_t pid, const char* boundary) {
    errno = 0;
    require(::kill(pid, 0) == -1 && errno == ESRCH,
            std::string("owned child still exists at ") + boundary);
}

void reset_faults() {
    fork_call = 0;
    fail_fork_call = 0;
    check_attempt_boundary = false;
    send_fault = SendFault::None;
    force_nonzero_after_flushed = false;
    child_sent_flushed = false;
    obscure_one_normal_reap = false;
    obscured_reap = false;
    rewrite_ca_footer_after_reap = false;
    ca_footer_rewritten = false;
    ca_footer_path.clear();
    received_prefixes.fill({});
    owned.clear();
}

void require_all_reaped() {
    for (const pid_t pid : owned) {
        require_gone(pid, "run return");
        int status = 0;
        errno = 0;
        require(::waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD,
                "owned child remained waitable after run return");
    }
}

std::vector<json> lines(const std::filesystem::path& path) {
    std::ifstream input(path);
    require(static_cast<bool>(input), "missing ledger: " + path.string());
    std::vector<json> rows;
    std::string line;
    while (std::getline(input, line)) if (!line.empty()) rows.push_back(json::parse(line));
    return rows;
}

json final_for(const std::vector<json>& rows, std::uint64_t attempt) {
    for (const auto& row : rows)
        if (row.value("record_kind", "") == "attempt_final" &&
            row.value("attempt_id", std::uint64_t{}) == attempt)
            return row;
    throw std::runtime_error("attempt_final row missing");
}

json summary(const std::vector<json>& rows) {
    for (const auto& row : rows)
        if (row.value("record_kind", "") == "run_summary") return row;
    throw std::runtime_error("run_summary row missing");
}

turtle::model::RunConfig base(const char* adapters, const std::filesystem::path& output,
                              const std::filesystem::path& object) {
    turtle::model::RunConfig config;
    config.client_adapter = config.server_adapter = "mock";
    config.adapter_directory = adapters;
    config.output_directory = output.string();
    config.samples = 1;
    config.failure_policy = turtle::model::FailurePolicy::FixedAttempts;
    config.timeout_ms = 180;
    config.flush_grace_ms = 100;
    config.perf = false;
    config.pin_cores = false;
    config.calibration_samples = 2;
    config.lookup.enabled = true;
    config.lookup.object_file = object.string();
    return config;
}

void normal_timeout_normal(const char* adapters, const std::filesystem::path& root,
                           const std::filesystem::path& object) {
    reset_faults();
    check_attempt_boundary = true;
    send_fault = SendFault::DelaySampleTwoResponse;
    auto config = base(adapters, root / "normal-timeout-normal", object);
    config.samples = 3;
    config.timeout_ms = 120;
    config.flush_grace_ms = 40;
    require(turtle::lifecycle::run(config) != 0, "timeout bundle unexpectedly succeeded");
    require_all_reaped();

    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    require(final_for(rows, 1).at("final_status") == "success", "attempt 1 not successful");
    const auto timed_out = final_for(rows, 2);
    require(timed_out.at("final_status") == "timeout", "attempt 2 did not retain timeout");
    require(timed_out.at("failure_phase") == "scenario", "timeout phase was not scenario");
    require(final_for(rows, 3).at("final_status") == "success", "attempt 3 not successful");
    const auto totals = summary(rows);
    require(totals.at("requested") == 3 && totals.at("started") == 3 &&
            totals.at("success") == 2 && totals.at("timeout") == 1 &&
            totals.at("not_attempted") == 0,
            "normal-timeout-normal ledger denominator differs");

    for (const int attempt : {1, 3}) {
        char sample[32];
        std::snprintf(sample, sizeof sample, "sample-%06d", attempt);
        const auto received = std::filesystem::path(config.output_directory) / sample /
                              "lookup-0.received.bin";
        require(std::filesystem::exists(received) && std::filesystem::file_size(received) > 44,
                "successful attempt lacks actual lookup TCP bytes");
    }
}

void partial_fork(const char* adapters, const std::filesystem::path& root,
                  const std::filesystem::path& object, int failed_call) {
    reset_faults();
    fail_fork_call = failed_call;
    auto config = base(adapters, root / ("fork-" + std::to_string(failed_call)), object);
    require(turtle::lifecycle::run(config) != 0, "partial fork failure accepted");
    require_all_reaped();
    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    const auto final = final_for(rows, 1);
    require(final.at("final_status") == "error" && final.at("failure_phase") == "startup",
            "partial fork did not retain startup error");
    require(final.at("artifacts").size() == 4 &&
            final.at("artifacts").contains("server.jsonl") &&
            final.at("artifacts").contains("client.jsonl") &&
            final.at("artifacts").contains("lookup.jsonl") &&
            final.at("artifacts").contains("ca.jsonl"),
            "partial fork ledger lost a required raw artifact slot");
    const auto totals = summary(rows);
    require(totals.at("requested") == 1 && totals.at("started") == 1 &&
            totals.at("error") == 1 && totals.at("not_attempted") == 0,
            "partial fork denominator differs");
    require(totals.at("missing_artifacts").get<int>() > 0,
            "missing child raw artifacts disappeared from the denominator");
}

void error_survives_late_cleanup(const char* adapters, const std::filesystem::path& root,
                                 const std::filesystem::path& object) {
    reset_faults();
    send_fault = SendFault::DelayAbortFlush;
    ::setenv("TURTLE_MOCK_VERIFY_FAIL", "1", 1);
    auto config = base(adapters, root / "error-late-cleanup", object);
    config.timeout_ms = 100;
    config.flush_grace_ms = 350;
    require(turtle::lifecycle::run(config) != 0, "mock verification error accepted");
    ::unsetenv("TURTLE_MOCK_VERIFY_FAIL");
    require_all_reaped();
    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    const auto final = final_for(rows, 1);
    require(final.at("final_status") == "error", "late cleanup overwrote first error");
    require(final.at("reason").get<std::string>().find("verification") != std::string::npos,
            "first execution reason was not retained");
    const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    require(now > final.at("measurement_deadline_monotonic_ns").get<std::int64_t>(),
            "fixture cleanup did not pass the measurement deadline");
}

void flush_failure(const char* adapters, const std::filesystem::path& root,
                   const std::filesystem::path& object, bool timeout_first) {
    reset_faults();
    send_fault = timeout_first ? SendFault::DelaySampleTwoResponseRejectFlushed
                               : SendFault::RejectFlushed;
    auto config = base(adapters, root / (timeout_first ? "timeout-flush" : "normal-flush"), object);
    config.timeout_ms = 120;
    config.flush_grace_ms = 50;
    // The response-delay wrapper targets sample 2. The first attempt rejects FLUSHED and the
    // second combines a timeout with the same rejection to prove precedence.
    config.samples = timeout_first ? 2 : 1;
    require(turtle::lifecycle::run(config) != 0, "flush failure accepted");
    require_all_reaped();
    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    const auto final = final_for(rows, timeout_first ? 2 : 1);
    require(final.at("final_status") == (timeout_first ? "timeout" : "incomplete"),
            "flush failure precedence differs");
    if (!timeout_first)
        require(final.at("reason").get<std::string>().find("control message send failed") !=
                    std::string::npos,
                "child flush diagnostic was replaced by a generic parent reason");
    if (timeout_first) {
        const auto totals = summary(rows);
        require(totals.at("requested") == totals.at("started") &&
                totals.at("started") == totals.at("incomplete").get<int>() +
                                         totals.at("timeout").get<int>(),
                "missing-child raw denominator is inconsistent");
    }
}

void nonzero_after_flushed(const char* adapters, const std::filesystem::path& root,
                           const std::filesystem::path& object) {
    reset_faults();
    force_nonzero_after_flushed = true;
    auto config = base(adapters, root / "nonzero-after-flushed", object);
    require(turtle::lifecycle::run(config) != 0,
            "nonzero participant exit after FLUSHED was accepted");
    require_all_reaped();
    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    const auto final = final_for(rows, 1);
    require(final.at("final_status") == "incomplete",
            "post-FLUSHED participant failure was not incomplete");
    require(final.at("reason").get<std::string>().find("unsuccessfully") != std::string::npos,
            "post-FLUSHED exit failure reason missing");
}

void unproven_normal_reap(const char* adapters, const std::filesystem::path& root,
                          const std::filesystem::path& object) {
    reset_faults();
    obscure_one_normal_reap = true;
    auto config = base(adapters, root / "unproven-normal-reap", object);
    config.samples = 3;
    require(turtle::lifecycle::run(config) != 0,
            "unproven child cleanup was reported as success");
    require(obscured_reap, "waitpid fixture did not obscure the completed child reap");
    require_all_reaped();
    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    const auto final = final_for(rows, 1);
    require(final.at("final_status") == "incomplete" &&
            final.at("failure_phase") == "exit",
            "unproven cleanup did not become an exit-phase incomplete attempt");
    const auto totals = summary(rows);
    require(totals.at("requested") == 3 && totals.at("started") == 1 &&
            totals.at("success") == 0 && totals.at("incomplete") == 1 &&
            totals.at("not_attempted") == 2,
            "fatal unproven-cleanup denominator differs");
    require(!std::filesystem::exists(std::filesystem::path(config.output_directory) /
                                     "sample-000002"),
            "fatal cleanup uncertainty started a later attempt");
}

void partial_required_artifact(const char* adapters, const std::filesystem::path& root,
                               const std::filesystem::path& object) {
    reset_faults();
    auto config = base(adapters, root / "partial-required-artifact", object);
    config.samples = 2;
    rewrite_ca_footer_after_reap = true;
    ca_footer_path = std::filesystem::path(config.output_directory) /
                     "sample-000001" / "ca.jsonl";
    require(turtle::lifecycle::run(config) != 0,
            "partial required CA artifact was reported as success");
    require(ca_footer_rewritten, "CA footer fixture did not run after the real child reap");
    require_all_reaped();
    const auto rows = lines(std::filesystem::path(config.output_directory) / "attempts.jsonl");
    const auto guarded = final_for(rows, 1);
    require(guarded.at("final_status") == "incomplete" &&
            guarded.at("failure_phase") == "flush",
            "partial required artifact did not downgrade normal completion");
    require(guarded.at("reason") == "required raw artifact is not complete: ca.jsonl",
            "required artifact guard reason differs");
    const auto& artifacts = guarded.at("artifacts");
    require(artifacts.at("server.jsonl") == "complete" &&
            artifacts.at("client.jsonl") == "complete" &&
            artifacts.at("lookup.jsonl") == "complete" &&
            artifacts.at("ca.jsonl") == "partial",
            "named artifact statuses do not isolate the partial CA footer");
    require(final_for(rows, 2).at("final_status") == "success",
            "fixed-attempt policy did not continue after artifact incompleteness");
    const auto totals = summary(rows);
    require(totals.at("started") == 2 && totals.at("success") == 1 &&
            totals.at("incomplete") == 1 && totals.at("not_attempted") == 0,
            "partial artifact denominator differs");
}
} // namespace fixture

extern "C" pid_t __real_fork();
extern "C" pid_t __wrap_fork() {
    using namespace fixture;
    ++fork_call;
    if (check_attempt_boundary && (fork_call == 4 || fork_call == 7)) {
        const std::size_t begin = static_cast<std::size_t>(fork_call == 4 ? 0 : 3);
        for (std::size_t i = begin; i != begin + 3; ++i)
            require_gone(owned.at(i), "next attempt fork");
    }
    if (fork_call == fail_fork_call) {
        errno = EAGAIN;
        return -1;
    }
    const pid_t result = __real_fork();
    if (result > 0) owned.push_back(result);
    return result;
}

extern "C" ssize_t __real_send(int, const void*, size_t, int);
extern "C" ssize_t __wrap_send(int fd, const void* data, size_t size, int flags) {
    using namespace fixture;
    const auto* bytes = static_cast<const unsigned char*>(data);
    if (send_fault == SendFault::DelayAbortFlush && ::getpid() == director_pid && size >= 16 &&
        bytes[0] == 'T' && bytes[1] == 'C' && bytes[2] == 'T' && bytes[3] == 'L' &&
        read_u16(bytes + 6) == 8) {
        std::this_thread::sleep_for(std::chrono::milliseconds(140));
    }
    if ((send_fault == SendFault::RejectFlushed ||
         send_fault == SendFault::DelaySampleTwoResponseRejectFlushed) &&
        ::getpid() != director_pid && size >= 16 &&
        bytes[0] == 'T' && bytes[1] == 'C' && bytes[2] == 'T' && bytes[3] == 'L' &&
        read_u16(bytes + 6) == 9) {
        errno = EIO;
        return -1;
    }
    const ssize_t result = __real_send(fd, data, size, flags);
    if (force_nonzero_after_flushed && ::getpid() != director_pid && result >= 0 && size >= 16 &&
        bytes[0] == 'T' && bytes[1] == 'C' && bytes[2] == 'T' && bytes[3] == 'L' &&
        read_u16(bytes + 6) == 9)
        child_sent_flushed = true;
    return result;
}

extern "C" ssize_t __real_recvmsg(int, struct msghdr*, int);
extern "C" ssize_t __wrap_recvmsg(int fd, struct msghdr* message, int flags) {
    const ssize_t result = __real_recvmsg(fd, message, flags);
    const auto* bytes = message && message->msg_iovlen
        ? static_cast<const unsigned char*>(message->msg_iov[0].iov_base) : nullptr;
    const bool delay_mode = fixture::send_fault == fixture::SendFault::DelaySampleTwoResponse ||
        fixture::send_fault == fixture::SendFault::DelaySampleTwoResponseRejectFlushed;
    if (delay_mode && result > 0 && bytes && fd >= 0 &&
        static_cast<std::size_t>(fd) < fixture::received_prefixes.size()) {
        auto& prefix = fixture::received_prefixes[static_cast<std::size_t>(fd)];
        const auto count = std::min<std::size_t>(static_cast<std::size_t>(result),
                                                prefix.bytes.size() - prefix.used);
        std::copy_n(bytes, count, prefix.bytes.begin() + prefix.used);
        prefix.used += count;
        if (prefix.used >= 4 && !prefix.unrelated &&
            !(prefix.bytes[0] == 'T' && prefix.bytes[1] == 'C' &&
              prefix.bytes[2] == 'A' && prefix.bytes[3] == '1'))
            prefix.unrelated = true;
        if (!prefix.unrelated && !prefix.delayed && prefix.used == prefix.bytes.size() &&
            fixture::read_u16(prefix.bytes.data() + 6) == 2 &&
            fixture::read_u64(prefix.bytes.data() + 8) == 2) {
            prefix.delayed = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    }
    return result;
}

extern "C" [[noreturn]] void __real__exit(int);
extern "C" [[noreturn]] void __wrap__exit(int status) {
    __real__exit(fixture::force_nonzero_after_flushed && fixture::child_sent_flushed && status == 0
                     ? 1
                     : status);
}

extern "C" pid_t __real_waitpid(pid_t, int*, int);
extern "C" pid_t __wrap_waitpid(pid_t pid, int* status, int options) {
    const pid_t result = __real_waitpid(pid, status, options);
    if (fixture::rewrite_ca_footer_after_reap && !fixture::ca_footer_rewritten &&
        ::getpid() == fixture::director_pid && fixture::owned.size() >= 3 &&
        pid == fixture::owned[2] && result == pid) {
        try {
            auto rows = fixture::lines(fixture::ca_footer_path);
            bool found = false;
            for (auto& row : rows) {
                if (row.value("record_kind", "") != "footer") continue;
                row["artifact_status"] = "partial";
                row["incomplete_reason"] = "test fixture changed footer after normal child exit";
                found = true;
            }
            fixture::require(found, "CA footer absent after normal child exit");
            std::ofstream output(fixture::ca_footer_path, std::ios::trunc);
            fixture::require(static_cast<bool>(output), "cannot rewrite CA footer fixture");
            for (const auto& row : rows) output << row.dump() << '\n';
            output.close();
            fixture::require(static_cast<bool>(output), "cannot flush CA footer fixture");
            fixture::ca_footer_rewritten = true;
        } catch (...) {
            // Leave the flag false; the test reports a deterministic fixture failure after run().
        }
    }
    if (fixture::obscure_one_normal_reap && !fixture::obscured_reap &&
        ::getpid() == fixture::director_pid && !fixture::owned.empty() &&
        pid == fixture::owned.front() && result == pid) {
        fixture::obscured_reap = true;
        errno = EIO;
        return -1;
    }
    return result;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    fixture::director_pid = ::getpid();
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-attempt-boundaries-" + std::to_string(::getpid()));
    try {
        std::filesystem::create_directories(root);
        const std::string object =
            "-----BEGIN CERTIFICATE-----\nTURTLE ATTEMPT BOUNDARY\n-----END CERTIFICATE-----\n";
        const auto object_path = root / "object.pem";
        std::ofstream(object_path, std::ios::binary).write(object.data(), object.size());
        fixture::normal_timeout_normal(argv[1], root, object_path);
        fixture::partial_fork(argv[1], root, object_path, 2);
        fixture::partial_fork(argv[1], root, object_path, 3);
        fixture::error_survives_late_cleanup(argv[1], root, object_path);
        fixture::flush_failure(argv[1], root, object_path, false);
        fixture::flush_failure(argv[1], root, object_path, true);
        fixture::nonzero_after_flushed(argv[1], root, object_path);
        fixture::unproven_normal_reap(argv[1], root, object_path);
        fixture::partial_required_artifact(argv[1], root, object_path);
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        ::unsetenv("TURTLE_MOCK_VERIFY_FAIL");
        std::cerr << error.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
