#include "report/prototype.hpp"
#include "report/report.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}
Json header() {
    return {{"role", "client"},
            {"mode", "memory"},
            {"adapter_connection", {{"mode", "builtin"}}},
            {"config", {{"tls", {{"scenario", "handshake"}}}}},
            {"declaration", {{"internal_events", Json::array({"message_process"})}}},
            {"connections", Json::array({{{"index", 0}, {"warmup", false},
                                          {"scenario_completed", true},
                                          {"start_sequence", 1}, {"end_sequence", 8}}})}};
}
std::vector<Json> events() {
    std::vector<Json> result;
    const char* kinds[] = {"CALL_BEGIN", "IO_SEND_ENTER", "IO_SEND_RETURN", "CALL_END",
                           "WAIT_BEGIN", "WAIT_END", "CALL_BEGIN", "CALL_END"};
    const unsigned times[] = {100, 110, 130, 150, 155, 185, 190, 200};
    const unsigned cpus[] = {10, 20, 22, 40, 41, 42, 43, 50};
    const unsigned peaks[] = {1000, 9, 11, 15, 5, 5, 5, 5};
    for (unsigned i = 0; i < 8; ++i)
        result.push_back({{"connection", 0}, {"sequence", i + 1}, {"kind", kinds[i]},
                          {"location", "implementation_boundary"}, {"call", "handshake"},
                          {"monotonic_ns", times[i]}, {"thread_cpu_ns", cpus[i]},
                          {"result", 0}, {"heap", {{"live", 5}, {"interval_peak", peaks[i]}}}});
    return result;
}
void check_partition(const Json& part) {
    // Independently drawn intervals: computation [100,110), [130,150), [190,200);
    // socket [110,130); waiting [155,185); gaps [150,155), [185,190).
    require(part.at("elapsed_ns") == 100, "elapsed oracle");
    require(part.at("computation_ns") == 40, "computation attribution oracle");
    require(part.at("io_ns") == 20, "I/O attribution oracle");
    require(part.at("wait_ns") == 30, "waiting attribution oracle");
    require(part.at("gap_ns") == 10, "framework gap attribution oracle");
    require(part.at("thread_cpu_ns") == 40, "thread CPU difference oracle");
}
void run(const std::string& name) {
    auto h = header();
    auto rows = events();
    if (name == "partition") {
        auto part = turtle::report::partition(h, rows).at(0);
        check_partition(part);
        require(part.at("heap_peak_bytes") == 15, "pre-window peak must be excluded");
        // The oracle must detect an earlier endpoint, not merely conserved totals.
        h["connections"][0]["end_sequence"] = 7;
        bool detected = false;
        try { check_partition(turtle::report::partition(h, rows).at(0)); }
        catch (const std::runtime_error&) { detected = true; }
        require(detected, "oracle failed to detect shifted endpoint");
    } else if (name == "scenario_end") {
        h["measurement_contract_revision"] = 4;
        h["config"]["tls"] = {{"scenario", "client-request"}, {"application_bytes", 4}};
        h["connections"][0]["application_verified"] = true;
        rows[6]["call"] = rows[7]["call"] = "app_recv";
        rows[7]["result"] = 2;
        rows[7]["transferred"] = 4;
        auto bookkeeping = rows.back();
        bookkeeping["kind"] = "APPLICATION_READ_END";
        bookkeeping["sequence"] = 9;
        bookkeeping["monotonic_ns"] = 210;
        rows.push_back(bookkeeping);
        h["connections"][0]["end_sequence"] = 9;
        require(!turtle::report::partition(h, rows)[0]["primary_window"]["available"].get<bool>(),
                "post-API bookkeeping accepted as scenario completion");
        h["connections"][0]["end_sequence"] = 8;
        check_partition(turtle::report::partition(h, rows)[0]);
    } else if (name == "heap_missing") {
        rows[3]["heap"] = nullptr;
        const auto part = turtle::report::partition(h, rows).at(0);
        require(part.at("heap_peak_bytes").is_null(), "partial heap snapshots became a peak");
        require(part.at("heap_peak_reason") == "heap_snapshot_missing", "missing heap reason");
        for (auto& row : rows)
            row["heap"] = {{"live", 0}, {"interval_peak", 0}};
        require(turtle::report::partition(h, rows)[0]["heap_peak_bytes"] == 0,
                "observed zero heap is not missing");
    } else if (name == "heap_equal_time") {
        // An additional snapshot resets the interval peak even when the clock has
        // not ticked, and even when it is not a partition boundary.
        auto internal = rows.front();
        internal["kind"] = "INTERNAL_BEGIN";
        internal["location"] = "library_hook";
        internal["heap"]["interval_peak"] = 57;
        rows.insert(rows.begin() + 1, internal);
        for (std::size_t i = 0; i < rows.size(); ++i)
            rows[i]["sequence"] = i + 1;
        h["connections"][0]["end_sequence"] = rows.size();
        require(turtle::report::partition(h, rows)[0]["heap_peak_bytes"] == 57,
                "equal-time or non-boundary heap interval was lost");
    } else if (name == "heap_shared_rx_snapshot") {
        h["role"] = "server";
        rows[1]["kind"] = "IO_RECV_ENTER";
        rows[2]["kind"] = "IO_RECV_RETURN";
        rows[2]["transferred"] = 1;
        rows[2]["heap"]["interval_peak"] = 9999;
        auto kernel = rows[2];
        kernel["kind"] = "KERNEL_RX";
        kernel["location"] = "kernel";
        rows.insert(rows.begin() + 3, kernel);
        for (std::size_t i = 0; i < rows.size(); ++i)
            rows[i]["sequence"] = i + 1;
        h["connections"][0]["start_sequence"] = 3;
        h["connections"][0]["end_sequence"] = rows.size();
        require(turtle::report::partition(h, rows)[0]["heap_peak_bytes"] == 15,
                "shared first-receive snapshot imported pre-window peak");
    } else if (name == "io_missing") {
        rows.erase(rows.begin() + 1, rows.begin() + 3);
        const auto part = turtle::report::partition(h, rows).at(0);
        require(!part.at("valid").get<bool>(), "missing I/O events became computation");
        require(part.at("io_ns").is_null(), "missing I/O became zero");
        require(!part.at("io_breakdown").at("available").get<bool>(), "missing I/O available");
    } else if (name == "span_cpu_missing" || name == "span_order") {
        h["mode"] = "trace";
        rows.resize(2);
        for (auto& row : rows) {
            row["location"] = "library_hook";
            row["trace_operation"] = "message_process";
            row["message_type"] = 20;
            row["message_id"] = 7;
        }
        rows[0]["kind"] = "INTERNAL_BEGIN";
        rows[1]["kind"] = "INTERNAL_END";
        if (name == "span_cpu_missing") {
            rows[1].erase("thread_cpu_ns");
            const auto p = turtle::report::prototype_observations(h, rows, 0);
            const auto& span = p.at("internal_spans").at(0);
            require(span.at("elapsed_ns") == 10, "missing CPU discarded elapsed");
            require(span.at("thread_cpu_ns").is_null(), "missing CPU became zero");
            require(span.at("thread_cpu_reason") == "thread_cpu_snapshot_missing", "CPU reason");
        } else {
            rows[1]["monotonic_ns"] = 90;
            const auto p = turtle::report::prototype_observations(h, rows, 0);
            require(p.at("internal_spans_status") == "missing", "regressed span available");
            require(!p.at("internal_spans_complete").get<bool>(), "regressed span complete");
        }
    } else {
        throw std::runtime_error("unknown evidence case");
    }
}
} // namespace
int main(int argc, char** argv) {
    try {
        require(argc == 2, "expected case name");
        run(argv[1]);
        std::cout << "PASS: " << argv[1] << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
