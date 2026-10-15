#include "report/report.hpp"
#include "report/window.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>

namespace {
using Json = nlohmann::json;

Json event(std::uint64_t sequence, std::uint64_t monotonic_ns, std::uint64_t thread_cpu_ns,
           std::string kind, std::string call, std::uint64_t call_id,
           std::uint64_t stream_begin = 0, std::uint64_t stream_end = 0,
           std::uint64_t transferred = 0, std::int64_t result = 0) {
    return {{"connection", 0},
            {"sequence", sequence},
            {"monotonic_ns", monotonic_ns},
            {"thread_cpu_ns", thread_cpu_ns},
            {"kind", std::move(kind)},
            {"call", std::move(call)},
            {"call_id", call_id},
            {"location", "framework"},
            {"stream_begin", stream_begin},
            {"stream_end", stream_end},
            {"transferred", transferred},
            {"result", result}};
}
} // namespace

int main() {
    using namespace turtle::report;
    const Json header = {
        {"type", "sample"},
        {"schema", 1},
        {"measurement_contract_revision", 1},
        {"sample", 1},
        {"batch", 1},
        {"role", "server"},
        {"valid", true},
        {"profile_hash", "window-profile"},
        {"environment_hash", "window-environment"},
        {"mode", "timing"},
        {"pinned_cpu", 2},
        {"perf_complete", true},
        {"loaded_context_size", 0},
        {"loaded_context_hash", ""},
        {"declaration", {{"library", "fixture"}, {"version", "1"},
                           {"build_options", "default"}, {"is_mock", true}}},
        {"capabilities", Json::object()},
        {"config", {{"tls", {{"framework_io", true}, {"application_bytes", 4}}},
                    {"channel_observer", true}, {"client_adapter", "fixture-client"},
                    {"server_adapter", "fixture-server"}, {"warmups", 0}}},
        {"availability", {{"io_events", {{"available", true}, {"reason", nullptr}}}}},
        {"connections", Json::array({{{"index", 0},
                                         {"warmup", false},
                                         {"application_verified", true},
                                         {"primary_window", {{"available", true},
                                                             {"reason", nullptr}}}}})}};
    std::vector<Json> events = {
        event(1, 100, 10, "CALL_BEGIN", "handshake", 1),
        event(2, 110, 15, "IO_RECV_ENTER", "handshake", 1),
        event(3, 120, 20, "IO_RECV_RETURN", "handshake", 1, 0, 5, 5),
        event(4, 125, 23, "IO_RECV_ENTER", "handshake", 1, 5, 5),
        event(5, 130, 25, "IO_RECV_RETURN", "handshake", 1, 5, 100, 95),
        event(6, 200, 60, "IO_SEND_ENTER", "handshake", 1, 0, 0),
        event(7, 220, 70, "IO_SEND_RETURN", "handshake", 1, 0, 60, 60),
        event(8, 240, 80, "IO_SEND_ENTER", "handshake", 1, 60, 60),
        event(9, 260, 90, "IO_SEND_RETURN", "handshake", 1, 60, 160, 100),
        event(10, 280, 100, "CALL_END", "handshake", 1),
        event(11, 300, 110, "CALL_BEGIN", "app_send", 2),
        event(12, 320, 120, "CALL_END", "app_send", 2, 0, 0, 4, 2),
    };
    events[5]["requested"] = 160;
    events[7]["requested"] = 100;
    const Json decoded = {
        {"connection", 0},
        {"decryption_complete", true},
        {"client_sent",
         {{"decryption_complete", true},
          {"records", Json::array({{{"index", 0}, {"stream_begin", 0},
                                      {"stream_end", 100}}})},
          {"messages", Json::array({{{"name", "ClientHello"}, {"records", {0}},
                                       {"record_stream_ranges",
                                        Json::array({{{"begin", 0}, {"end", 100}}})},
                                       {"bundled", false}}})}}},
        {"server_sent",
         {{"decryption_complete", true},
          {"records", Json::array({{{"index", 0}, {"stream_begin", 0}, {"stream_end", 40}},
                                     {{"index", 1}, {"stream_begin", 40}, {"stream_end", 46}},
                                     {{"index", 2}, {"stream_begin", 46}, {"stream_end", 100}},
                                     {{"index", 3}, {"stream_begin", 100}, {"stream_end", 120}},
                                     {{"index", 4}, {"stream_begin", 120},
                                      {"stream_end", 160}}})},
          {"messages", Json::array({{{"name", "ServerHello"}, {"records", {0}},
                                       {"record_stream_ranges",
                                        Json::array({{{"begin", 0}, {"end", 40}}})},
                                       {"bundled", false}},
                                      {{"name", "ChangeCipherSpec"}, {"records", {1}},
                                       {"record_stream_ranges",
                                        Json::array({{{"begin", 40}, {"end", 46}}})},
                                       {"bundled", false}},
                                      {{"name", "EncryptedExtensions"}, {"records", {2}},
                                       {"record_stream_ranges",
                                        Json::array({{{"begin", 46}, {"end", 100}}})},
                                       {"bundled", false}},
                                      {{"name", "Certificate"}, {"records", {2, 3}},
                                       {"record_stream_ranges",
                                        Json::array({{{"begin", 46}, {"end", 120}}})},
                                       {"bundled", true}},
                                      {{"name", "Finished"}, {"records", {4}},
                                       {"record_stream_ranges",
                                        Json::array({{{"begin", 120}, {"end", 160}}})},
                                       {"bundled", false}}})}}}};

    const auto connection = partition(header, events).at(0);
    const auto attribution =
        record_computation_attribution(header, events, decoded, connection);
    assert(attribution["available"] == true && attribution["reason"].is_null());
    assert(attribution["scope"] == "primary_window_computation_segments");
    assert(attribution["segments"].size() == 5);
    const auto& first = attribution["segments"][0];
    assert(first["segment_index"] == 0 && first["elapsed_ns"] == 5);
    assert(first["begin_event_sequence"] == 3 && first["end_event_sequence"] == 4);
    assert(first["thread_cpu_ns"] == 3 && first["thread_cpu_reason"].is_null());
    assert(first["start"].is_null());
    assert(first["end"].is_null());

    const auto& completed_receive = attribution["segments"][1];
    assert(completed_receive["segment_index"] == 2);
    assert(completed_receive["start"]["kind"] == "after_receive");
    assert(completed_receive["start"]["record_indices"] == Json::array({0}));
    assert(completed_receive["start"]["names"] == Json::array({"ClientHello"}));
    assert(completed_receive["end"]["kind"] == "before_send");
    assert(completed_receive["end"]["boundary_event_sequence"] == 6);
    assert(completed_receive["end"]["io_return_event_sequence"] == 7);
    assert(completed_receive["end"]["record_indices"] == Json::array({0, 1, 2}));
    assert(completed_receive["end"]["names"] ==
           Json::array({"ServerHello", "ChangeCipherSpec", "EncryptedExtensions",
                        "Certificate"}));
    assert(completed_receive["end"]["bundled"] == true);
    const auto& partial_followup = attribution["segments"][2];
    assert(partial_followup["start"].is_null());
    assert(partial_followup["end"]["kind"] == "before_send");
    assert(partial_followup["end"]["record_indices"] == Json::array({2, 3, 4}));
    assert(partial_followup["end"]["names"] ==
           Json::array({"EncryptedExtensions", "Certificate", "Finished"}));
    assert(partial_followup["end"]["bundled"] == true);

    auto duplicate_name_decoded = decoded;
    duplicate_name_decoded["server_sent"]["records"].push_back(
        {{"index", 5}, {"stream_begin", 160}, {"stream_end", 180}});
    duplicate_name_decoded["server_sent"]["records"].push_back(
        {{"index", 6}, {"stream_begin", 180}, {"stream_end", 200}});
    for (const auto index : {5, 6})
        duplicate_name_decoded["server_sent"]["messages"].push_back(
            {{"name", "NewSessionTicket"}, {"records", {index}},
             {"record_stream_ranges",
              Json::array({{{"begin", index == 5 ? 160 : 180},
                            {"end", index == 5 ? 180 : 200}}})},
             {"bundled", false}});
    auto duplicate_name_events = events;
    duplicate_name_events[6]["stream_end"] = 200;
    duplicate_name_events[6]["transferred"] = 200;
    const auto duplicate_name_partition = partition(header, duplicate_name_events).at(0);
    const auto duplicate_name_attribution = record_computation_attribution(
        header, duplicate_name_events, duplicate_name_decoded, duplicate_name_partition);
    const auto& duplicate_names = duplicate_name_attribution["segments"][1]["end"];
    assert(std::count(duplicate_names["names"].begin(), duplicate_names["names"].end(),
                      "NewSessionTicket") == 2);
    assert(duplicate_names["bundled"] == true);

    auto spanning_message_decoded = decoded;
    spanning_message_decoded["server_sent"]["records"] =
        Json::array({{{"index", 0}, {"stream_begin", 0}, {"stream_end", 40}},
                     {{"index", 1}, {"stream_begin", 40}, {"stream_end", 100}}});
    spanning_message_decoded["server_sent"]["messages"] = Json::array(
        {{{"name", "Certificate"}, {"records", {0, 1}},
          {"record_stream_ranges", Json::array({{{"begin", 0}, {"end", 100}}})},
          {"bundled", false}}});
    const auto spanning_message = record_computation_attribution(
        header, events, spanning_message_decoded, connection);
    assert(spanning_message["segments"][1]["end"]["names"] ==
           Json::array({"Certificate"}));
    assert(spanning_message["segments"][1]["end"]["bundled"] == false);

    auto earlier_shared_record = decoded;
    earlier_shared_record["server_sent"]["records"] =
        Json::array({{{"index", 0}, {"stream_begin", 0}, {"stream_end", 40}},
                     {{"index", 1}, {"stream_begin", 40}, {"stream_end", 100}}});
    earlier_shared_record["server_sent"]["messages"] = Json::array(
        {{{"name", "SpanningA"}, {"records", {0, 1}},
          {"record_stream_ranges", Json::array({{{"begin", 0}, {"end", 100}}})},
          {"bundled", true}},
         {{"name", "EarlierOnlyB"}, {"records", {0}},
          {"record_stream_ranges", Json::array({{{"begin", 0}, {"end", 40}}})},
          {"bundled", true}}});
    auto later_record_only = events;
    later_record_only[6]["stream_begin"] = 40;
    later_record_only[6]["stream_end"] = 100;
    later_record_only[6]["transferred"] = 60;
    const auto later_record_partition = partition(header, later_record_only).at(0);
    const auto boundary_local_bundling = record_computation_attribution(
        header, later_record_only, earlier_shared_record, later_record_partition);
    assert(boundary_local_bundling["segments"][1]["end"]["names"] ==
           Json::array({"SpanningA"}));
    assert(boundary_local_bundling["segments"][1]["end"]["bundled"] == false);

    const auto& call_end = attribution["segments"][3];
    assert(call_end["end"]["kind"] == "call_end");
    const auto& application_call = attribution["segments"][4];
    assert(application_call["start"]["kind"] == "call_begin");
    assert(application_call["start"]["io_return_event_sequence"].is_null());
    assert(application_call["start"]["record_indices"].empty() &&
           application_call["start"]["names"].empty());
    assert(application_call["start"]["bundled"] == false &&
           application_call["start"]["mapping"] == "boundary_event");
    assert(application_call["end"]["kind"] == "call_end");
    std::uint64_t attributed_elapsed = 0;
    for (const auto& segment : attribution["segments"])
        attributed_elapsed += segment["elapsed_ns"].get<std::uint64_t>();
    assert(attributed_elapsed == connection["computation_ns"]);

    auto missing_cpu_events = events;
    missing_cpu_events[5]["thread_cpu_ns"] = nullptr;
    const auto missing_cpu_partition = partition(header, missing_cpu_events).at(0);
    const auto missing_cpu = record_computation_attribution(
        header, missing_cpu_events, decoded, missing_cpu_partition);
    assert(missing_cpu["segments"][1]["elapsed_ns"] == 70);
    assert(missing_cpu["segments"][1]["thread_cpu_ns"].is_null());
    assert(missing_cpu["segments"][1]["thread_cpu_reason"] ==
           "thread_cpu_snapshot_missing");
    auto regressed_cpu_events = events;
    regressed_cpu_events[5]["thread_cpu_ns"] = 20;
    const auto regressed_cpu_partition = partition(header, regressed_cpu_events).at(0);
    const auto regressed_cpu = record_computation_attribution(
        header, regressed_cpu_events, decoded, regressed_cpu_partition);
    assert(regressed_cpu["segments"][1]["elapsed_ns"] == 70);
    assert(regressed_cpu["segments"][1]["thread_cpu_ns"].is_null());
    assert(regressed_cpu["segments"][1]["thread_cpu_reason"] ==
           "thread_cpu_regression");
    auto unsuccessful_send = events;
    unsuccessful_send[6]["result"] = 1;
    const auto unsuccessful_partition = partition(header, unsuccessful_send).at(0);
    const auto unsuccessful_attribution = record_computation_attribution(
        header, unsuccessful_send, decoded, unsuccessful_partition);
    assert(unsuccessful_attribution["segments"][1]["end"].is_null());
    auto zero_byte_success = events;
    zero_byte_success[6]["stream_end"] = 0;
    zero_byte_success[6]["transferred"] = 0;
    const auto zero_byte_partition = partition(header, zero_byte_success).at(0);
    const auto zero_byte_attribution = record_computation_attribution(
        header, zero_byte_success, decoded, zero_byte_partition);
    assert(zero_byte_attribution["segments"][1]["end"].is_null());
    auto want_then_success = events;
    want_then_success[6]["result"] = 1;
    want_then_success[6]["stream_end"] = 0;
    want_then_success[6]["transferred"] = 0;
    const auto retry_partition = partition(header, want_then_success).at(0);
    const auto retry_attribution = record_computation_attribution(
        header, want_then_success, decoded, retry_partition);
    assert(retry_attribution["segments"][1]["end"].is_null());
    assert(retry_attribution["segments"][2]["end"]["kind"] == "before_send");
    assert(retry_attribution["segments"][2]["end"]["io_return_event_sequence"] == 9);
    auto foreign_call_return = events;
    foreign_call_return[6]["call_id"] = 99;
    const auto foreign_call_partition = partition(header, foreign_call_return).at(0);
    const auto foreign_call_attribution = record_computation_attribution(
        header, foreign_call_return, decoded, foreign_call_partition);
    assert(foreign_call_attribution["segments"][1]["end"].is_null());

    const auto server_window =
        server_client_hello_to_finished_send_window(header, events, decoded);
    assert(server_window["definition"] ==
           "server_client_hello_receive_return_to_server_finished_send_return");
    assert(server_window["available"] == true && server_window["reason"].is_null());
    assert(server_window["start_event_sequence"] == 3);
    assert(server_window["end_event_sequence"] == 9);
    assert(server_window["elapsed_ns"] == 140);
    assert(server_window["thread_cpu_ns"] == 70);
    assert(server_window["cycles"].is_null());

    auto failed_receive = events;
    failed_receive[2]["result"] = 1;
    assert(server_client_hello_to_finished_send_window(header, failed_receive, decoded)
               ["reason"] == "server_window_io_boundary_unavailable");
    auto failed_send = events;
    failed_send[8]["result"] = 1;
    assert(server_client_hello_to_finished_send_window(header, failed_send, decoded)
               ["reason"] == "server_window_io_boundary_unavailable");
    auto server_cpu_missing = events;
    server_cpu_missing[8]["thread_cpu_ns"] = nullptr;
    const auto elapsed_without_server_cpu =
        server_client_hello_to_finished_send_window(header, server_cpu_missing, decoded);
    assert(elapsed_without_server_cpu["available"] == true &&
           elapsed_without_server_cpu["elapsed_ns"] == 140);
    assert(elapsed_without_server_cpu["thread_cpu_ns"].is_null() &&
           elapsed_without_server_cpu["thread_cpu_reason"] ==
               "thread_cpu_snapshot_missing");

    auto observer_off = header;
    observer_off["availability"]["io_events"] = {
        {"available", false}, {"reason", "channel_observer_disabled"}};
    const auto off_attribution =
        record_computation_attribution(observer_off, events, decoded, connection);
    assert(off_attribution["available"] == false &&
           off_attribution["reason"] == "channel_observer_disabled" &&
           off_attribution["segments"].is_null());
    const auto off_server_window =
        server_client_hello_to_finished_send_window(observer_off, events, decoded);
    assert(off_server_window["available"] == false &&
           off_server_window["reason"] == "channel_observer_disabled" &&
           off_server_window["elapsed_ns"].is_null() &&
           off_server_window["thread_cpu_ns"].is_null() &&
           off_server_window["thread_cpu_reason"] == "channel_observer_disabled");
    auto mapping_missing = decoded;
    mapping_missing["server_sent"].erase("records");
    const auto unavailable_mapping =
        record_computation_attribution(header, events, mapping_missing, connection);
    assert(unavailable_mapping["available"] == false &&
           unavailable_mapping["reason"] == "decoded_record_mapping_unavailable" &&
           unavailable_mapping["segments"].is_null());
    auto sequence_missing = events;
    sequence_missing[5].erase("sequence");
    const auto sequence_missing_partition = partition(header, sequence_missing).at(0);
    const auto sequence_missing_attribution = record_computation_attribution(
        header, sequence_missing, decoded, sequence_missing_partition);
    assert(sequence_missing_attribution["available"] == false &&
           sequence_missing_attribution["reason"] ==
               "primary_segment_event_mapping_unavailable");

    auto mixed_connections = events;
    auto foreign_receive = event(90, 1, 1, "IO_RECV_RETURN", "handshake", 1, 0, 100, 100);
    foreign_receive["connection"] = 1;
    auto foreign_send = event(91, 2, 2, "IO_SEND_RETURN", "handshake", 1, 0, 160, 160);
    foreign_send["connection"] = 1;
    mixed_connections.insert(mixed_connections.begin(), foreign_send);
    mixed_connections.insert(mixed_connections.begin(), foreign_receive);
    const auto isolated_server_window =
        server_client_hello_to_finished_send_window(header, mixed_connections, decoded);
    assert(isolated_server_window["start_event_sequence"] == 3 &&
           isolated_server_window["end_event_sequence"] == 9);

    const auto directory = std::filesystem::temp_directory_path() /
                           ("turtle-window-report-" + std::to_string(::getpid()));
    const auto output = directory / "out";
    std::filesystem::create_directories(directory);
    {
        std::ofstream raw(directory / "server.jsonl");
        raw << header.dump() << '\n';
        for (const auto& row : events)
            raw << row.dump() << '\n';
        std::ofstream decoded_out(directory / "server.decoded.json");
        decoded_out << Json({{"schema", 1}, {"sample", 1}, {"role", "server"},
                             {"connections", Json::array({decoded})}})
                           .dump(2)
                    << '\n';
    }
    const auto summary = summarize(directory, output);
    const auto& reported_connection = summary["samples"][0]["connections"][0];
    assert(reported_connection["record_computation_attribution"]["available"] == true);
    assert(reported_connection["server_client_hello_to_finished_send"]["elapsed_ns"] == 140);
    assert(summary["groups"][0]["metrics"]
                  ["server_client_hello_to_finished_send_elapsed_ns"]["count"] == 1);
    assert(summary["groups"][0]["server_client_hello_to_finished_send"]["definition"] ==
           "server_client_hello_receive_return_to_server_finished_send_return");
    assert(!summary["groups"][0]["metrics"].contains("record_computation_attribution"));
    std::filesystem::remove_all(directory);

    std::cout << "report window tests passed\n";
}
