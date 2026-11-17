#include "run/runner.hpp"
#include "measure/recorder.hpp"
#include "net/transport.hpp"
#include "artifact/endpoint.hpp"
#include <array>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
namespace turtle::run {
namespace {
void require(bool success, const char* reason) { if (!success) throw std::runtime_error(reason); }
net::Socket socket(const Options& o) {
    if (o.role == TURTLE_CLIENT) return net::connect(o.host.c_str(), o.port);
    auto listener = net::listen(o.host.c_str(), o.port);
    std::cout << "LISTEN " << net::port(listener) << std::endl;
    return net::accept(listener);
}
void send(const turtle_implementation& api, void* state, measure::Recorder& recorder, std::string_view message) {
    while (!message.empty()) {
        measure::Scope call(recorder, measure::Operation::write);
        const auto size = api.write(state, message.data(), message.size());
        require(size > 0 && static_cast<std::size_t>(size) <= message.size(), "application_write_failed");
        message.remove_prefix(static_cast<std::size_t>(size));
        call.succeeded(size);
    }
}
void receive(const turtle_implementation& api, void* state, measure::Recorder& recorder, std::string_view expected) {
    std::array<char, 4> message{};
    std::size_t offset = 0;
    while (offset < message.size()) {
        measure::Scope call(recorder, measure::Operation::read);
        const auto size = api.read(state, message.data() + offset, message.size() - offset);
        require(size > 0 && static_cast<std::size_t>(size) <= message.size() - offset, "application_read_failed");
        offset += static_cast<std::size_t>(size);
        if (offset == message.size())
            require(std::string_view(message.data(), message.size()) == expected, "application_content_mismatch");
        call.succeeded(size);
    }
}
}
int run(const turtle_implementation& api, const Options& o) {
    using namespace measure;
    std::filesystem::create_directories(o.output);
    for (const auto* file : {"endpoint.json", "events.jsonl", "counters.json", "tls_send.bin", "tls_receive.bin", "wire_send.bin", "wire_receive.bin"})
        require(!std::filesystem::exists(std::filesystem::path(o.output) / file), "output_already_exists");
    Recorder recorder(Recorder::event_capacity, o.perf_counters);
    artifact::Result result;
    result.run_id = o.run_id;
    result.implementation = api.name;
    result.role = o.role == TURTLE_CLIENT ? "client" : "server";
    result.chunk = o.chunk;
    result.cpu_samples = o.cpu_samples;
    try {
        net::Connection connection(socket(o), recorder, o.chunk, o.timeout);
        std::unique_ptr<void, decltype(api.release)> state(nullptr, api.release);
        {
            Scope call(recorder, Operation::prepare);
            state.reset(api.prepare(o.role, static_cast<int>(o.arguments.size()), o.arguments.data(), connection.transport()));
            require(state != nullptr && recorder.complete(), "prepare_failed");
            call.succeeded();
        }
        std::cout << "READY" << std::endl;
        if (o.controlled) {
            std::string command;
            require(static_cast<bool>(std::getline(std::cin, command)) && command == "START", "start_barrier_failed");
        }
        turtle_handshake_info info{0, -1, nullptr, nullptr, TURTLE_PROFILE_UNSPECIFIED};
        result.begin = recorder.stamp();
        {
            Scope call(recorder, Operation::handshake);
            require(api.handshake(state.get(), &info) == 1, "handshake_failed");
            require(info.version == TURTLE_TLS13 && info.resumed == 0, "not_full_tls13");
            call.succeeded();
        }
        if (o.role == TURTLE_CLIENT) {
            send(api, state.get(), recorder, "ping");
            receive(api, state.get(), recorder, "pong");
            result.end = recorder.stamp();
        } else {
            receive(api, state.get(), recorder, "ping");
            send(api, state.get(), recorder, "pong");
            for (auto it = recorder.events().rbegin(); it != recorder.events().rend(); ++it) {
                if (it->kind == Kind::socket && it->direction == Direction::send && it->transferred > 0) {
                    result.end = it->end;
                    break;
                }
            }
        }
        require(connection.at_record_boundary(), "scenario_record_incomplete");
        result.scenario_complete = true;
        result.scenario_observations_complete = recorder.complete();
        result.scenario_tls_send = recorder.total(Layer::tls, Direction::send);
        result.scenario_tls_receive = recorder.total(Layer::tls, Direction::receive);
        result.scenario_wire_send = recorder.total(Layer::wire, Direction::send);
        result.scenario_wire_receive = recorder.total(Layer::wire, Direction::receive);
        result.version = info.version;
        result.resumed = info.resumed;
        result.profile = info.profile;
        if (info.cipher) result.cipher = info.cipher;
        if (info.group) result.group = info.group;
        result.shutdown = api.shutdown ? "failed" : "not_supported";
        if (api.shutdown) {
            Scope call(recorder, Operation::shutdown);
            if (api.shutdown(state.get()) == 1) { call.succeeded(); result.shutdown = "ok"; }
        }
    } catch (const std::exception& error) {
        if (!result.scenario_complete) result.invalid_reason = error.what();
    } catch (...) {
        if (!result.scenario_complete) result.invalid_reason = "implementation_exception";
    }
    if (recorder.reason()) {
        result.observation_reason = recorder.reason();
        if (!result.scenario_observations_complete) result.invalid_reason = recorder.reason();
    }
    artifact::write(o.output, recorder, result);
    return result.scenario_complete && result.scenario_observations_complete ? 0 : 1;
}
}
