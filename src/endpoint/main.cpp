#include "execution/execution.hpp"
#include "journal/journal.hpp"
#include "mockca/mockca.hpp"
#include "observation/observation.hpp"
#include "socket/socket.hpp"
#include "spec/spec.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <unistd.h>
#include <nlohmann/json.hpp>
namespace {
using namespace turtle;
using json = nlohmann::json;
void send_json(int fd, const json& j, std::uint64_t deadline) {
    auto text = j.dump();
    auto length = htonl(std::uint32_t(text.size()));
    write_all(fd, {reinterpret_cast<const std::uint8_t*>(&length), 4}, deadline);
    write_all(fd, {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()}, deadline);
}
json receive_json(int fd, std::uint64_t deadline) {
    std::uint32_t length = 0;
    read_all(fd, {reinterpret_cast<std::uint8_t*>(&length), 4}, deadline);
    length = ntohl(length);
    if (length > 65536)
        throw std::runtime_error("control capacity");
    std::string text(length, '\0');
    read_all(fd, {reinterpret_cast<std::uint8_t*>(text.data()), text.size()}, deadline);
    return json::parse(text);
}
json shared(const Spec& s) {
    return {{"contract", "turtle-message-control/1"},
            {"run_id", s.run_id},
            {"scenario", scenario_name(s.scenario)},
            {"mutual_auth", s.mutual},
            {"group", s.group},
            {"connections", s.connections},
            {"warmups", s.warmups},
            {"client_bytes", s.client_bytes},
            {"server_bytes", s.server_bytes}};
}
} // namespace
int main(int argc, char** argv) {
    try {
        if (argc != 2)
            throw std::runtime_error("usage: endpoint RUN.json");
        auto spec = read_spec(argv[1], TURTLE_ROLE);
        if (std::filesystem::exists(spec.output))
            throw std::runtime_error("output already exists");
        std::filesystem::create_directories(spec.output);
        std::filesystem::copy_file(argv[1], spec.output + "/run.json");
        auto api = turtle_register();
        auto support = api.support();
        Event infrastructure{};
        infrastructure.kind = Kind::FrameworkPreparation;
        infrastructure.begin.wall = monotonic_ns();
        if (spec.cpu)
            infrastructure.begin.cpu = thread_cpu_ns();
        Observer observer(spec.cpu, spec.perf, spec.white, spec.event_capacity, spec.allocations);
        infrastructure.end = observer.now(false);
        observer.add(infrastructure);
        std::string failure;
        try {
            Socket data_listener, control_listener, control;
            auto deadline = monotonic_ns() + std::uint64_t(spec.timeout_ms) * 1000000;
            if (spec.role == TURTLE_SERVER) {
                Event listener{};
                listener.kind = Kind::ListenerPreparation;
                listener.begin = observer.now(false);
                data_listener = listen_socket(spec.address, spec.port);
                listener.end = observer.now(false);
                observer.add(listener);
                if (!spec.external)
                    control_listener = listen_socket(spec.address, spec.control_port);
                std::ofstream ready(spec.output + "/ready");
                ready << "listening\n";
            }
            std::string ca = spec.pki + "/ca.pem",
                        cert = spec.pki + (spec.role == TURTLE_CLIENT ? "/client-chain.pem"
                                                                      : "/server-chain.pem"),
                        key =
                            spec.pki + (spec.role == TURTLE_CLIENT ? "/client.key" : "/server.key");
            auto object_cache = prepare_lookup(spec, observer);
            turtle_options options{spec.role,   spec.mutual, ca.c_str(),         cert.c_str(),
                                   key.c_str(), "localhost", spec.group.c_str(), spec.max_message};
            char error[512]{};
            Event e{};
            e.kind = Kind::Context;
            e.begin = observer.now(false);
            std::unique_ptr<turtle_context, decltype(api.destroy_context)> context(
                [&] {
                    AllocationScope scope(observer.tracker());
                    return api.create_context(&options, error, sizeof(error));
                }(),
                api.destroy_context);
            e.end = observer.now(false);
            observer.add(e);
            if (!context)
                throw std::runtime_error(error);
            if (!spec.external) {
                control = spec.role == TURTLE_SERVER
                              ? accept_socket(control_listener, deadline)
                              : connect_socket(spec.address, spec.control_port, deadline);
                auto expected = shared(spec);
                send_json(control.fd(), expected, deadline);
                if (receive_json(control.fd(), deadline) != expected)
                    throw std::runtime_error("shared run specification mismatch");
            }
            for (unsigned i = 0; i < spec.connections + spec.warmups; ++i) {
                deadline = monotonic_ns() + std::uint64_t(spec.timeout_ms) * 1000000;
                Event transport{};
                transport.kind = Kind::Transport;
                transport.connection = i + 1;
                transport.begin = observer.now(false);
                Socket data = spec.role == TURTLE_SERVER
                                  ? accept_socket(data_listener, deadline)
                                  : connect_socket(spec.address, spec.port, deadline);
                transport.end = observer.now(false);
                observer.add(transport);
                e = {};
                e.kind = Kind::Connection;
                e.connection = i + 1;
                e.detail = i < spec.warmups ? 1 : 0;
                e.begin = observer.now(false);
                std::unique_ptr<turtle_connection, decltype(api.destroy_connection)> connection(
                    [&] {
                        AllocationScope scope(observer.tracker());
                        return api.create_connection(context.get(), error, sizeof(error));
                    }(),
                    api.destroy_connection);
                if (!connection)
                    throw std::runtime_error(error);
                Execution execution(spec, api, connection.get(), observer, data.fd(), i + 1);
                e.end = observer.now(false);
                observer.add(e);
                auto result = execution.run();
                auto storage = api.storage(connection.get());
                if (spec.stream) {
                    save_stream(spec.output + "/" + std::to_string(i + 1) + ".tx.plain.bin",
                                execution.tx_plain_stream);
                    save_stream(spec.output + "/" + std::to_string(i + 1) + ".rx.plain.bin",
                                execution.rx_plain_stream);
                    save_stream(spec.output + "/" + std::to_string(i + 1) + ".tx.bin",
                                execution.tx_stream);
                    save_stream(spec.output + "/" + std::to_string(i + 1) + ".rx.bin",
                                execution.rx_stream);
                }
                std::ofstream evidence(spec.output + "/" + std::to_string(i + 1) + ".result.json");
                evidence << json(
                                {{"full_handshake", result.full_handshake != 0},
                                 {"peer_verified", result.peer_verified != 0},
                                 {"peer_certificate", result.peer_certificate != 0},
                                 {"technique_used", result.technique_used},
                                 {"keygen", result.keygen},
                                 {"encapsulate", result.encapsulate},
                                 {"decapsulate", result.decapsulate},
                                 {"optimized", result.optimized},
                                 {"certificate_cache_hit", result.certificate_cache_hit},
                                 {"request_cache_hit", result.request_cache_hit},
                                 {"ssc_cache_hit", result.ssc_cache_hit},
                                 {"storage",
                                  {{"message_buffer_bytes", (storage.storage_available & 1)
                                                                ? json(storage.message_buffer_bytes)
                                                                : json(nullptr)},
                                   {"record_buffer_bytes", (storage.storage_available & 2)
                                                               ? json(storage.record_buffer_bytes)
                                                               : json(nullptr)},
                                   {"technique_cache_bytes", (storage.storage_available & 4)
                                                                 ? json(storage.cache_bytes)
                                                                 : json(nullptr)}}}})
                                .dump(2)
                         << '\n';
                {
                    AllocationScope scope(observer.tracker());
                    connection.reset();
                }
                if (!spec.external) {
                    json done = {{"connection", i + 1}, {"success", true}};
                    send_json(control.fd(), done, deadline);
                    if (receive_json(control.fd(), deadline) != done)
                        throw std::runtime_error("peer completion mismatch");
                }
            }
            {
                AllocationScope scope(observer.tracker());
                context.reset();
            }
        } catch (const std::exception& error) {
            failure = error.what();
            if (failure.empty())
                failure = "implementation operation failed without diagnostic";
        }
        save_events(spec, observer, support, failure);
        if (!failure.empty()) {
            std::cerr << support.name << ": " << failure << '\n';
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
