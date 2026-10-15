#include "lifecycle/lifecycle.hpp"

#include "lifecycle/endpoint_protocol.hpp"
#include "lifecycle/lookup_runtime.hpp"
#include "lifecycle/role_runtime.hpp"
#include "capability/capability.hpp"
#include "control/control.hpp"
#include "lookup/lookup.hpp"
#include "model/run_config.hpp"
#include "model/service.hpp"
#include "record/service.hpp"
#include "transport/tcp.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <sched.h>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>
#include <unistd.h>

namespace turtle::lifecycle {
namespace {
using detail::AbortRequested;
using detail::ChildProtocol;
using detail::close_all;
using detail::monotonic_ns;
using detail::send;

void enter_namespace_and_close(int selected, std::span<const int> inherited) {
    if (selected >= 0) {
        control::enter_network_namespace(selected);
        ::close(selected);
    }
    for (int fd : inherited)
        if (fd >= 0)
            ::close(fd);
}

std::vector<int> accept_connections(int listener, std::size_t count) {
    std::vector<int> sockets;
    sockets.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        sockets.push_back(tcp::accept_one(listener));
    ::close(listener);
    return sockets;
}

std::vector<int> connect_connections(const std::string& source, const tcp::Endpoint& destination,
                                     std::size_t count) {
    std::vector<int> sockets;
    sockets.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        sockets.push_back(tcp::connect_ipv4(source, destination));
    return sockets;
}

model::ArtifactStatus inspect_artifact(const std::filesystem::path& path, bool service) {
    std::ifstream input(path);
    if (!input)
        return model::ArtifactStatus::Missing;
    try {
        std::string line;
        if (!service) {
            if (!std::getline(input, line) || line.empty())
                return model::ArtifactStatus::Partial;
            const auto header = nlohmann::json::parse(line);
            return header.value("valid", false) ? model::ArtifactStatus::Complete
                                                 : model::ArtifactStatus::Partial;
        }
        nlohmann::json footer;
        while (std::getline(input, line))
            if (!line.empty()) {
                const auto value = nlohmann::json::parse(line);
                if (value.value("record_kind", "") == "footer")
                    footer = value;
            }
        if (!footer.is_object())
            return model::ArtifactStatus::Partial;
        const auto status = footer.value("artifact_status", "partial");
        if (status == "complete") return model::ArtifactStatus::Complete;
        if (status == "missing") return model::ArtifactStatus::Missing;
        return model::ArtifactStatus::Partial;
    } catch (const nlohmann::json::exception&) {
        return model::ArtifactStatus::Partial;
    }
}

struct ChildControl { pid_t pid = -1; int fd = -1; std::unique_ptr<control::Waiter> waiter; };

control::ReapResult terminate_and_reap(std::span<ChildControl> children,
                                        control::Deadline deadline) {
    std::vector<pid_t> pids;
    for (auto& child : children) if (child.pid > 0) pids.push_back(child.pid);
    const auto result = control::reap_result(pids, deadline);
    for (auto& child : children) { if (child.fd >= 0) ::close(child.fd); child.fd = -1; }
    if (!result.all_reaped)
        throw std::runtime_error("owned child cleanup could not be proven");
    return result;
}

int run_attempt(const model::RunConfig& config, std::uint64_t sample,
                const std::string& directory, std::span<const std::uint8_t> client_context,
                std::span<const std::uint8_t> server_context,
                const lookup::Snapshot* reference, const lookup::Snapshot* initial,
                record::AttemptEntry& ledger, control::Deadline deadline) {
    ledger.failure_phase = model::FailurePhase::Startup;
    const std::size_t child_count = reference ? 3 : 2;
    std::array<int, 3> namespace_fds{-1, -1, -1};
    std::string client_tls = "127.0.0.1", server_addr = "127.0.0.1";
    std::string client_ca = "127.0.0.1", ca_addr = "127.0.0.1";
    if (config.network_handoff) {
        const auto& handoff = *config.network_handoff;
        namespace_fds = {::dup(handoff.server_namespace_fd), ::dup(handoff.client_namespace_fd),
                         reference ? ::dup(handoff.ca_namespace_fd) : -1};
        client_tls = handoff.client_tls_address; server_addr = handoff.server_address;
        client_ca = handoff.client_ca_address; ca_addr = handoff.ca_address;
        auto ack = control::exchange_phase(handoff.phase_control_fd, sample, control::Phase::Setup,
                                           control::PhaseEdge::Begin, deadline);
        ledger.network_observation_ids.push_back(ack.observation_id);
        for (std::size_t i = 0; i < child_count; ++i)
            if (namespace_fds[i] < 0)
                throw std::runtime_error("network namespace descriptor duplication failed");
    }
    std::vector<std::array<int, 2>> pairs(child_count, std::array<int, 2>{-1, -1});
    for (std::size_t i = 0; i < pairs.size(); ++i) {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i].data())) {
            for (std::size_t j = 0; j < i; ++j) {
                ::close(pairs[j][0]);
                ::close(pairs[j][1]);
            }
            for (int fd : namespace_fds) if (fd >= 0) ::close(fd);
            throw std::runtime_error("control socketpair failed");
        }
    }
    std::vector<ChildControl> children(child_count);
    auto spawn = [&](std::size_t index) {
        const auto pid = ::fork();
        if (pid != 0) { children[index].pid = pid; return; }
        for (std::size_t j = 0; j < pairs.size(); ++j) {
            ::close(pairs[j][0]); if (j != index) ::close(pairs[j][1]);
        }
        std::vector<int> close_ns;
        for (std::size_t j = 0; j < namespace_fds.size(); ++j)
            if (j != index && namespace_fds[j] >= 0) close_ns.push_back(namespace_fds[j]);
        if (config.network_handoff) {
            const auto& handoff = *config.network_handoff;
            for (int fd : {handoff.client_namespace_fd, handoff.server_namespace_fd,
                           handoff.ca_namespace_fd, handoff.phase_control_fd})
                if (fd >= 0) close_ns.push_back(fd);
        }
        int result = 1;
        std::unique_ptr<control::Waiter> parent;
        try {
            parent = std::make_unique<control::Waiter>(pairs[index][1]);
            enter_namespace_and_close(namespace_fds[index], close_ns);
            send(*parent, control::MessageKind::NamespaceReady, deadline, sample);
            if (index == 0) {
                auto listener = tcp::listen_ipv4(server_addr, 0);
                auto actual = tcp::local_endpoint(listener.fd);
                send(*parent, control::MessageKind::ReadyAddress, deadline, sample, 0, false,
                     actual.address, actual.port);
                auto sockets = accept_connections(listener.fd, config.warmups + config.connections);
                result = detail::run_tls_role(config, Role::Server, sample, directory, std::move(sockets),
                                      pairs[index][1], deadline, server_context, nullptr, nullptr);
            } else if (index == 2) {
                auto listener = tcp::listen_ipv4(ca_addr, 0);
                auto actual = tcp::local_endpoint(listener.fd);
                send(*parent, control::MessageKind::ReadyAddress, deadline, sample, 0, false,
                     actual.address, actual.port);
                auto sockets = accept_connections(listener.fd, config.warmups + config.connections);
                result = detail::ca_endpoint(config, sample, directory, std::move(sockets), pairs[index][1],
                                     deadline, *reference);
            } else {
                auto server = control::receive_message(*parent, deadline);
                auto ca = reference ? control::receive_message(*parent, deadline) : control::Message{};
                auto tls_sockets = connect_connections(client_tls, {server.address, server.port},
                                                        config.warmups + config.connections);
                std::vector<int> ca_sockets;
                if (reference) ca_sockets = connect_connections(client_ca, {ca.address, ca.port},
                                                                  config.warmups + config.connections);
                result = detail::run_tls_role(config, Role::Client, sample, directory, std::move(tls_sockets),
                                      pairs[index][1], deadline, client_context, reference, initial,
                                      std::move(ca_sockets));
            }
        } catch (const std::exception& error) {
            if (parent) {
                try {
                    send(*parent, control::MessageKind::Failed, deadline, sample, 0, false, {}, 0,
                         0, error.what());
                } catch (...) {}
            }
            std::cerr << "child: " << error.what() << '\n';
        }
        ::close(pairs[index][1]); ::_exit(result);
    };
    for (std::size_t i = 0; i < child_count; ++i) {
        spawn(i);
        if (children[i].pid < 0) break;
    }
    try {
        for (std::size_t i = 0; i < child_count; ++i) {
            ::close(pairs[i][1]);
            pairs[i][1] = -1;
            if (children[i].pid > 0) {
                children[i].fd = pairs[i][0];
                children[i].waiter = std::make_unique<control::Waiter>(pairs[i][0]);
            } else {
                ::close(pairs[i][0]);
                pairs[i][0] = -1;
            }
        }
    } catch (...) {
        for (auto& pair : pairs)
            for (int fd : pair)
                if (fd >= 0) ::close(fd);
        for (int fd : namespace_fds) if (fd >= 0) ::close(fd);
        std::vector<pid_t> owned;
        for (const auto& child : children) if (child.pid > 0) owned.push_back(child.pid);
        const auto recovery = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(config.flush_grace_ms);
        (void)control::reap_owned(owned, recovery);
        throw;
    }
    for (int fd : namespace_fds) if (fd >= 0) ::close(fd);
    bool ok = std::all_of(children.begin(), children.end(), [](const auto& c) { return c.pid > 0; });
    std::string first_reason;
    model::AttemptStatus terminal_status = model::AttemptStatus::Success;
    control::Deadline grace{};
    bool cleanup_started = false;
    bool scenario_started = false;
    bool scenario_ended = false;
    std::size_t completions = 0;
    try {
        if (!ok) throw std::runtime_error("fork failed");
        if (config.pin_cores) {
            std::string reason;
            if (!capability::pin_to_cpu(config.director_cpu, reason))
                throw std::runtime_error("director CPU affinity failed: " + reason);
        }
        for (auto& child : children) {
            auto namespace_ready = control::receive_message(*child.waiter, deadline);
            if (namespace_ready.kind != control::MessageKind::NamespaceReady)
                throw std::runtime_error("participant namespace acknowledgement missing");
        }
        ledger.failure_phase = model::FailurePhase::Listener;
        auto server_address = control::receive_message(*children[0].waiter, deadline);
        if (server_address.kind != control::MessageKind::ReadyAddress) throw std::runtime_error("server address missing");
        control::send_message(*children[1].waiter, server_address, deadline);
        if (reference) {
            auto ca_address = control::receive_message(*children[2].waiter, deadline);
            if (ca_address.kind != control::MessageKind::ReadyAddress) throw std::runtime_error("CA address missing");
            control::send_message(*children[1].waiter, ca_address, deadline);
        }
        ledger.failure_phase = model::FailurePhase::TcpReady;
        for (auto& child : children) {
            auto ready = control::receive_message(*child.waiter, deadline);
            if (ready.kind == control::MessageKind::Failed)
                throw std::runtime_error(ready.reason.empty()
                                             ? "participant TCP_READY failed without a diagnostic"
                                             : ready.reason);
            if (ready.kind != control::MessageKind::TcpReady)
                throw std::runtime_error("participant TCP_READY missing");
        }
        if (config.network_handoff) {
            auto ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Setup, control::PhaseEdge::End, deadline);
            ledger.network_observation_ids.push_back(ack.observation_id);
            ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Scenario, control::PhaseEdge::Begin, deadline);
            ledger.network_observation_ids.push_back(ack.observation_id);
            scenario_started = true;
        }
        for (auto& child : children) send(*child.waiter, control::MessageKind::Start, deadline, sample);
        ledger.failure_phase = model::FailurePhase::Scenario;
        const std::size_t connection_count = config.warmups + config.connections;
        const std::size_t expected = child_count * connection_count;
        std::vector<std::vector<bool>> completed(child_count,
                                                  std::vector<bool>(connection_count));
        std::vector<std::array<bool, 2>> opened(connection_count);
        while (completions < expected) {
            pollfd descriptors[3]{};
            for (std::size_t i = 0; i < child_count; ++i) { descriptors[i].fd = children[i].fd; descriptors[i].events = POLLIN; }
            const auto remaining_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining_ns <= 0)
                throw std::runtime_error("attempt deadline exceeded");
            const auto remaining_ms = (remaining_ns + 999999) / 1000000;
            const int poll_result = ::poll(descriptors, child_count, static_cast<int>(remaining_ms));
            if (poll_result < 0) {
                if (errno == EINTR)
                    continue;
                throw std::system_error(errno, std::generic_category(),
                                        "participant control poll failed");
            }
            if (poll_result == 0) {
                if (std::chrono::steady_clock::now() >= deadline)
                    throw std::runtime_error("attempt deadline exceeded");
                continue;
            }
            for (std::size_t i = 0; i < child_count; ++i) if (descriptors[i].revents) {
                auto message = control::receive_message(*children[i].waiter, deadline);
                if (message.kind == control::MessageKind::TcpReady && i < 2) {
                    if (message.connection >= connection_count || opened[message.connection][i])
                        throw std::runtime_error("duplicate endpoint open readiness");
                    opened[message.connection][i] = true;
                    if (opened[message.connection][0] && opened[message.connection][1]) {
                        send(*children[0].waiter, control::MessageKind::Start, deadline, sample,
                             message.connection);
                        send(*children[1].waiter, control::MessageKind::Start, deadline, sample,
                             message.connection);
                    }
                } else if (message.kind == control::MessageKind::ConnectionComplete) {
                    if (message.connection >= connection_count || completed[i][message.connection])
                        throw std::runtime_error("duplicate connection completion");
                    completed[i][message.connection] = true;
                    ++completions;
                    bool release = true;
                    for (std::size_t participant = 0; participant < child_count; ++participant)
                        release = release && completed[participant][message.connection];
                    if (release)
                        for (auto& child : children)
                            send(*child.waiter, control::MessageKind::Start, deadline, sample,
                                 message.connection);
                } else if (i == 1 && reference && (message.kind == control::MessageKind::ResponseComplete ||
                                                  message.kind == control::MessageKind::LookupSkipped))
                    control::send_message(*children[2].waiter, message, deadline);
                else if (message.kind == control::MessageKind::Failed)
                    throw std::runtime_error(message.reason.empty()
                        ? "participant reported execution failure" : message.reason);
                else throw std::runtime_error("unexpected participant message");
            }
        }
        if (config.network_handoff) {
            auto ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Scenario, control::PhaseEdge::End, deadline);
            ledger.network_observation_ids.push_back(ack.observation_id);
            scenario_ended = true;
        }
        if (config.network_handoff) {
            auto ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Cleanup, control::PhaseEdge::Begin, deadline);
            ledger.network_observation_ids.push_back(ack.observation_id);
            cleanup_started = true;
        }
        ledger.failure_phase = model::FailurePhase::Flush;
        grace = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.flush_grace_ms);
        for (auto& child : children)
            send(*child.waiter, control::MessageKind::Flush, grace, sample, 0, false, {}, 0,
                 monotonic_ns(grace));
        for (auto& child : children) {
            const auto message = control::receive_message(*child.waiter, grace);
            if (message.kind == control::MessageKind::Failed)
                throw std::runtime_error(message.reason.empty()
                    ? "participant flush failed without a diagnostic" : message.reason);
            if (message.kind != control::MessageKind::Flushed)
                throw std::runtime_error("participant flush incomplete");
        }
        ok = true;
    } catch (const std::exception& error) {
        ok = false;
        first_reason = error.what();
        if (ledger.failure_phase == model::FailurePhase::Flush)
            terminal_status = model::AttemptStatus::Incomplete;
        else if (std::chrono::steady_clock::now() >= deadline)
            terminal_status = model::AttemptStatus::Timeout;
        else
            terminal_status = model::AttemptStatus::Error;
    }
    if (grace == control::Deadline{})
        grace = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.flush_grace_ms);
    if (!ok) {
        for (auto& child : children) if (child.pid > 0) {
            try {
                send(*child.waiter, control::MessageKind::AbortFlush, grace, sample, 0, false, {}, 0,
                     monotonic_ns(grace));
            } catch (...) {}
        }
    }
    if (scenario_started && !scenario_ended && config.network_handoff) {
        try {
            auto ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Scenario, control::PhaseEdge::End, grace);
            ledger.network_observation_ids.push_back(ack.observation_id);
        } catch (const std::exception& error) {
            ledger.secondary_reasons.push_back(error.what());
        }
    }
    if (!cleanup_started && config.network_handoff) {
        try {
            auto ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Cleanup, control::PhaseEdge::Begin, grace);
            ledger.network_observation_ids.push_back(ack.observation_id);
        } catch (const std::exception& error) {
            ledger.secondary_reasons.push_back(error.what());
        }
    }
    bool cleanup_proven = true;
    control::ReapResult reap;
    try {
        reap = terminate_and_reap(children, grace);
        if (reap.forced_kill)
            ledger.secondary_reasons.push_back("owned child required SIGKILL after cleanup grace");
        if (ok && !reap.all_success) {
            ok = false;
            terminal_status = model::AttemptStatus::Incomplete;
            first_reason = "participant exited unsuccessfully after FLUSHED";
        }
    }
    catch (const std::exception& error) {
        cleanup_proven = false;
        if (terminal_status == model::AttemptStatus::Success) {
            terminal_status = model::AttemptStatus::Incomplete;
            ledger.failure_phase = model::FailurePhase::Exit;
            first_reason = error.what();
        } else if (first_reason.empty()) {
            first_reason = error.what();
        } else {
            ledger.secondary_reasons.push_back(error.what());
        }
        ok = false;
    }
    if (config.network_handoff) {
        try {
            auto ack = control::exchange_phase(config.network_handoff->phase_control_fd, sample,
                control::Phase::Cleanup, control::PhaseEdge::End, grace);
            ledger.network_observation_ids.push_back(ack.observation_id);
        } catch (const std::exception& error) { ledger.secondary_reasons.push_back(error.what()); }
    }
    ledger.reason = first_reason;
    ledger.artifact_status.clear();
    for (const auto& artifact : ledger.artifact_names) {
        const bool service = artifact == record::lookup_filename || artifact == record::ca_filename;
        ledger.artifact_status.push_back(
            inspect_artifact(std::filesystem::path(directory) / artifact, service));
    }
    if (ok) {
        for (std::size_t i = 0; i < ledger.artifact_status.size(); ++i) {
            if (ledger.artifact_status[i] == model::ArtifactStatus::Complete)
                continue;
            ok = false;
            terminal_status = model::AttemptStatus::Incomplete;
            ledger.failure_phase = model::FailurePhase::Flush;
            first_reason = "required raw artifact is not complete: " + ledger.artifact_names[i];
            ledger.reason = first_reason;
            break;
        }
    }
    ledger.final_status = ok ? model::AttemptStatus::Success : terminal_status;
    if (ok)
        ledger.failure_phase = model::FailurePhase::None;
    const bool fatal_failure =
        !ok && terminal_status == model::AttemptStatus::Error &&
        ledger.failure_phase != model::FailurePhase::Scenario;
    return ok ? 0 : (cleanup_proven && !fatal_failure ? 1 : 2);
}
} // namespace

int run(const model::RunConfig& input) {
    auto config = input;
    if (!config.perf && config.perf_scope == model::PerfScope::UserKernel)
        throw std::invalid_argument("perf scope user+kernel requires perf measurement");
    if (config.tls.cipher != "TLS_AES_128_GCM_SHA256")
        throw std::invalid_argument("TURTLE supports only TLS_AES_128_GCM_SHA256");
    if (config.connections == 0 || config.connections > 1025 || config.warmups > 1025 - config.connections)
        throw std::invalid_argument("total warmup and measured connections must be 1..1025");
    auto environment = capability::inspect_environment(); capability::choose_cpus(config, environment);
    cpu_set_t original_affinity;
    const bool have_affinity =
        ::sched_getaffinity(0, sizeof original_affinity, &original_affinity) == 0;
    const auto client_context = detail::load_serialized_context(config, Role::Client);
    const auto server_context = detail::load_serialized_context(config, Role::Server);
    auto lookup_inputs = detail::load_lookup_inputs(config);
    auto& reference = lookup_inputs.reference;
    auto& initial = lookup_inputs.initial;
    std::filesystem::create_directories(config.output_directory);
    record::AttemptWriter attempts(config.output_directory, config.samples, config.failure_policy);
    std::vector<record::AttemptEntry> ledger;
    ledger.reserve(config.samples);
    bool failed = false;
    bool fatal = false;
    for (std::uint64_t sample = 1; sample <= config.samples; ++sample) {
        record::AttemptEntry entry; entry.attempt_id = sample; entry.requested_count = config.samples;
        entry.flush_grace_ms = config.flush_grace_ms;
        entry.participants = {model::ParticipantKind::TlsServer, model::ParticipantKind::TlsClient};
        if (reference) entry.participants.push_back(model::ParticipantKind::MockCa);
        entry.artifact_names = {"server.jsonl", "client.jsonl"};
        if (reference) {
            entry.artifact_names.push_back(record::lookup_filename);
            entry.artifact_names.push_back(record::ca_filename);
        }
        entry.artifact_status.assign(entry.artifact_names.size(), model::ArtifactStatus::Missing);
        entry.connections.resize(config.warmups + config.connections);
        std::iota(entry.connections.begin(), entry.connections.end(), 0);
        if (fatal || (failed && config.failure_policy == model::FailurePolicy::FailFast)) {
            ledger.push_back(entry); continue;
        }
        std::ostringstream name; name << "sample-" << std::setw(6) << std::setfill('0') << sample;
        const auto directory = (std::filesystem::path(config.output_directory) / name.str()).string();
        if (!std::filesystem::create_directory(directory)) throw std::runtime_error("sample directory already exists");
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(config.timeout_ms);
        entry.measurement_deadline_monotonic_ns = monotonic_ns(deadline);
        entry.started = true; attempts.started(entry);
        if (config.pin_cores && have_affinity &&
            ::sched_setaffinity(0, sizeof original_affinity, &original_affinity))
            throw std::runtime_error("cannot restore director affinity before fork");
        int rc = 2;
        try {
            rc = run_attempt(config, sample, directory, client_context, server_context,
                             reference.get(), initial.get(), entry, deadline);
        } catch (const std::exception& error) {
            entry.final_status = std::chrono::steady_clock::now() >= deadline
                ? model::AttemptStatus::Timeout : model::AttemptStatus::Error;
            entry.reason = error.what();
            entry.artifact_status.assign(entry.artifact_names.size(), model::ArtifactStatus::Missing);
            if (config.network_handoff) {
                const auto cleanup_deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(config.flush_grace_ms);
                for (const auto edge : {control::PhaseEdge::Begin, control::PhaseEdge::End}) {
                    try {
                        auto ack = control::exchange_phase(config.network_handoff->phase_control_fd,
                            sample, control::Phase::Cleanup, edge, cleanup_deadline);
                        entry.network_observation_ids.push_back(ack.observation_id);
                    } catch (const std::exception& cleanup_error) {
                        entry.secondary_reasons.push_back(cleanup_error.what());
                        break;
                    }
                }
            }
        }
        if (config.pin_cores && have_affinity)
            ::sched_setaffinity(0, sizeof original_affinity, &original_affinity);
        attempts.finished(entry); ledger.push_back(entry);
        std::ofstream status(std::filesystem::path(directory) / "director.txt");
        status << (rc == 0 ? "valid\n" : "invalid: " + entry.reason + "\n");
        failed |= rc != 0;
        fatal |= rc == 2;
    }
    if (config.pin_cores && have_affinity)
        ::sched_setaffinity(0, sizeof original_affinity, &original_affinity);
    attempts.summary(ledger);
    return failed ? 1 : 0;
}
} // namespace turtle::lifecycle
