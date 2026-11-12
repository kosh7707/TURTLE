#include "lifecycle/peer_session.hpp"

#include "lifecycle/endpoint_protocol.hpp"
#include "model/sample.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <unistd.h>

namespace turtle::lifecycle::detail {
namespace {
using Json = nlohmann::json;

Json endpoint(const tcp::Endpoint& value) {
    return {{"address", value.address}, {"port", value.port}};
}

Json readiness(const model::SampleInfo& info) {
    const auto& caps = info.capabilities;
    const auto& config = info.config;
    return {{"version", 1},
            {"role", model::name(info.role)},
            {"run_id", config.run_id},
            {"context_id", config.context_id},
            {"sample", info.sample},
            {"ready", true},
            {"implementation", config.implementation},
            {"library", info.declaration.library},
            {"library_version", info.declaration.version},
            {"is_mock", info.declaration.is_mock},
            {"adapter_linkage", config.adapter_linkage},
            {"tls_linkage", config.tls_linkage},
            {"mode", model::name(config.mode)},
            {"context", "prepared"},
            {"buffers", "allocated"},
            {"scenario", "supported"},
            {"send_policy", "supported"},
            {"data_connection", "not_probed"},
            {"peer_authentication", "not_checked"},
            {"measurement",
             {{"monotonic_clock", caps.monotonic_clock},
              {"thread_cpu_clock", caps.thread_cpu_clock},
              {"perf_status", model::name(caps.perf_status)},
              {"perf_requested_scope", model::name(caps.perf_requested_scope)},
              {"perf_effective_scope", caps.perf_effective_scope
                                           ? Json(model::name(*caps.perf_effective_scope))
                                           : Json(nullptr)},
              {"perf_note", caps.perf_note},
              {"heap_tracking", config.mode != model::Mode::Memory ? "not_requested"
                                : caps.heap_tracking               ? "supported"
                                                                   : "unavailable"},
              {"kernel_timestamps", config.kernel_timestamps ? "not_checked" : "not_requested"},
              {"tls_stream", info.tls_stream_available},
              {"affinity", config.pin_cores ? "applied" : "not_requested"}}}};
}
} // namespace

PeerSession::PeerSession(model::RunConfig& config, control::Deadline deadline)
    : config_(config), deadline_(deadline) {}

PeerSession::~PeerSession() {
    for (const int fd : {peer_, control_listener_, listener_})
        if (fd >= 0)
            ::close(fd);
}

void PeerSession::connect() {
    if (config_.role == Role::Server) {
        status_.stage = "listen";
        const auto data = tcp::listen_ipv4(config_.address, config_.port);
        listener_ = data.fd;
        config_.port = data.port;
        const auto control = tcp::listen_ipv4(config_.control_address, config_.control_port);
        control_listener_ = control.fd;
        config_.control_port = control.port;
        tcp::nonblocking_listener(control_listener_);
        if (!config_.ready_file.empty()) {
            std::ofstream ready(config_.ready_file);
            ready.exceptions(std::ios::badbit | std::ios::failbit);
            ready << Json{{"port", data.port},
                          {"control_port", control.port},
                          {"state", "listening"},
                          {"test_ready", false}}
                  << '\n';
        }
        status_.stage = "control_accept";
        while ((peer_ = tcp::try_accept(control_listener_)) < 0)
            control::wait(control_listener_, false, deadline_);
    } else {
        status_.stage = "control_connect";
        peer_ = tcp::begin_connect(tcp::prepare_dial(
            config_.source_address, {config_.control_address, config_.control_port}));
        control::wait(peer_, true, deadline_);
        tcp::finish_connect(peer_);
    }
    // Only the control path has been reached. TLS reachability and certificate
    // authentication remain unobserved until the first measured connection.
    status_.control_document = Json{{"transport", "tcp/ipv4"},
                                    {"local", endpoint(tcp::local_endpoint(peer_))},
                                    {"peer", endpoint(tcp::peer_endpoint(peer_))},
                                    {"physical_nic", "unobserved"}}
                                   .dump();
    (void)transport::configure(peer_, true, 65536, 65536, false);
    status_.stage = "scenario";
    control::Waiter peer(peer_);
    negotiate(peer, config_, deadline_, true);
    status_.scenario_agreed = true;
    status_.stage = "local_preparation";
}

void PeerSession::prepare(const model::SampleInfo& info, control::Waiter& peer) {
    const auto local = readiness(info);
    status_.local_document = local.dump();
    status_.stage = "peer_preparation";
    // A peer that cannot prepare sends the ordinary Failed frame here. Only
    // after both readiness barriers succeed do we exchange the JSON summaries.
    PeerProtocol protocol(peer, info.sample);
    protocol.synchronize(control::MessageKind::TcpReady, 0, deadline_);
    const auto remote =
        Json::parse(exchange_preparation(peer, status_.local_document, info.role, deadline_));
    const auto other = info.role == Role::Client ? Role::Server : Role::Client;
    if (remote.at("version") != 1 || remote.at("role") != model::name(other) ||
        remote.at("run_id") != config_.run_id || remote.at("context_id") != config_.context_id ||
        remote.at("sample") != info.sample || remote.at("ready") != true)
        throw std::runtime_error("peer readiness or identity differs");
    status_.peer_document = remote.dump();
    status_.stage = "ready";
}

} // namespace turtle::lifecycle::detail
