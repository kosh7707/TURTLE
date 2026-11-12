#include "lifecycle/endpoint_protocol.hpp"
#include <array>
#include <cerrno>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace turtle::lifecycle::detail {
namespace {
void transfer(control::Waiter& peer, char* data, std::size_t size, bool writing,
              control::Deadline deadline) {
    std::size_t offset = 0;
    while (offset < size) {
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("control preparation deadline exceeded");
        const auto n =
            writing ? ::send(peer.fd(), data + offset, size - offset, MSG_DONTWAIT | MSG_NOSIGNAL)
                    : ::recv(peer.fd(), data + offset, size - offset, MSG_DONTWAIT);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            peer.wait(writing, deadline);
            continue;
        }
        throw std::runtime_error("control preparation stream ended");
    }
}
void write_json(control::Waiter& peer, const nlohmann::json& value, control::Deadline deadline) {
    auto bytes = value.dump();
    if (bytes.size() > 16384)
        throw std::runtime_error("control preparation exceeds capacity");
    std::array<char, 4> length{};
    for (unsigned i = 0; i < 4; ++i)
        length[i] = static_cast<char>(bytes.size() >> (24 - 8 * i));
    transfer(peer, length.data(), length.size(), true, deadline);
    transfer(peer, bytes.data(), bytes.size(), true, deadline);
}
nlohmann::json read_json(control::Waiter& peer, control::Deadline deadline) {
    std::array<char, 4> length{};
    transfer(peer, length.data(), length.size(), false, deadline);
    std::size_t size = 0;
    for (const auto byte : length)
        size = (size << 8U) | static_cast<unsigned char>(byte);
    if (!size || size > 16384)
        throw std::runtime_error("invalid control preparation length");
    std::string bytes(size, '\0');
    transfer(peer, bytes.data(), bytes.size(), false, deadline);
    return nlohmann::json::parse(bytes);
}
} // namespace
void negotiate(control::Waiter& peer, model::RunConfig& config, control::Deadline deadline,
               bool readiness) {
    using Json = nlohmann::json;
    Json local{{"protocol", control::protocol_version},
               {"readiness_version", readiness ? 1 : 0},
               {"role", model::name(config.role)},
               {"run_id", config.run_id},
               {"context_id", config.context_id},
               {"sample", config.sample},
               {"batch", config.batch},
               {"scenario", Json::parse(config.scenario_document)}};
    auto check = [&](const Json& remote) {
        const auto other = config.role == Role::Client ? Role::Server : Role::Client;
        if (remote.at("protocol") != control::protocol_version ||
            remote.at("role") != model::name(other) ||
            remote.value("readiness_version", 0) != (readiness ? 1 : 0) ||
            remote.at("scenario") != local.at("scenario") ||
            remote.at("context_id") != local.at("context_id") ||
            remote.at("sample") != local.at("sample") || remote.at("batch") != local.at("batch"))
            throw std::runtime_error("peer identity or shared scenario differs");
        const auto id = remote.at("run_id").get<std::string>();
        if (id.empty() || id.size() > 128 || (!config.run_id.empty() && config.run_id != id))
            throw std::runtime_error("peer run identity differs");
        config.run_id = id;
    };
    if (config.role == Role::Client) {
        write_json(peer, local, deadline);
        check(read_json(peer, deadline));
    } else {
        check(read_json(peer, deadline));
        local["run_id"] = config.run_id;
        write_json(peer, local, deadline);
    }
}
std::string exchange_preparation(control::Waiter& peer, const std::string& local, Role role,
                                 control::Deadline deadline) {
    const auto value = nlohmann::json::parse(local);
    if (role == Role::Client) {
        write_json(peer, value, deadline);
        return read_json(peer, deadline).dump();
    }
    auto remote = read_json(peer, deadline);
    write_json(peer, value, deadline);
    return remote.dump();
}
void PeerProtocol::synchronize(control::MessageKind kind, std::uint32_t connection,
                               control::Deadline deadline) {
    control::Message message;
    message.kind = kind;
    message.sample = sample_;
    message.connection = connection;
    control::send_message(peer_, message, deadline);
    const auto remote = control::receive_message(peer_, deadline);
    if (remote.kind == control::MessageKind::Failed)
        throw std::runtime_error("peer aborted: " + remote.reason);
    if (remote.kind != kind || remote.sample != sample_ || remote.connection != connection)
        throw std::runtime_error("peer phase or connection identity differs");
}

void PeerProtocol::fail(const std::string& reason, control::Deadline deadline) noexcept {
    try {
        control::Message message;
        message.kind = control::MessageKind::Failed;
        message.sample = sample_;
        message.reason = reason;
        control::send_message(peer_, message, deadline);
    } catch (...) {
    }
}
void close_all(std::span<int> sockets) noexcept {
    for (int& fd : sockets) {
        if (fd >= 0)
            ::close(fd);
        fd = -1;
    }
}
} // namespace turtle::lifecycle::detail
