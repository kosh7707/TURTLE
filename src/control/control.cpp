#include "control/control.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace turtle::control {
namespace {
constexpr std::size_t message_address_size = 15;
constexpr std::size_t message_reason_size = 255;
constexpr std::size_t message_frame_size = 312;
constexpr std::size_t maximum_json_line_size = 4096;
constexpr std::size_t maximum_json_payload_size = maximum_json_line_size - 1;
constexpr std::array<unsigned char, 4> message_magic{'T', 'C', 'T', 'L'};
constexpr std::uint16_t message_version = 1;

int timeout_ms(Deadline deadline) {
    const auto remaining = deadline - std::chrono::steady_clock::now();
    if (remaining <= Deadline::duration::zero())
        throw std::runtime_error("operation deadline exceeded");
    const auto rounded = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
    return static_cast<int>(std::min<std::int64_t>(rounded, INT_MAX));
}

void put_u16(unsigned char* output, std::uint16_t value) noexcept {
    output[0] = static_cast<unsigned char>(value >> 8U);
    output[1] = static_cast<unsigned char>(value);
}
void put_u32(unsigned char* output, std::uint32_t value) noexcept {
    for (unsigned int i = 0; i != 4; ++i)
        output[i] = static_cast<unsigned char>(value >> (24U - i * 8U));
}
void put_u64(unsigned char* output, std::uint64_t value) noexcept {
    for (unsigned int i = 0; i != 8; ++i)
        output[i] = static_cast<unsigned char>(value >> (56U - i * 8U));
}
std::uint16_t get_u16(const unsigned char* input) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[0]) << 8U) |
                                      static_cast<std::uint16_t>(input[1]));
}
std::uint32_t get_u32(const unsigned char* input) noexcept {
    std::uint32_t value = 0;
    for (unsigned int i = 0; i != 4; ++i)
        value = (value << 8U) | input[i];
    return value;
}
std::uint64_t get_u64(const unsigned char* input) noexcept {
    std::uint64_t value = 0;
    for (unsigned int i = 0; i != 8; ++i)
        value = (value << 8U) | input[i];
    return value;
}

bool valid_kind(MessageKind kind) noexcept {
    return kind >= MessageKind::NamespaceReady && kind <= MessageKind::Exit;
}

void validate_address(MessageKind kind, std::string_view address, std::uint16_t port) {
    if (kind != MessageKind::ReadyAddress) {
        if (!address.empty() || port != 0)
            throw std::runtime_error("address is only valid in ready-address messages");
        return;
    }
    if (address.empty() || address.size() > message_address_size)
        throw std::runtime_error("ready-address message has an invalid IPv4 address length");
    in_addr parsed{};
    std::array<char, message_address_size + 1> text{};
    std::memcpy(text.data(), address.data(), address.size());
    if (::inet_pton(AF_INET, text.data(), &parsed) != 1)
        throw std::runtime_error("ready-address message is not numeric IPv4");
}

void validate_cleanup_deadline(MessageKind kind, std::uint64_t deadline) {
    if (deadline != 0 && kind != MessageKind::Flush && kind != MessageKind::AbortFlush)
        throw std::runtime_error("cleanup deadline is only valid in flush messages");
}

void validate_reason(MessageKind kind, std::string_view reason) {
    if (kind != MessageKind::Failed && !reason.empty())
        throw std::runtime_error("failure reason is only valid in failed messages");
}

void send_all(Waiter& waiter, const unsigned char* data, std::size_t size, Deadline deadline) {
    std::size_t offset = 0;
    while (offset != size) {
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("operation deadline exceeded");
        const auto sent = ::send(waiter.fd(), data + offset, size - offset,
                                 MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            waiter.wait(true, deadline);
            continue;
        }
        throw std::runtime_error("control message send failed");
    }
}

void receive_all(Waiter& waiter, unsigned char* data, std::size_t size, Deadline deadline) {
    std::size_t offset = 0;
    while (offset != size) {
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("operation deadline exceeded");
        const auto received = ::recv(waiter.fd(), data + offset, size - offset, MSG_DONTWAIT);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0)
            throw std::runtime_error("control peer closed before message completed");
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            waiter.wait(false, deadline);
            continue;
        }
        throw std::runtime_error("control message receive failed");
    }
}

std::array<unsigned char, message_frame_size> encode_message(const Message& message) {
    if (!valid_kind(message.kind))
        throw std::runtime_error("invalid control message kind");
    validate_address(message.kind, message.address, message.port);
    validate_cleanup_deadline(message.kind, message.cleanup_deadline_monotonic_ns);
    validate_reason(message.kind, message.reason);

    std::array<unsigned char, message_frame_size> frame{};
    std::copy(message_magic.begin(), message_magic.end(), frame.begin());
    put_u16(frame.data() + 4, message_version);
    put_u16(frame.data() + 6, static_cast<std::uint16_t>(message.kind));
    put_u64(frame.data() + 8, message.sample);
    put_u32(frame.data() + 16, message.connection);
    put_u64(frame.data() + 20, message.request_id);
    put_u64(frame.data() + 28, message.cleanup_deadline_monotonic_ns);
    frame[36] = message.cache_hit ? 1U : 0U;
    frame[37] = static_cast<unsigned char>(message.address.size());
    put_u16(frame.data() + 38, message.port);
    std::copy(message.address.begin(), message.address.end(), frame.begin() + 40);
    const std::size_t reason_size = std::min(message.reason.size(), message_reason_size);
    frame[55] = static_cast<unsigned char>(reason_size);
    frame[56] = message.reason.size() > message_reason_size ? 1U : 0U;
    std::copy_n(message.reason.begin(), reason_size, frame.begin() + 57);
    return frame;
}

Message decode_message(const std::array<unsigned char, message_frame_size>& frame) {
    if (!std::equal(message_magic.begin(), message_magic.end(), frame.begin()) ||
        get_u16(frame.data() + 4) != message_version)
        throw std::runtime_error("invalid control message header");
    const auto raw_kind = get_u16(frame.data() + 6);
    if (raw_kind > static_cast<std::uint16_t>(MessageKind::Exit))
        throw std::runtime_error("invalid control message kind");
    if (frame[36] > 1U || frame[37] > message_address_size || frame[56] > 1U)
        throw std::runtime_error("invalid control message fields");
    const auto address_size = static_cast<std::size_t>(frame[37]);
    if (std::any_of(frame.begin() + 40 + address_size, frame.begin() + 55,
                    [](unsigned char value) { return value != 0; }))
        throw std::runtime_error("invalid control message address padding");
    const auto reason_size = static_cast<std::size_t>(frame[55]);
    const bool reason_truncated = frame[56] != 0;
    if ((reason_truncated && reason_size != message_reason_size) ||
        std::any_of(frame.begin() + 57 + reason_size, frame.end(),
                    [](unsigned char value) { return value != 0; }))
        throw std::runtime_error("invalid control message reason encoding");

    Message message;
    message.kind = static_cast<MessageKind>(raw_kind);
    message.sample = get_u64(frame.data() + 8);
    message.connection = get_u32(frame.data() + 16);
    message.request_id = get_u64(frame.data() + 20);
    message.cleanup_deadline_monotonic_ns = get_u64(frame.data() + 28);
    message.cache_hit = frame[36] != 0;
    message.address.assign(reinterpret_cast<const char*>(frame.data() + 40), address_size);
    message.port = get_u16(frame.data() + 38);
    message.reason.assign(reinterpret_cast<const char*>(frame.data() + 57), reason_size);
    if (reason_truncated)
        message.reason += "[truncated]";
    validate_address(message.kind, message.address, message.port);
    validate_cleanup_deadline(message.kind, message.cleanup_deadline_monotonic_ns);
    validate_reason(message.kind, message.reason);
    return message;
}

} // namespace

const char* name(Phase value) noexcept {
    switch (value) {
    case Phase::Setup: return "setup";
    case Phase::Scenario: return "scenario";
    case Phase::Cleanup: return "cleanup";
    }
    return "unknown";
}
const char* name(PhaseEdge value) noexcept {
    switch (value) {
    case PhaseEdge::Begin: return "begin";
    case PhaseEdge::End: return "end";
    }
    return "unknown";
}
const char* name(MessageKind value) noexcept {
    switch (value) {
    case MessageKind::NamespaceReady: return "namespace_ready";
    case MessageKind::ReadyAddress: return "ready_address";
    case MessageKind::TcpReady: return "tcp_ready";
    case MessageKind::Start: return "start";
    case MessageKind::ResponseComplete: return "response_complete";
    case MessageKind::LookupSkipped: return "lookup_skipped";
    case MessageKind::ConnectionComplete: return "connection_complete";
    case MessageKind::Flush: return "flush";
    case MessageKind::AbortFlush: return "abort_flush";
    case MessageKind::Flushed: return "flushed";
    case MessageKind::Failed: return "failed";
    case MessageKind::Exit: return "exit";
    }
    return "unknown";
}

Waiter::Waiter(int fd) : fd_(fd), epoll_(::epoll_create1(EPOLL_CLOEXEC)) {
    if (fd_ < 0) {
        if (epoll_ >= 0)
            ::close(epoll_);
        throw std::invalid_argument("wait descriptor is invalid");
    }
    if (epoll_ < 0)
        throw std::runtime_error("epoll preparation failed");
    epoll_event event{};
    event.events = EPOLLIN | EPOLLRDHUP;
    if (::epoll_ctl(epoll_, EPOLL_CTL_ADD, fd_, &event)) {
        ::close(epoll_);
        throw std::runtime_error("epoll registration failed");
    }
}
Waiter::~Waiter() {
    if (epoll_ >= 0)
        ::close(epoll_);
}
void Waiter::wait(bool writing, Deadline deadline) {
    epoll_event event{};
    event.events = (writing ? EPOLLOUT : EPOLLIN) | EPOLLRDHUP;
    if (::epoll_ctl(epoll_, EPOLL_CTL_MOD, fd_, &event))
        throw std::runtime_error("epoll interest failed");
    for (;;) {
        const int rc = ::epoll_wait(epoll_, &event, 1, timeout_ms(deadline));
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc == 0)
            throw std::runtime_error("operation deadline exceeded");
        if (rc < 0)
            throw std::runtime_error("epoll wait failed");
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("operation deadline exceeded");
        if (event.events & (writing ? EPOLLOUT : EPOLLIN))
            return;
        throw std::runtime_error("peer closed before operation completed");
    }
}

WaitSet::WaitSet(int data_fd, int control_fd)
    : data_fd_(data_fd), control_fd_(control_fd), epoll_(::epoll_create1(EPOLL_CLOEXEC)) {
    if (data_fd_ < 0 || control_fd_ < 0 || data_fd_ == control_fd_) {
        if (epoll_ >= 0)
            ::close(epoll_);
        throw std::invalid_argument("wait-set descriptors are invalid");
    }
    if (epoll_ < 0)
        throw std::runtime_error("wait-set epoll preparation failed");
    epoll_event event{};
    event.events = EPOLLIN | EPOLLRDHUP;
    event.data.u32 = 0;
    if (::epoll_ctl(epoll_, EPOLL_CTL_ADD, data_fd_, &event)) {
        ::close(epoll_);
        throw std::runtime_error("wait-set data registration failed");
    }
    event.data.u32 = 1;
    if (::epoll_ctl(epoll_, EPOLL_CTL_ADD, control_fd_, &event)) {
        ::close(epoll_);
        throw std::runtime_error("wait-set control registration failed");
    }
}
WaitSet::~WaitSet() {
    if (epoll_ >= 0)
        ::close(epoll_);
}
WaitSet::Ready WaitSet::wait(bool data_writing, Deadline deadline) {
    epoll_event interest{};
    interest.events = (data_writing ? EPOLLOUT : EPOLLIN) | EPOLLRDHUP;
    interest.data.u32 = 0;
    if (::epoll_ctl(epoll_, EPOLL_CTL_MOD, data_fd_, &interest))
        throw std::runtime_error("wait-set data interest failed");
    for (;;) {
        std::array<epoll_event, 2> events{};
        const int count = ::epoll_wait(epoll_, events.data(), static_cast<int>(events.size()),
                                       timeout_ms(deadline));
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0)
            throw std::runtime_error("operation deadline exceeded");
        if (count < 0)
            throw std::runtime_error("wait-set epoll wait failed");
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("operation deadline exceeded");
        for (int i = 0; i != count; ++i)
            if (events[static_cast<std::size_t>(i)].data.u32 == 1)
                return Ready::Control;
        for (int i = 0; i != count; ++i)
            if (events[static_cast<std::size_t>(i)].data.u32 == 0)
                return Ready::Data;
    }
}

void send_message(Waiter& waiter, const Message& message, Deadline deadline) {
    const auto frame = encode_message(message);
    send_all(waiter, frame.data(), frame.size(), deadline);
}
Message receive_message(Waiter& waiter, Deadline deadline) {
    std::array<unsigned char, message_frame_size> frame{};
    receive_all(waiter, frame.data(), frame.size(), deadline);
    return decode_message(frame);
}
void wait(int fd, bool writing, Deadline deadline) {
    Waiter waiter(fd);
    waiter.wait(writing, deadline);
}
void barrier(Waiter& waiter, Deadline deadline) {
    const char ready = 1;
    waiter.wait(true, deadline);
    if (::send(waiter.fd(), &ready, 1, MSG_NOSIGNAL) != 1)
        throw std::runtime_error("ready signal failed");
    waiter.wait(false, deadline);
    char peer = 0;
    if (::recv(waiter.fd(), &peer, 1, 0) != 1 || peer != ready)
        throw std::runtime_error("peer not ready");
}
void barrier(int fd, Deadline deadline) {
    Waiter waiter(fd);
    barrier(waiter, deadline);
}
void isolate() {
    const rlimit limit{0, 0};
    if (::setrlimit(RLIMIT_NOFILE, &limit) || ::setrlimit(RLIMIT_NPROC, &limit))
        throw std::runtime_error("resource isolation failed");
}

namespace {
constexpr auto killed_child_reap_budget = std::chrono::milliseconds(250);

ReapResult reap_children(std::span<const pid_t> children, Deadline deadline) {
    struct Child { pid_t pid; bool pending = true; };
    std::vector<Child> owned;
    owned.reserve(children.size());
    for (const pid_t pid : children) {
        if (pid <= 0)
            continue;
        const auto duplicate = std::find_if(owned.begin(), owned.end(),
                                            [pid](const Child& child) { return child.pid == pid; });
        if (duplicate == owned.end())
            owned.push_back({pid, true});
    }

    ReapResult outcome;
    for (;;) {
        bool any_pending = false;
        for (auto& child : owned) {
            if (!child.pending)
                continue;
            int status = 0;
            const pid_t result = ::waitpid(child.pid, &status, WNOHANG);
            if (result == child.pid) {
                child.pending = false;
                outcome.all_success = outcome.all_success && WIFEXITED(status) &&
                                      WEXITSTATUS(status) == 0;
            } else if (result == 0 || (result < 0 && errno == EINTR)) {
                any_pending = true;
            } else {
                child.pending = false;
                outcome.all_reaped = false;
                outcome.all_success = false;
            }
        }
        if (!any_pending)
            return outcome;
        if (std::chrono::steady_clock::now() >= deadline)
            break;
        std::this_thread::sleep_until(
            std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(1)));
    }

    // The caller's grace has expired. SIGKILL does not extend that deadline;
    // this separate fixed window only gives the kernel a bounded chance to
    // publish and reap the resulting exits.
    outcome.all_success = false;
    outcome.forced_kill = true;
    for (const auto& child : owned)
        if (child.pending)
            (void)::kill(child.pid, SIGKILL);

    const Deadline recovery_deadline = std::chrono::steady_clock::now() +
                                       killed_child_reap_budget;
    for (;;) {
        bool any_pending = false;
        for (auto& child : owned) {
            if (!child.pending)
                continue;
            const pid_t result = ::waitpid(child.pid, nullptr, WNOHANG);
            if (result == child.pid) {
                child.pending = false;
            } else if (result == 0 || (result < 0 && errno == EINTR)) {
                any_pending = true;
            } else {
                child.pending = false;
                outcome.all_reaped = false;
            }
        }
        if (!any_pending)
            return outcome;
        if (std::chrono::steady_clock::now() >= recovery_deadline) {
            outcome.all_reaped = false;
            return outcome;
        }
        std::this_thread::sleep_until(
            std::min(recovery_deadline,
                     std::chrono::steady_clock::now() + std::chrono::milliseconds(1)));
    }
}
} // namespace

ReapResult reap_result(std::span<const pid_t> children, Deadline deadline) {
    return reap_children(children, deadline);
}
bool reap_owned(std::span<const pid_t> children, Deadline deadline) {
    return reap_result(children, deadline).all_reaped;
}
bool reap(pid_t server, pid_t client, Deadline deadline) {
    const std::array<pid_t, 2> children{server, client};
    const auto outcome = reap_result(children, deadline);
    return outcome.all_reaped && outcome.all_success;
}

void enter_network_namespace(int namespace_fd) {
    if (namespace_fd < 0)
        throw std::invalid_argument("network namespace descriptor is invalid");
    if (::setns(namespace_fd, CLONE_NEWNET) < 0)
        throw std::system_error(errno, std::generic_category(), "network namespace entry failed");
}

PhaseAck exchange_phase(int phase_control_fd, std::uint64_t attempt, Phase phase,
                        PhaseEdge edge, Deadline deadline) {
    using Json = nlohmann::json;
    Json request{{"type", "phase"}, {"schema", 1}, {"attempt", attempt},
                 {"phase", name(phase)}, {"edge", name(edge)}};
    std::string request_line = request.dump();
    if (request_line.size() > maximum_json_payload_size)
        throw std::runtime_error("phase request exceeds JSON-line limit");
    request_line.push_back('\n');

    Waiter waiter(phase_control_fd);
    send_all(waiter, reinterpret_cast<const unsigned char*>(request_line.data()),
             request_line.size(), deadline);

    std::string response_line;
    response_line.reserve(256);
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("operation deadline exceeded");
        unsigned char byte = 0;
        const auto received = ::recv(phase_control_fd, &byte, 1, MSG_DONTWAIT);
        if (received == 1) {
            if (byte == '\n')
                break;
            if (response_line.size() == maximum_json_payload_size)
                throw std::runtime_error("phase acknowledgement exceeds JSON-line limit");
            response_line.push_back(static_cast<char>(byte));
            continue;
        }
        if (received == 0)
            throw std::runtime_error("phase control peer closed before acknowledgement");
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            waiter.wait(false, deadline);
            continue;
        }
        throw std::runtime_error("phase acknowledgement receive failed");
    }

    Json response;
    try {
        response = Json::parse(response_line);
    } catch (const Json::exception&) {
        throw std::runtime_error("phase acknowledgement is not valid JSON");
    }
    if (!response.is_object() || response.size() != 6 || !response.contains("type") ||
        !response.contains("schema") || !response.contains("attempt") ||
        !response.contains("phase") || !response.contains("edge") ||
        !response.contains("observation_id") || !response["type"].is_string() ||
        !response["schema"].is_number_unsigned() ||
        !response["attempt"].is_number_unsigned() || !response["phase"].is_string() ||
        !response["edge"].is_string() || !response["observation_id"].is_string())
        throw std::runtime_error("phase acknowledgement has invalid fields");

    const std::string expected_observation = std::to_string(attempt) + ":" + name(phase) +
                                             ":" + name(edge);
    if (response["type"].get_ref<const std::string&>() != "ack" ||
        response["schema"].get<std::uint64_t>() != 1 ||
        response["attempt"].get<std::uint64_t>() != attempt ||
        response["phase"].get_ref<const std::string&>() != name(phase) ||
        response["edge"].get_ref<const std::string&>() != name(edge) ||
        response["observation_id"].get_ref<const std::string&>() != expected_observation)
        throw std::runtime_error("phase acknowledgement does not match request");
    return {attempt, phase, edge, expected_observation};
}
} // namespace turtle::control
