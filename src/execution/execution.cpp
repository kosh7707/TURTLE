#include "execution.hpp"
#include "socket/socket.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
namespace turtle {
static turtle_bytes bytes(std::span<const std::uint8_t> v) {
    return {v.data(), v.size()};
}
static turtle_buffer buffer(std::span<std::uint8_t> v) {
    return {v.data(), v.size()};
}
Execution::Execution(const Spec& s, const turtle_implementation& a, turtle_connection* c,
                     Observer& o, int fd, std::uint64_t connection)
    : spec_(s), api_(a), tls_(c), obs_(o), socket_(fd), connection_(connection),
      deadline_(monotonic_ns() + std::uint64_t(s.timeout_ms) * 1000000), message_(s.max_message),
      pending_(s.max_message * 2 + 65536), wire_(18432), decoded_(18432),
      incoming_(s.max_message + 18432), plain_pending_(16384) {
    if (s.stream) {
        tx_stream.reserve(pending_.size() * 2);
        rx_stream.reserve(pending_.size() * 2);
        tx_plain_stream.reserve(pending_.size() * 2);
        rx_plain_stream.reserve(pending_.size() * 2);
    }
}
std::uint64_t Execution::identity(bool outgoing, std::uint64_t n) const {
    return ((outgoing == (spec_.role == TURTLE_SERVER)) ? UINT64_C(1) << 32 : 0) | n;
}
void Execution::checked(bool ok) {
    if (!ok) {
        const char* message = api_.error(tls_);
        throw std::runtime_error(
            message && *message ? message : "implementation operation failed without diagnostic");
    }
}
void Execution::transition(turtle_transition op, unsigned type,
                           std::span<const std::uint8_t> data) {
    Event e{};
    e.kind = Kind::Transition;
    e.connection = connection_;
    e.message = op == TURTLE_BEGIN || op == TURTLE_FINISH ? 0 : current_message_;
    e.outgoing = op == TURTLE_PREPARE_SEND || op == TURTLE_COMMIT_SEND;
    e.type = type;
    e.detail = unsigned(op);
    e.begin = obs_.now();
    int ok = [&] {
        AllocationScope scope(obs_.tracker());
        return api_.transition(tls_, op, type, bytes(data));
    }();
    e.end = obs_.now();
    obs_.add(e);
    checked(ok);
}
void Execution::protect(unsigned type, std::span<const std::uint8_t> data) {
    Event e{};
    e.kind = Kind::Protect;
    e.connection = connection_;
    e.record = identity(true, ++tx_record_);
    e.batch = batch_;
    e.outgoing = true;
    e.type = type;
    e.offset = tx_offset_ + pending_size_;
    e.plain_offset = tx_plain_;
    e.plain_length = data.size();
    e.begin = obs_.now();
    auto p = [&] {
        AllocationScope scope(obs_.tracker());
        return api_.protect(tls_, type, bytes(data), buffer(wire_));
    }();
    e.end = obs_.now();
    checked(p.status == TURTLE_DONE);
    if (p.consumed != data.size() || p.produced > wire_.size() || p.produced < 5)
        throw std::runtime_error("invalid record protection progress");
    if (pending_size_ + p.produced > pending_.size())
        throw std::runtime_error("output batch capacity exhausted");
    e.length = p.produced;
    obs_.add(e);
    e.kind = Kind::Record;
    obs_.add(e);
    std::memcpy(pending_.data() + pending_size_, wire_.data(), p.produced);
    pending_size_ += p.produced;
    if (spec_.stream) {
        if (tx_plain_stream.size() + data.size() > tx_plain_stream.capacity())
            throw std::runtime_error("plaintext capture capacity");
        tx_plain_stream.insert(tx_plain_stream.end(), data.begin(), data.end());
    }
    tx_plain_ += data.size();
}
void Execution::flush_plain() {
    if (plain_pending_size_) {
        protect(22, {plain_pending_.data(), plain_pending_size_});
        plain_pending_size_ = 0;
    }
}
void Execution::submit() {
    flush_plain();
    if (!pending_size_)
        return;
    Event batch{};
    batch.kind = Kind::Batch;
    batch.connection = connection_;
    batch.batch = batch_;
    batch.outgoing = true;
    batch.offset = tx_offset_;
    batch.length = pending_size_;
    batch.begin = obs_.now();
    std::size_t offset = 0;
    while (offset < pending_size_) {
        Event e{};
        e.kind = Kind::Send;
        e.connection = connection_;
        e.batch = batch_;
        e.outgoing = true;
        e.offset = tx_offset_ + offset;
        e.begin = obs_.now();
        std::size_t nmax = pending_size_ - offset;
        if (spec_.io_chunk)
            nmax = std::min(nmax, spec_.io_chunk);
        auto n = send(socket_, pending_.data() + offset, nmax, MSG_NOSIGNAL);
        int error = errno;
        e.end = obs_.now();
        e.length = n > 0 ? std::size_t(n) : 0;
        e.detail = n < 0 ? unsigned(error) : 0;
        obs_.add(e);
        if (n > 0)
            offset += std::size_t(n);
        else if (n < 0 && (error == EAGAIN || error == EWOULDBLOCK))
            wait_socket(socket_, true, deadline_, &obs_, connection_);
        else if (n < 0 && error == EINTR)
            continue;
        else
            throw std::runtime_error("TLS socket send failed");
    }
    batch.end = obs_.now();
    obs_.add(batch);
    if (spec_.stream) {
        if (tx_stream.size() + pending_size_ > tx_stream.capacity())
            throw std::runtime_error("stream capture capacity");
        tx_stream.insert(tx_stream.end(), pending_.begin(),
                         pending_.begin() + std::ptrdiff_t(pending_size_));
    }
    tx_offset_ += pending_size_;
    pending_size_ = 0;
    ++batch_;
}
void Execution::io_receive(std::span<std::uint8_t> out) {
    while (!out.empty()) {
        Event e{};
        e.kind = Kind::Receive;
        e.connection = connection_;
        e.offset = rx_offset_;
        e.begin = obs_.now();
        auto size = spec_.io_chunk ? std::min(out.size(), spec_.io_chunk) : out.size();
        auto n = recv(socket_, out.data(), size, 0);
        int error = errno;
        e.end = obs_.now();
        e.length = n > 0 ? std::size_t(n) : 0;
        e.detail = n < 0 ? unsigned(error) : 0;
        obs_.add(e);
        if (n > 0) {
            if (spec_.stream) {
                if (rx_stream.size() + std::size_t(n) > rx_stream.capacity())
                    throw std::runtime_error("stream capture capacity");
                rx_stream.insert(rx_stream.end(), out.data(), out.data() + n);
            }
            out = out.subspan(std::size_t(n));
            rx_offset_ += std::size_t(n);
        } else if (n == 0)
            throw std::runtime_error("peer closed before scenario completed");
        else if (error == EAGAIN || error == EWOULDBLOCK)
            wait_socket(socket_, false, deadline_, &obs_, connection_);
        else if (error != EINTR)
            throw std::runtime_error("TLS socket receive failed");
    }
}
unsigned Execution::receive_record() {
    io_receive({wire_.data(), 5});
    std::size_t n = (std::size_t(wire_[3]) << 8) | wire_[4];
    if (n + 5 > wire_.size())
        throw std::runtime_error("record capacity exhausted");
    io_receive({wire_.data() + 5, n});
    Event e{};
    e.kind = Kind::Unprotect;
    e.connection = connection_;
    e.record = identity(false, ++rx_record_);
    e.offset = rx_offset_ - n - 5;
    e.length = n + 5;
    e.plain_offset = rx_plain_;
    e.begin = obs_.now();
    unsigned type = 0;
    turtle_progress p{};
    if (wire_[0] == 20) {
        type = 20;
        p = {TURTLE_DONE, n + 5, 0, 0};
    } // TLS 1.3 compatibility CCS has no transcript or keys.
    else
        p = [&] {
            AllocationScope scope(obs_.tracker());
            return api_.unprotect(tls_, {wire_.data(), n + 5}, buffer(decoded_), &type);
        }();
    e.end = obs_.now();
    checked(p.status == TURTLE_DONE);
    if (p.consumed != n + 5 || p.produced > decoded_.size())
        throw std::runtime_error("invalid record unprotection progress");
    e.plain_length = p.produced;
    e.type = type;
    obs_.add(e);
    e.kind = Kind::Record;
    obs_.add(e);
    if (incoming_used_) {
        std::memmove(incoming_.data(), incoming_.data() + incoming_used_,
                     incoming_size_ - incoming_used_);
        incoming_size_ -= incoming_used_;
        incoming_used_ = 0;
    }
    if (incoming_size_ + p.produced > incoming_.size())
        throw std::runtime_error("reassembly capacity exhausted");
    std::memcpy(incoming_.data() + incoming_size_, decoded_.data(), p.produced);
    incoming_size_ += p.produced;
    if (spec_.stream) {
        if (rx_plain_stream.size() + p.produced > rx_plain_stream.capacity())
            throw std::runtime_error("plaintext capture capacity");
        rx_plain_stream.insert(rx_plain_stream.end(), decoded_.data(),
                               decoded_.data() + p.produced);
    }
    rx_plain_ += p.produced;
    return type;
}
void Execution::send_message(unsigned type) {
    current_message_ = identity(true, ++tx_message_);
    transition(TURTLE_PREPARE_SEND, type);
    std::size_t n = 0;
    for (;;) {
        Event e{};
        e.kind = Kind::Assemble;
        e.connection = connection_;
        e.message = current_message_;
        e.type = type;
        e.outgoing = true;
        e.offset = n;
        e.begin = obs_.now();
        auto p = [&] {
            AllocationScope scope(obs_.tracker());
            return api_.assemble(
                tls_, type, n,
                {message_.data() + n, std::min<std::size_t>(4096, message_.size() - n)});
        }();
        e.end = obs_.now();
        e.length = p.produced;
        obs_.add(e);
        checked(p.status != TURTLE_ERROR);
        if (p.produced > std::min<std::size_t>(4096, message_.size() - n) || p.consumed ||
            !p.produced)
            throw std::runtime_error("invalid assembly progress");
        n += p.produced;
        if (p.status == TURTLE_DONE)
            break;
        if (n == message_.size())
            throw std::runtime_error("message capacity exhausted");
    }
    if (n < 4 || message_[0] != type ||
        ((std::size_t(message_[1]) << 16) | (std::size_t(message_[2]) << 8) | message_[3]) + 4 != n)
        throw std::runtime_error("assembled message header mismatch");
    Event link{};
    link.kind = Kind::Message;
    link.connection = connection_;
    link.message = current_message_;
    link.type = type;
    link.outgoing = true;
    link.plain_offset = tx_plain_ + plain_pending_size_;
    link.plain_length = n;
    obs_.add(link);
    std::size_t offset = 0;
    while (offset < n) {
        auto count = std::min(n - offset, spec_.record_size - plain_pending_size_);
        std::memcpy(plain_pending_.data() + plain_pending_size_, message_.data() + offset, count);
        plain_pending_size_ += count;
        offset += count;
        if (plain_pending_size_ == spec_.record_size)
            flush_plain();
    }
    // Hello/Finished change protection state. Protect their last fragment before committing keys.
    if (!spec_.bundle || type == TURTLE_CLIENT_HELLO || type == TURTLE_SERVER_HELLO ||
        type == TURTLE_FINISHED)
        flush_plain();
    transition(TURTLE_COMMIT_SEND, type, {message_.data(), n});
    if (type == TURTLE_SERVER_HELLO && spec_.hello_first)
        submit();
}
void Execution::receive_message(unsigned type) {
    auto available = [&] { return incoming_size_ - incoming_used_; };
    auto need = [&](std::size_t count) {
        while (available() < count) {
            unsigned record_type = receive_record();
            if (record_type != 22 && record_type != 20)
                throw std::runtime_error("expected handshake record");
        }
    };
    need(4);
    auto* data = incoming_.data() + incoming_used_;
    std::size_t n = 4 + (std::size_t(data[1]) << 16) + (std::size_t(data[2]) << 8) + data[3];
    if (n > spec_.max_message)
        throw std::runtime_error("logical message capacity exhausted");
    need(n);
    data = incoming_.data() + incoming_used_;
    if (data[0] != type)
        throw std::runtime_error("unexpected logical message: expected " + std::to_string(type) +
                                 ", received " + std::to_string(data[0]));
    current_message_ = identity(false, ++rx_message_);
    transition(TURTLE_PREPARE_RECEIVE, type, {data, n});
    Event e{};
    std::size_t offset = 0;
    while (offset < n) {
        e = {};
        e.kind = Kind::Process;
        e.connection = connection_;
        e.message = current_message_;
        e.type = type;
        auto count = std::min<std::size_t>(4096, n - offset);
        e.offset = offset;
        e.begin = obs_.now();
        auto p = [&] {
            AllocationScope scope(obs_.tracker());
            return api_.process(tls_, type, {data + offset, count}, offset + count == n);
        }();
        e.end = obs_.now();
        e.length = p.consumed;
        obs_.add(e);
        checked(p.status != TURTLE_ERROR);
        if (!p.consumed || p.consumed > count || p.produced ||
            (p.status == TURTLE_DONE) != (offset + p.consumed == n))
            throw std::runtime_error("invalid processing progress");
        offset += p.consumed;
    }
    transition(TURTLE_COMMIT_RECEIVE, type, {data, n});
    e = {};
    e.kind = Kind::Message;
    e.connection = connection_;
    e.message = current_message_;
    e.type = type;
    e.plain_offset = rx_message_offset_;
    e.plain_length = n;
    obs_.add(e);
    rx_message_offset_ += n;
    incoming_used_ += n;
}
static std::uint8_t payload(std::size_t offset, turtle_role sender) {
    return std::uint8_t((offset * 17 + (sender == TURTLE_CLIENT ? 0x43 : 0x53)) & 255);
}
void Execution::send_application(std::size_t size) {
    flush_plain();
    current_message_ = identity(true, ++tx_message_);
    Event e{};
    e.kind = Kind::Assemble;
    e.connection = connection_;
    e.message = current_message_;
    e.type = TURTLE_APPLICATION;
    e.outgoing = true;
    e.length = size;
    e.begin = obs_.now();
    for (std::size_t i = 0; i < size; ++i)
        message_[i] = payload(i, spec_.role);
    e.end = obs_.now();
    obs_.add(e);
    e.kind = Kind::Message;
    e.plain_offset = tx_plain_;
    e.plain_length = size;
    obs_.add(e);
    for (std::size_t off = 0; off < size;) {
        auto n = std::min(size - off, spec_.record_size);
        protect(23, {message_.data() + off, n});
        off += n;
    }
}
void Execution::receive_application(std::size_t size) {
    current_message_ = identity(false, ++rx_message_);
    std::size_t got = 0;
    auto start = rx_message_offset_;
    while (got < size) {
        if (incoming_size_ == incoming_used_) {
            auto type = receive_record();
            if (type == 20)
                continue;
            if (type != 23)
                throw std::runtime_error("expected encrypted application record");
        }
        auto n = std::min(size - got, incoming_size_ - incoming_used_);
        Event e{};
        e.kind = Kind::Process;
        e.connection = connection_;
        e.message = current_message_;
        e.type = TURTLE_APPLICATION;
        e.offset = got;
        e.begin = obs_.now();
        for (std::size_t i = 0; i < n; ++i)
            if (incoming_[incoming_used_ + i] !=
                payload(got + i, spec_.role == TURTLE_CLIENT ? TURTLE_SERVER : TURTLE_CLIENT))
                throw std::runtime_error("application payload mismatch");
        e.end = obs_.now();
        e.length = n;
        obs_.add(e);
        got += n;
        incoming_used_ += n;
        rx_message_offset_ += n;
    }
    Event e{};
    e.kind = Kind::Message;
    e.connection = connection_;
    e.message = current_message_;
    e.type = TURTLE_APPLICATION;
    e.plain_offset = start;
    e.plain_length = size;
    obs_.add(e);
}
turtle_result Execution::run() {
    Event scenario{};
    scenario.kind = Kind::Scenario;
    scenario.connection = connection_;
    scenario.begin = obs_.now(false);
    try {
        transition(TURTLE_BEGIN, 0);
        const bool ping =
            spec_.scenario == Scenario::ServerPing || spec_.scenario == Scenario::FinishedPing;
        auto server_flight = [&](auto&& message) {
            message(TURTLE_SERVER_HELLO);
            message(TURTLE_ENCRYPTED_EXTENSIONS);
            if (spec_.mutual)
                message(TURTLE_CERTIFICATE_REQUEST);
            message(TURTLE_CERTIFICATE);
            message(TURTLE_CERTIFICATE_VERIFY);
            message(TURTLE_FINISHED);
        };
        auto client_flight = [&](auto&& message) {
            if (spec_.mutual) {
                message(TURTLE_CERTIFICATE);
                message(TURTLE_CERTIFICATE_VERIFY);
            }
            message(TURTLE_FINISHED);
        };
        if (spec_.role == TURTLE_CLIENT) {
            send_message(TURTLE_CLIENT_HELLO);
            submit();
            server_flight([&](unsigned t) { receive_message(t); });
            client_flight([&](unsigned t) { send_message(t); });
            submit();
            transition(TURTLE_FINISH, 0);
            if (ping) {
                receive_application(spec_.server_bytes);
                send_application(spec_.client_bytes);
                submit();
            } else if (spec_.scenario == Scenario::ClientRequest) {
                send_application(spec_.client_bytes);
                submit();
                receive_application(spec_.server_bytes);
            }
        } else {
            receive_message(TURTLE_CLIENT_HELLO);
            server_flight([&](unsigned t) { send_message(t); });
            if (spec_.scenario != Scenario::FinishedPing)
                submit();
            if (ping) {
                send_application(spec_.server_bytes);
                submit();
            }
            client_flight([&](unsigned t) { receive_message(t); });
            transition(TURTLE_FINISH, 0);
            if (ping)
                receive_application(spec_.client_bytes);
            else if (spec_.scenario == Scenario::ClientRequest) {
                receive_application(spec_.client_bytes);
                send_application(spec_.server_bytes);
                submit();
            }
        }
        auto r = api_.result(tls_);
        if (!r.full_handshake || ((spec_.role == TURTLE_CLIENT || spec_.mutual) &&
                                  (!r.peer_verified || !r.peer_certificate)))
            throw std::runtime_error("full handshake/peer authentication not confirmed");
        scenario.end = obs_.now(false);
        obs_.add(scenario);
        return r;
    } catch (...) {
        scenario.end = obs_.now(false);
        scenario.detail = 1;
        obs_.add(scenario);
        throw;
    }
}
} // namespace turtle
