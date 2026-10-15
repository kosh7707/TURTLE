#include "lookup/lookup.hpp"
#include "measure/measure.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
using turtle::Io;
using turtle::lookup::Progress;

constexpr std::string_view opaque_fixture =
    "-----BEGIN CERTIFICATE-----\n"
    "TURTLE loopback opaque fixture; not TLS verification evidence\n"
    "-----END CERTIFICATE-----\n";

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

void exact_write(int fd, const void* data, std::size_t size) {
    auto* cursor = static_cast<const std::uint8_t*>(data);
    while (size != 0) {
        const auto written = ::write(fd, cursor, size);
        if (written < 0 && errno == EINTR)
            continue;
        require(written > 0, "pipe write failed");
        cursor += written;
        size -= static_cast<std::size_t>(written);
    }
}

void exact_read(int fd, void* data, std::size_t size) {
    auto* cursor = static_cast<std::uint8_t*>(data);
    while (size != 0) {
        const auto received = ::read(fd, cursor, size);
        if (received < 0 && errno == EINTR)
            continue;
        require(received > 0, "pipe read failed");
        cursor += received;
        size -= static_cast<std::size_t>(received);
    }
}

struct EventCounts {
    std::array<std::uint32_t, 9> values{};
    static void observe(void* opaque, const turtle::lookup::Observation& event) noexcept {
        auto& self = *static_cast<EventCounts*>(opaque);
        const auto index = static_cast<std::size_t>(event.kind);
        if (index < self.values.size())
            ++self.values[index];
    }
    turtle::lookup::Observer observer() noexcept {
        return {this, observe};
    }
    std::uint32_t get(turtle::lookup::SemanticEventKind kind) const noexcept {
        return values[static_cast<std::size_t>(kind)];
    }
};

struct ChannelCounts {
    std::size_t send_returns = 0;
    std::size_t recv_returns = 0;
    std::size_t successful_sends = 0;
    std::size_t successful_receives = 0;
    std::size_t sent_bytes = 0;
    std::size_t received_bytes = 0;
    static void observe(void* opaque, const turtle::transport::Observation& event) noexcept {
        if (event.entering)
            return;
        auto& self = *static_cast<ChannelCounts*>(opaque);
        if (event.sending)
            ++self.send_returns;
        else
            ++self.recv_returns;
        if (event.result.status != turtle::IoStatus::Ok)
            return;
        if (event.sending) {
            ++self.successful_sends;
            self.sent_bytes += event.result.bytes;
        } else {
            ++self.successful_receives;
            self.received_bytes += event.result.bytes;
        }
    }
};

struct MeasuredEvents {
    EventCounts counts;
    turtle::measure::Meter* meter = nullptr;
    turtle::model::Snapshot ca_begin;
    turtle::model::Snapshot ca_end;
    bool saw_begin = false;
    bool saw_end = false;

    static void observe(void* opaque, const turtle::lookup::Observation& event) noexcept {
        auto& self = *static_cast<MeasuredEvents*>(opaque);
        EventCounts::observe(&self.counts, event);
        if (event.kind == turtle::lookup::SemanticEventKind::CaProcessBegin) {
            self.ca_begin = self.meter->read(false);
            self.saw_begin = true;
        } else if (event.kind == turtle::lookup::SemanticEventKind::CaProcessEnd) {
            self.ca_end = self.meter->read(false);
            self.saw_end = true;
        }
    }
    turtle::lookup::Observer observer() noexcept {
        return {this, observe};
    }
};

void make_nonblocking(int fd) {
    const auto flags = ::fcntl(fd, F_GETFL);
    require(flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
            "could not make loopback socket nonblocking");
}

struct WaitMeasurements {
    std::size_t count = 0;
    std::uint64_t elapsed_ns = 0;
    bool timed = false;
};

template <typename Operation>
void drive(Operation& operation, Io& io, WaitMeasurements& waits) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        const auto progress = operation.advance(io);
        if (progress == Progress::Complete)
            return;
        require(progress != Progress::Failed, operation.error());
        ++waits.count;
        pollfd descriptor{io.native_socket,
                          static_cast<short>(progress == Progress::WantWrite ? POLLOUT : POLLIN),
                          0};
        int result;
        const auto wait_begin = std::chrono::steady_clock::now();
        do {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            require(remaining.count() > 0, "loopback lookup timed out");
            result = ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
        } while (result < 0 && errno == EINTR);
        const auto wait_end = std::chrono::steady_clock::now();
        waits.elapsed_ns += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(wait_end - wait_begin).count());
        waits.timed = true;
        require(result > 0 && !(descriptor.revents & (POLLERR | POLLNVAL)),
                "loopback readiness wait failed");
    }
}

std::vector<std::uint8_t> load_object(int argc, char** argv) {
    if (argc == 1)
        return {opaque_fixture.begin(), opaque_fixture.end()};
    require(argc == 2, "usage: turtle_lookup_tcp_test [PUBLIC-PEM-FILE]");
    std::ifstream input(argv[1], std::ios::binary);
    require(static_cast<bool>(input), "could not open optional public PEM byte fixture");
    std::vector<std::uint8_t> object;
    object.reserve(turtle::lookup::maximum_object_size + 1);
    char byte = 0;
    while (input.get(byte) && object.size() <= turtle::lookup::maximum_object_size)
        object.push_back(static_cast<std::uint8_t>(byte));
    require(input.eof() && object.size() <= turtle::lookup::maximum_object_size,
            "optional public PEM byte fixture exceeds 65536 bytes");
    require(!object.empty(), "optional public PEM byte fixture is empty");
    return object;
}

struct ChildReport {
    pid_t pid = -1;
    std::uint64_t request_id = 0;
    std::uint64_t sent_bytes = 0;
    std::uint64_t received_bytes = 0;
    std::uint32_t request_count = 0;
    std::uint32_t ca_begin = 0;
    std::uint32_t ca_end = 0;
    std::uint32_t semantic_event_count = 0;
    std::uint64_t ca_begin_monotonic_ns = 0;
    std::uint64_t ca_end_monotonic_ns = 0;
    std::uint64_t ca_begin_cpu_ns = 0;
    std::uint64_t ca_end_cpu_ns = 0;
    std::uint64_t ca_begin_heap_live = 0;
    std::uint64_t ca_end_heap_live = 0;
    std::uint64_t heap_allocations = 0;
    std::uint64_t channel_send_returns = 0;
    std::uint64_t channel_recv_returns = 0;
    std::uint64_t channel_successful_sends = 0;
    std::uint64_t channel_successful_receives = 0;
    std::uint64_t poll_waits = 0;
    std::uint64_t poll_wait_elapsed_ns = 0;
    bool poll_wait_timed = false;
    int status = 1;
};
} // namespace

int main(int argc, char** argv) {
    int ready_pipe[2]{-1, -1};
    int report_pipe[2]{-1, -1};
    pid_t child = -1;
    try {
        require(::pipe(ready_pipe) == 0 && ::pipe(report_pipe) == 0, "pipe creation failed");
        const auto object = load_object(argc, argv);
        const pid_t parent_pid = ::getpid();
        child = ::fork();
        require(child >= 0, "fork failed");
        if (child == 0) {
            ::close(ready_pipe[0]);
            ::close(report_pipe[0]);
            ChildReport report;
            report.pid = ::getpid();
            int listener_fd = -1;
            int connection_fd = -1;
            try {
                const auto listener = turtle::tcp::listen_loopback();
                listener_fd = listener.fd;
                exact_write(ready_pipe[1], &listener.port, sizeof listener.port);
                connection_fd = turtle::tcp::accept_one(listener.fd);
                ::close(listener_fd);
                listener_fd = -1;
                make_nonblocking(connection_fd);
                turtle::lookup::Snapshot repository(object);
                // The CA endpoint owns exactly one Meter. Its allocator is the
                // CA heap domain; semantic reads do not create another perf group.
                turtle::measure::Meter meter(turtle::model::Mode::Memory, false);
                MeasuredEvents events;
                events.meter = &meter;
                turtle::lookup::Responder responder(repository.object(), meter.allocator(),
                                                    events.observer());
                ChannelCounts channel_counts;
                turtle::transport::Channel channel{connection_fd, &channel_counts,
                                                   ChannelCounts::observe};
                auto io = channel.io();
                WaitMeasurements poll_waits;
                responder.begin(37, 5);
                drive(responder, io, poll_waits);
                report.request_id = responder.request_id();
                report.sent_bytes = channel_counts.sent_bytes;
                report.received_bytes = channel_counts.received_bytes;
                report.channel_send_returns = channel_counts.send_returns;
                report.channel_recv_returns = channel_counts.recv_returns;
                report.channel_successful_sends = channel_counts.successful_sends;
                report.channel_successful_receives = channel_counts.successful_receives;
                report.poll_waits = poll_waits.count;
                report.poll_wait_elapsed_ns = poll_waits.elapsed_ns;
                report.poll_wait_timed = poll_waits.timed;
                report.ca_begin =
                    events.counts.get(turtle::lookup::SemanticEventKind::CaProcessBegin);
                report.ca_end =
                    events.counts.get(turtle::lookup::SemanticEventKind::CaProcessEnd);
                report.request_count = report.ca_begin;
                for (const auto count : events.counts.values)
                    report.semantic_event_count += count;
                require(events.saw_begin && events.saw_end && events.ca_begin.heap &&
                            events.ca_end.heap,
                        "CA semantic events did not receive memory-mode snapshots");
                report.ca_begin_monotonic_ns = events.ca_begin.monotonic_ns;
                report.ca_end_monotonic_ns = events.ca_end.monotonic_ns;
                report.ca_begin_cpu_ns = events.ca_begin.thread_cpu_ns;
                report.ca_end_cpu_ns = events.ca_end.thread_cpu_ns;
                report.ca_begin_heap_live = events.ca_begin.heap->live;
                report.ca_end_heap_live = events.ca_end.heap->live;
                report.heap_allocations = events.ca_end.heap->allocations;
                report.status = 0;
            } catch (...) {
                report.status = 1;
            }
            if (connection_fd >= 0)
                ::close(connection_fd);
            if (listener_fd >= 0)
                ::close(listener_fd);
            exact_write(report_pipe[1], &report, sizeof report);
            ::close(ready_pipe[1]);
            ::close(report_pipe[1]);
            _exit(report.status);
        }

        ::close(ready_pipe[1]);
        ::close(report_pipe[1]);
        std::uint16_t port = 0;
        exact_read(ready_pipe[0], &port, sizeof port);
        const int fd = turtle::tcp::connect_loopback(port);
        make_nonblocking(fd);
        turtle::lookup::Snapshot expected(object);
        turtle::lookup::Snapshot empty;
        turtle::measure::HeapTracker heap(true);
        turtle::lookup::Cache cache(heap.allocator());
        cache.restore(empty);
        EventCounts events;
        turtle::lookup::Client client(cache, expected.object(), heap.allocator(), events.observer());
        ChannelCounts channel_counts;
        turtle::transport::Channel channel{fd, &channel_counts, ChannelCounts::observe};
        auto io = channel.io();
        WaitMeasurements client_poll_waits;
        client.begin(37, 5);
        drive(client, io, client_poll_waits);
        require(!client.cache_hit() && client.object().id == expected.object().id &&
                    client.object().bytes.size() == object.size() &&
                    std::equal(client.object().bytes.begin(), client.object().bytes.end(),
                               object.begin()),
                "real TCP client did not receive the original opaque bytes");
        require(events.get(turtle::lookup::SemanticEventKind::RequestBegin) == 1 &&
                    events.get(turtle::lookup::SemanticEventKind::ResponseComplete) == 1 &&
                    events.get(turtle::lookup::SemanticEventKind::CacheInsert) == 1 &&
                    events.get(turtle::lookup::SemanticEventKind::UsableObject) == 1,
                "real TCP client lookup events are incomplete");

        // Restore the same fixed state for the next logical connection. A
        // warm hit consumes the object but makes no call through Channel.
        const auto sends_before_warm = channel_counts.send_returns;
        const auto receives_before_warm = channel_counts.recv_returns;
        const auto bytes_before_warm = channel_counts.sent_bytes + channel_counts.received_bytes;
        cache.restore(expected);
        EventCounts warm_events;
        turtle::lookup::Client warm(cache, expected.object(), heap.allocator(),
                                    warm_events.observer());
        warm.begin(38, 6);
        require(warm.advance(io) == Progress::Complete && warm.cache_hit() &&
                    warm.object().bytes.size() == object.size(),
                "real-TCP setup did not produce the next connection's warm hit");
        require(channel_counts.send_returns == sends_before_warm &&
                    channel_counts.recv_returns == receives_before_warm &&
                    channel_counts.sent_bytes + channel_counts.received_bytes == bytes_before_warm,
                "warm hit made a lookup Channel I/O call");
        require(warm_events.get(turtle::lookup::SemanticEventKind::CacheHit) == 1 &&
                    warm_events.get(turtle::lookup::SemanticEventKind::RequestBegin) == 0,
                "warm hit semantic events do not match request_count=0");
        ::close(fd);

        ChildReport report;
        exact_read(report_pipe[0], &report, sizeof report);
        int child_status = 0;
        require(::waitpid(child, &child_status, 0) == child, "server child was not reaped");
        require(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 && report.status == 0,
                "server child failed");
        require(report.pid == child && report.pid != parent_pid,
                "client and real server were not independent processes");
        require(report.request_id == turtle::lookup::single_request_id &&
                    report.request_count == 1 && report.ca_begin == 1 && report.ca_end == 1,
                "server request ID or event counts are incorrect");
        require(report.received_bytes == turtle::lookup::wire_header_size &&
                    report.sent_bytes == turtle::lookup::wire_header_size + object.size(),
                "real server byte counts do not match the request/response contract");
        require(report.semantic_event_count == 2,
                "CA semantic processing interval contains I/O/wait events");
        require(report.channel_send_returns > 0 && report.channel_recv_returns > 0 &&
                    report.channel_successful_sends > 0 &&
                    report.channel_successful_receives > 0 && report.poll_waits > 0 &&
                    report.poll_wait_timed && client_poll_waits.count > 0 &&
                    client_poll_waits.timed,
                "Channel I/O and poll waits were not observed separately");
        require(report.ca_begin_monotonic_ns > 0 &&
                    report.ca_end_monotonic_ns >= report.ca_begin_monotonic_ns &&
                    report.ca_begin_cpu_ns > 0 && report.ca_end_cpu_ns >= report.ca_begin_cpu_ns,
                "CA_PROCESS begin/end did not carry clock observations");
        require(report.ca_begin_heap_live == object.size() &&
                    report.ca_end_heap_live == object.size() && report.heap_allocations == 1,
                "CA allocator heap domain was mixed with fixed/reference storage");
        ::close(ready_pipe[0]);
        ::close(report_pipe[0]);
        std::cout << "lookup real TCP cold/warm test passed (input bytes are not TLS "
                     "verification evidence)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        for (const int fd : {ready_pipe[0], ready_pipe[1], report_pipe[0], report_pipe[1]})
            if (fd >= 0)
                ::close(fd);
        if (child > 0) {
            ::kill(child, SIGKILL);
            while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
            }
        }
        return 1;
    }
}
