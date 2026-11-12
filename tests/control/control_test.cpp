#include "control/control.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace std::chrono_literals;
using turtle::control::Deadline;

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

std::array<int, 2> socket_pair() {
    std::array<int, 2> pair{};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair.data()))
        throw std::runtime_error("socketpair failed");
    return pair;
}

Deadline soon() {
    return std::chrono::steady_clock::now() + 2s;
}

bool reap_test_child(pid_t child) {
    int status = 0;
    pid_t result;
    do {
        result = ::waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

void write_all(int fd, std::string_view bytes, bool one_at_a_time = false) {
    std::size_t offset = 0;
    while (offset != bytes.size()) {
        const std::size_t requested = one_at_a_time ? 1 : bytes.size() - offset;
        const auto written = ::write(fd, bytes.data() + offset, requested);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            ::_exit(20);
        offset += static_cast<std::size_t>(written);
        if (one_at_a_time)
            ::usleep(1000);
    }
}

void test_deadline_and_eof() {
    auto pair = socket_pair();
    turtle::control::Waiter waiter(pair[0]);
    const auto started = std::chrono::steady_clock::now();
    bool timed_out = false;
    try {
        waiter.wait(false, started + 25ms);
    } catch (const std::runtime_error&) {
        timed_out = true;
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    require(timed_out, "wait did not honor deadline");
    require(elapsed < 500ms, "wait extended its deadline");

    ::close(pair[1]);
    bool saw_eof = false;
    try {
        (void)turtle::control::receive_message(waiter, soon());
    } catch (const std::runtime_error&) {
        saw_eof = true;
    }
    require(saw_eof, "message EOF was not rejected");
    ::close(pair[0]);
}

void test_message_round_trip_and_partial_receive() {
    auto capture = socket_pair();
    turtle::control::Waiter capture_waiter(capture[0]);
    turtle::control::Message input;
    input.kind = turtle::control::MessageKind::TcpReady;
    input.sample = 0x0102030405060708ULL;
    input.connection = 0xa1b2c3d4U;
    turtle::control::send_message(capture_waiter, input, soon());

    std::array<char, 277> frame{};
    std::size_t offset = 0;
    while (offset != frame.size()) {
        const auto received = ::read(capture[1], frame.data() + offset, frame.size() - offset);
        require(received > 0, "could not capture message frame");
        offset += static_cast<std::size_t>(received);
    }
    require(::fcntl(capture[0], F_GETFD) >= 0, "send_message closed borrowed descriptor");
    ::close(capture[0]);
    ::close(capture[1]);

    auto partial = socket_pair();
    const pid_t writer = ::fork();
    require(writer >= 0, "partial writer fork failed");
    if (writer == 0) {
        ::close(partial[0]);
        write_all(partial[1], std::string_view(frame.data(), frame.size()), true);
        ::close(partial[1]);
        ::_exit(0);
    }
    ::close(partial[1]);
    turtle::control::Waiter receive_waiter(partial[0]);
    const auto output = turtle::control::receive_message(receive_waiter, soon());
    require(output.kind == input.kind && output.sample == input.sample &&
                output.connection == input.connection && output.reason.empty(),
            "partial message round trip changed fields");
    require(::fcntl(partial[0], F_GETFD) >= 0, "receive_message closed borrowed descriptor");
    ::close(partial[0]);
    require(reap_test_child(writer), "partial writer was not reaped");

    auto failure = socket_pair();
    turtle::control::Waiter failure_sender(failure[0]);
    turtle::control::Waiter failure_receiver(failure[1]);
    turtle::control::Message failed;
    failed.kind = turtle::control::MessageKind::Failed;
    failed.sample = 11;
    failed.reason = "listener setup failed";
    turtle::control::send_message(failure_sender, failed, soon());
    auto received_failed = turtle::control::receive_message(failure_receiver, soon());
    require(received_failed.kind == turtle::control::MessageKind::Failed &&
                received_failed.reason == failed.reason,
            "failure reason did not round trip");

    failed.reason.assign(300, 'r');
    turtle::control::send_message(failure_sender, failed, soon());
    received_failed = turtle::control::receive_message(failure_receiver, soon());
    require(received_failed.reason == std::string(255, 'r') + "[truncated]",
            "long failure reason was not bounded and marked");

    turtle::control::Message invalid_reason;
    invalid_reason.kind = turtle::control::MessageKind::Start;
    invalid_reason.reason = "not allowed";
    bool rejected_reason = false;
    try {
        turtle::control::send_message(failure_sender, invalid_reason, soon());
    } catch (const std::runtime_error&) {
        rejected_reason = true;
    }
    require(rejected_reason, "normal message accepted a failure reason");
    ::close(failure[0]);
    ::close(failure[1]);
}

void test_wait_set_control_priority() {
    auto data = socket_pair();
    auto control = socket_pair();
    turtle::control::WaitSet set(data[0], control[0]);
    const char byte = 1;
    require(::write(data[1], &byte, 1) == 1, "data setup failed");
    require(::write(control[1], &byte, 1) == 1, "control setup failed");
    require(set.wait(false, soon()) == turtle::control::WaitSet::Ready::Control,
            "control readiness did not take priority");
    for (int fd : {data[0], data[1], control[0], control[1]})
        ::close(fd);
}

void phase_peer(int fd, std::string_view acknowledgement, bool fragmented = true) {
    std::string request;
    char byte = 0;
    while (::read(fd, &byte, 1) == 1 && byte != '\n')
        request.push_back(byte);
    if (request != R"({"attempt":7,"edge":"begin","phase":"scenario","schema":1,"type":"phase"})")
        ::_exit(21);
    write_all(fd, acknowledgement, fragmented);
    ::close(fd);
    ::_exit(0);
}

void test_phase_loopback_and_strict_match() {
    auto pair = socket_pair();
    const pid_t peer = ::fork();
    require(peer >= 0, "phase peer fork failed");
    if (peer == 0) {
        ::close(pair[0]);
        phase_peer(
            pair[1],
            R"({"type":"ack","schema":1,"attempt":7,"phase":"scenario","edge":"begin","observation_id":"7:scenario:begin"}
)");
    }
    ::close(pair[1]);
    const auto ack = turtle::control::exchange_phase(pair[0], 7, turtle::control::Phase::Scenario,
                                                     turtle::control::PhaseEdge::Begin, soon());
    require(ack.attempt == 7 && ack.observation_id == "7:scenario:begin",
            "phase acknowledgement was decoded incorrectly");
    require(::fcntl(pair[0], F_GETFD) >= 0, "exchange_phase closed borrowed descriptor");
    ::close(pair[0]);
    require(reap_test_child(peer), "phase peer failed");

    pair = socket_pair();
    const pid_t mismatch_peer = ::fork();
    require(mismatch_peer >= 0, "mismatch peer fork failed");
    if (mismatch_peer == 0) {
        ::close(pair[0]);
        phase_peer(
            pair[1],
            R"({"type":"ack","schema":1,"attempt":8,"phase":"scenario","edge":"begin","observation_id":"8:scenario:begin"}
)");
    }
    ::close(pair[1]);
    bool rejected = false;
    try {
        (void)turtle::control::exchange_phase(pair[0], 7, turtle::control::Phase::Scenario,
                                              turtle::control::PhaseEdge::Begin, soon());
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "mismatched phase acknowledgement was accepted");
    ::close(pair[0]);
    require(reap_test_child(mismatch_peer), "mismatch peer failed");

    pair = socket_pair();
    const pid_t oversized_peer = ::fork();
    require(oversized_peer >= 0, "oversized peer fork failed");
    if (oversized_peer == 0) {
        ::close(pair[0]);
        phase_peer(pair[1], std::string(4096, 'x'), false);
    }
    ::close(pair[1]);
    rejected = false;
    try {
        (void)turtle::control::exchange_phase(pair[0], 7, turtle::control::Phase::Scenario,
                                              turtle::control::PhaseEdge::Begin, soon());
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, "oversized phase acknowledgement was accepted");
    ::close(pair[0]);
    require(reap_test_child(oversized_peer), "oversized peer failed");
}

} // namespace

int main() {
    try {
        test_deadline_and_eof();
        test_message_round_trip_and_partial_receive();
        test_wait_set_control_priority();
        test_phase_loopback_and_strict_match();
    } catch (const std::exception& error) {
        const std::string message = std::string("control test failed: ") + error.what() + "\n";
        (void)::write(STDERR_FILENO, message.data(), message.size());
        return 1;
    }
    return 0;
}
