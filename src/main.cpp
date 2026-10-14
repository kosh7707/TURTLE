#include "transport/tcp.hpp"
#include "turtle/implementation.hpp"

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace {

using turtle::Role;
using turtle::Step;
using turtle::Verification;
namespace impl = turtle::impl;
namespace tcp = turtle::tcp;

// Each measurement gets new role processes. Multi-connection scenarios come later.
constexpr int kMeasurements = 2;

void say(std::string_view who, std::string_view what) {
    std::cout << '[' << who << "] " << what << '\n';
    std::cout.flush();  // keep lifecycle output when a child exits or is stopped
}

const char* role_name(Role role) { return role == Role::Client ? "client" : "server"; }

// Each role owns one read end and one write end of two separate pipes.
// Both sockets must pass their checks before either role starts TLS.
struct Control {
    int ready_read;
    int ready_write;
};

struct Controls {
    Control server;
    Control client;
};

void signal_ready(const Control& c) {
    const char byte = 1;
    ssize_t result;
    do {
        result = ::write(c.ready_write, &byte, 1);
    } while (result == -1 && errno == EINTR);
    if (result != 1) throw std::runtime_error("control: write failed");
}

void wait_ready(const Control& c) {
    char byte = 0;
    ssize_t result;
    do {
        result = ::read(c.ready_read, &byte, 1);
    } while (result == -1 && errno == EINTR);
    if (result != 1 || byte != 1) throw std::runtime_error("control: peer did not become ready");
}

void isolate() {
    // Existing sockets, control channels, and output descriptors remain usable.
    // These process-local limits are not a security sandbox.
    const rlimit limit{0, 0};
    if (::setrlimit(RLIMIT_NOFILE, &limit) < 0)
        throw std::system_error(errno, std::generic_category(), "setrlimit RLIMIT_NOFILE");
    if (::setrlimit(RLIMIT_NPROC, &limit) < 0)
        throw std::system_error(errno, std::generic_category(), "setrlimit RLIMIT_NPROC");
}

// One role's lifecycle, run in its own process. `listen_fd` is used by the
// server only, `port` by the client only.
int run(Role role, int listen_fd, std::uint16_t port, const Control& control) {
    const char* me = role_name(role);
    auto stage = [me](std::string_view what) { say(me, what); };

    stage(std::string("implementation: ") + impl::name());
    stage("check environment: which measurement tools are usable here");
    stage("setup (measured separately)");
    impl::setup(role);

    const int sock = role == Role::Server ? tcp::accept_one(listen_fd) : tcp::connect_loopback(port);
    if (role == Role::Server) ::close(listen_fd);
    if (const std::string why = tcp::check_ready(sock); !why.empty()) {
        stage("TCP not ready: " + why + ": run is invalid");
        ::close(sock);
        impl::teardown(role);
        return 1;
    }
    signal_ready(control);
    wait_ready(control);
    ::close(control.ready_read);
    ::close(control.ready_write);
    stage("TCP established and checked by both roles (not timed)");

    isolate();
    stage("isolate: file and process creation limits applied");

    turtle::Connection* conn = impl::open(role, sock);
    auto end_connection = [&] {
        impl::close(conn);
        ::close(sock);
    };

    Step step;
    while ((step = impl::handshake_step(conn)) == Step::WantRead || step == Step::WantWrite) {
        stage(step == Step::WantRead ? "  wait until readable" : "  wait until writable");
    }
    if (step == Step::Failed) {
        stage("handshake failed: run is invalid");
        end_connection();
        impl::teardown(role);
        return 1;
    }

    const Verification v = impl::peer_verification(conn);
    if (v == Verification::Failed || (role == Role::Client && v != Verification::Passed)) {
        stage("peer verification did not pass: run is invalid");
        end_connection();
        impl::teardown(role);
        return 1;
    }

    stage("  handshake done; exchange encrypted application data");
    const bool ok = impl::exchange_app_data(conn);
    end_connection();
    stage("  closed; record state left for the next connection");
    if (!ok) {
        stage("application data exchange failed: run is invalid");
        impl::teardown(role);
        return 1;
    }

    impl::teardown(role);
    stage("lifecycle finished");
    return 0;
}

pid_t spawn(Role role, int listen_fd, std::uint16_t port, const Controls& controls) {
    std::cout.flush();  // do not duplicate buffered output into the child
    const pid_t pid = ::fork();
    if (pid != 0) return pid;
    int code = 1;
    try {
        const Control& control = role == Role::Server ? controls.server : controls.client;
        const Control& peer_control = role == Role::Server ? controls.client : controls.server;
        if (role == Role::Client) ::close(listen_fd);
        ::close(peer_control.ready_read);
        ::close(peer_control.ready_write);
        code = run(role, listen_fd, port, control);
    } catch (const std::exception& e) {
        say(role_name(role), std::string("error: ") + e.what());
    }
    std::cout.flush();
    ::_exit(code);
}

void stop_and_reap(pid_t pid) {
    if (pid <= 0) return;
    ::kill(pid, SIGTERM);
    while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
}

// The director never initializes the implementation or restricts its own
// resources. Implementation state is never carried over from a previous child.
bool measure_once() {
    const tcp::Listener listener = tcp::listen_loopback();
    say("turtle", "listening on 127.0.0.1:" + std::to_string(listener.port));

    int server_ready[2];
    if (::pipe(server_ready) < 0) {
        const int error = errno;
        ::close(listener.fd);
        throw std::system_error(error, std::generic_category(), "server ready pipe");
    }
    int client_ready[2];
    if (::pipe(client_ready) < 0) {
        const int error = errno;
        ::close(listener.fd);
        ::close(server_ready[0]);
        ::close(server_ready[1]);
        throw std::system_error(error, std::generic_category(), "client ready pipe");
    }

    const Controls controls{
        {client_ready[0], server_ready[1]},
        {server_ready[0], client_ready[1]},
    };
    auto close_prepared_fds = [&] {
        ::close(listener.fd);
        ::close(server_ready[0]);
        ::close(server_ready[1]);
        ::close(client_ready[0]);
        ::close(client_ready[1]);
    };

    pid_t server = spawn(Role::Server, listener.fd, listener.port, controls);
    if (server < 0) {
        const int error = errno;
        close_prepared_fds();
        throw std::system_error(error, std::generic_category(), "fork server");
    }
    pid_t client = spawn(Role::Client, listener.fd, listener.port, controls);
    if (client < 0) {
        const int error = errno;
        close_prepared_fds();
        stop_and_reap(server);
        throw std::system_error(error, std::generic_category(), "fork client");
    }
    close_prepared_fds();

    bool ok = true;
    while (server > 0 || client > 0) {
        int status = 0;
        const pid_t done = ::waitpid(-1, &status, 0);
        if (done < 0) {
            if (errno == EINTR) continue;
            const int error = errno;
            stop_and_reap(server);
            stop_and_reap(client);
            throw std::system_error(error, std::generic_category(), "waitpid");
        }
        if (done == server) server = -1;
        else if (done == client) client = -1;
        else continue;

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            ok = false;
            if (server > 0) ::kill(server, SIGTERM);
            if (client > 0) ::kill(client, SIGTERM);
        }
    }
    return ok;
}

}  // namespace

int main() {
    try {
        for (int measurement = 1; measurement <= kMeasurements; ++measurement) {
            say("turtle", "measurement " + std::to_string(measurement) + "/" +
                          std::to_string(kMeasurements));
            if (!measure_once()) {
                say("turtle", "a role failed");
                return 1;
            }
        }
        say("turtle", "all roles finished");
        return 0;
    } catch (const std::exception& e) {
        say("turtle", std::string("error: ") + e.what());
        return 1;
    }
}
