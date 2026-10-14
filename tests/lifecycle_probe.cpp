#include "turtle/implementation.hpp"

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace turtle {

struct Connection {
    Role role;
    int socket;
};

namespace impl {
namespace {

int setups = 0;
int connections = 0;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

const char* role_name(Role role) { return role == Role::Client ? "client" : "server"; }

void check_limits() {
    for (const int resource : {RLIMIT_NOFILE, RLIMIT_NPROC}) {
        rlimit limit{};
        require(::getrlimit(resource, &limit) == 0, "probe: getrlimit failed");
        require(limit.rlim_cur == 0 && limit.rlim_max == 0,
                "probe: resource limits were not applied before open");
    }

    const int fd = ::open("/dev/null", O_RDONLY);
    const int error = errno;
    if (fd >= 0) ::close(fd);
    require(fd == -1 && error == EMFILE, "probe: a new file could be opened after isolation");
}

bool send_byte(const Connection& conn, char byte) {
    ssize_t result;
    do {
        result = ::send(conn.socket, &byte, 1, MSG_NOSIGNAL);
    } while (result == -1 && errno == EINTR);
    return result == 1;
}

bool receive_byte(const Connection& conn, char expected) {
    char byte = 0;
    ssize_t result;
    do {
        result = ::recv(conn.socket, &byte, 1, 0);
    } while (result == -1 && errno == EINTR);
    return result == 1 && byte == expected;
}

}  // namespace

const char* name() { return "lifecycle-probe"; }

void setup(Role role) {
    require(++setups == 1, "probe: setup repeated in the same process");
    const int fd = ::open("/dev/null", O_RDONLY);
    require(fd >= 0, "probe: setup was restricted before preparation");
    ::close(fd);
    std::cout << "probe setup " << role_name(role) << " pid=" << ::getpid() << '\n';
}

Connection* open(Role role, int socket) {
    require(setups == 1, "probe: open called before setup");
    require(++connections == 1, "probe: multiple measurements reused a process");
    if (std::getenv("TURTLE_PROBE_CHECK_LIMITS")) check_limits();
    return new Connection{role, socket};
}

Step handshake_step(Connection*) { return Step::Done; }

Verification peer_verification(Connection* conn) {
    if (conn->role == Role::Client && std::getenv("TURTLE_PROBE_VERIFY_FAIL"))
        return Verification::Failed;
    return conn->role == Role::Client ? Verification::Passed : Verification::NotApplicable;
}

bool exchange_app_data(Connection* conn) {
    // This is a transport/lifecycle test, not a TLS implementation.
    const bool ok = conn->role == Role::Client
        ? send_byte(*conn, 'p') && receive_byte(*conn, 'q')
        : receive_byte(*conn, 'p') && send_byte(*conn, 'q');
    if (ok) std::cout << "probe exchange " << role_name(conn->role) << '\n';
    return ok;
}

void close(Connection* conn) { delete conn; }

void teardown(Role role) {
    require(setups == 1 && connections == 1, "probe: incomplete lifecycle");
    std::cout << "probe teardown " << role_name(role) << '\n';
}

}  // namespace impl
}  // namespace turtle
