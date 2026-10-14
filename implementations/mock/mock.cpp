#include "turtle/implementation.hpp"

#include <cstdlib>
#include <iostream>

namespace turtle {

struct Connection {
    Role role;
    int steps = 0;
};

namespace impl {

const char* name() { return "mock"; }

void setup(Role) { std::cout << "  (mock) setup\n"; }

Connection* open(Role role, int socket) {
    std::cout << "  (mock) open connection on socket " << socket << '\n';
    return new Connection{role};
}

Step handshake_step(Connection* conn) {
    std::cout << "  (mock) handshake step " << ++conn->steps << '\n';
    return conn->steps < 2 ? Step::WantRead : Step::Done;
}

Verification peer_verification(Connection* conn) {
    std::cout << "  (mock) report verification result\n";
    if (std::getenv("TURTLE_MOCK_VERIFY_FAIL")) return Verification::Failed;  // for tests
    return conn->role == Role::Client ? Verification::Passed : Verification::NotApplicable;
}

bool exchange_app_data(Connection*) {
    std::cout << "  (mock) ping/pong\n";
    return true;
}

void close(Connection* conn) {
    std::cout << "  (mock) close connection\n";
    delete conn;
}

void teardown(Role) { std::cout << "  (mock) teardown\n"; }

}  // namespace impl
}  // namespace turtle
