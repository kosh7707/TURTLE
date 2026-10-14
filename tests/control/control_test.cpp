#include "control/control.hpp"
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdexcept>
int main() {
    int pair[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair))
        return 1;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    auto child = ::fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        ::close(pair[0]);
        try {
            turtle::control::barrier(pair[1], deadline);
        } catch (...) {
            ::_exit(1);
        }
        ::_exit(0);
    }
    ::close(pair[1]);
    turtle::control::barrier(pair[0], deadline);
    ::close(pair[0]);
    if (!turtle::control::reap(child, -1, deadline))
        return 1;
    return 0;
}
