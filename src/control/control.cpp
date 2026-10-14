#include "control/control.hpp"
#include <poll.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <stdexcept>
#include <thread>
namespace turtle::control {
void wait(int fd, bool writing, Deadline deadline) {
    for (;;) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) throw std::runtime_error("operation deadline exceeded");
        pollfd p{fd, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
        int rc = ::poll(&p, 1, static_cast<int>(remaining));
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) throw std::runtime_error("poll failed or timed out");
        if (p.revents & (writing ? POLLOUT : POLLIN)) return;
        throw std::runtime_error("peer closed before operation completed");
    }
}
void barrier(int fd, Deadline deadline) {
    const char ready = 1;
    wait(fd, true, deadline);
    if (::send(fd, &ready, 1, MSG_NOSIGNAL) != 1) throw std::runtime_error("ready signal failed");
    wait(fd, false, deadline);
    char peer = 0;
    if (::recv(fd, &peer, 1, 0) != 1 || peer != ready) throw std::runtime_error("peer not ready");
}
void isolate() {
    const rlimit limit{0, 0};
    if (::setrlimit(RLIMIT_NOFILE, &limit) || ::setrlimit(RLIMIT_NPROC, &limit))
        throw std::runtime_error("resource isolation failed");
}
bool reap(pid_t server, pid_t client, Deadline deadline) {
    bool ok = true;
    while (server > 0 || client > 0) {
        for (pid_t* pid : {&server, &client}) {
            if (*pid <= 0) continue;
            int status = 0;
            const auto rc = ::waitpid(*pid, &status, WNOHANG);
            if (rc == *pid) { *pid = -1; ok = ok && WIFEXITED(status) && WEXITSTATUS(status) == 0; }
            else if (rc < 0 && errno != EINTR) { *pid = -1; ok = false; }
        }
        if (std::chrono::steady_clock::now() >= deadline) ok = false;
        if (!ok) {
            for (pid_t pid : {server, client}) if (pid > 0) {
                ::kill(pid, SIGKILL);
                while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
            }
            return false;
        }
        if (server > 0 || client > 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}
}
