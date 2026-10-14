#include "control/control.hpp"
#include <cerrno>
#include <csignal>
#include <stdexcept>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
namespace turtle::control {
Waiter::Waiter(int fd) : fd_(fd), epoll_(::epoll_create1(EPOLL_CLOEXEC)) {
    if (epoll_ < 0)
        throw std::runtime_error("epoll preparation failed");
    epoll_event event{};
    event.events = EPOLLIN;
    if (::epoll_ctl(epoll_, EPOLL_CTL_ADD, fd_, &event)) {
        ::close(epoll_);
        throw std::runtime_error("epoll registration failed");
    }
}
Waiter::~Waiter() {
    ::close(epoll_);
}
void Waiter::wait(bool writing, Deadline deadline) {
    epoll_event event{};
    event.events = writing ? EPOLLOUT : EPOLLIN;
    if (::epoll_ctl(epoll_, EPOLL_CTL_MOD, fd_, &event))
        throw std::runtime_error("epoll interest failed");
    for (;;) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - std::chrono::steady_clock::now())
                             .count();
        if (remaining <= 0)
            throw std::runtime_error("operation deadline exceeded");
        const int rc = ::epoll_wait(epoll_, &event, 1, static_cast<int>(remaining));
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc <= 0)
            throw std::runtime_error("epoll failed or timed out");
        if (event.events & (writing ? EPOLLOUT : EPOLLIN))
            return;
        throw std::runtime_error("peer closed before operation completed");
    }
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
bool reap(pid_t server, pid_t client, Deadline deadline) {
    bool ok = true;
    while (server > 0 || client > 0) {
        for (pid_t* pid : {&server, &client}) {
            if (*pid <= 0)
                continue;
            int status = 0;
            const auto rc = ::waitpid(*pid, &status, WNOHANG);
            if (rc == *pid) {
                *pid = -1;
                ok = ok && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            } else if (rc < 0 && errno != EINTR) {
                *pid = -1;
                ok = false;
            }
        }
        if (std::chrono::steady_clock::now() >= deadline)
            ok = false;
        if (!ok) {
            for (pid_t pid : {server, client})
                if (pid > 0) {
                    ::kill(pid, SIGKILL);
                    while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
                    }
                }
            return false;
        }
        if (server > 0 || client > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}
} // namespace turtle::control
