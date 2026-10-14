#pragma once
#include <chrono>
#include <sys/types.h>
namespace turtle::control {
using Deadline = std::chrono::steady_clock::time_point;
class Waiter {
  public:
    explicit Waiter(int fd);
    ~Waiter();
    Waiter(const Waiter&) = delete;
    Waiter& operator=(const Waiter&) = delete;
    void wait(bool writing, Deadline deadline);
    int fd() const noexcept {
        return fd_;
    }

  private:
    int fd_;
    int epoll_;
};
void wait(int fd, bool writing, Deadline deadline);
void barrier(Waiter& waiter, Deadline deadline);
void barrier(int fd, Deadline deadline);
void isolate();
bool reap(pid_t server, pid_t client, Deadline deadline);
} // namespace turtle::control
