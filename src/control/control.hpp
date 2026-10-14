#pragma once
#include <chrono>
#include <sys/types.h>
namespace turtle::control {
using Deadline = std::chrono::steady_clock::time_point;
void wait(int fd, bool writing, Deadline deadline);
void barrier(int fd, Deadline deadline);
void isolate();
bool reap(pid_t server, pid_t client, Deadline deadline);
}
