#include "observation.hpp"
#include <linux/perf_event.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
namespace turtle {
static std::uint64_t clock_ns(clockid_t id) {
    timespec t{};
    if (clock_gettime(id, &t))
        throw std::runtime_error("clock_gettime");
    return std::uint64_t(t.tv_sec) * 1000000000 + std::uint64_t(t.tv_nsec);
}
std::uint64_t monotonic_ns() {
    return clock_ns(CLOCK_MONOTONIC);
}
std::uint64_t thread_cpu_ns() {
    return clock_ns(CLOCK_THREAD_CPUTIME_ID);
}
Observer::Observer(bool cpu, bool perf, bool white, std::size_t capacity, bool allocation)
    : cpu_(cpu), white_(white), capacity_(capacity), allocations(allocation),
      allocation_enabled(allocation),
      counters(perf ? Availability::Unsupported : Availability::NotCollected) {
    events.reserve(capacity);
    if (!perf)
        return;
    perf_event_attr a{};
    a.size = sizeof(a);
    a.type = PERF_TYPE_HARDWARE;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    a.read_format =
        PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    perf_fd_ = int(syscall(SYS_perf_event_open, &a, 0, -1, -1, PERF_FLAG_FD_CLOEXEC));
    if (perf_fd_ < 0)
        return;
    a.config = PERF_COUNT_HW_INSTRUCTIONS;
    instruction_fd_ = int(syscall(SYS_perf_event_open, &a, 0, -1, perf_fd_, PERF_FLAG_FD_CLOEXEC));
    if (instruction_fd_ >= 0)
        counters = Availability::Available;
}
Observer::~Observer() {
    if (instruction_fd_ >= 0)
        close(instruction_fd_);
    if (perf_fd_ >= 0)
        close(perf_fd_);
}
Stamp Observer::now(bool detailed) const {
    if (detailed && !white_)
        return {};
    Stamp s;
    s.wall = monotonic_ns();
    if (allocation_enabled)
        s.allocation = allocations.value;
    if (cpu_)
        s.cpu = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    if (counters == Availability::Available) {
        std::uint64_t v[5]{};
        if (read(perf_fd_, v, sizeof(v)) != sizeof(v) || v[0] != 2)
            throw std::runtime_error("perf counter read missing");
        s.enabled = v[1];
        s.running = v[2];
        s.cycles = v[3];
        s.instructions = v[4];
    }
    return s;
}
void Observer::add(Event e) {
    if (!white_ && e.kind != Kind::Context && e.kind != Kind::Connection &&
        e.kind != Kind::Scenario && e.kind != Kind::Lookup &&
        e.kind != Kind::FrameworkPreparation && e.kind != Kind::Transport &&
        e.kind != Kind::ListenerPreparation)
        return;
    if (events.size() == capacity_)
        throw std::runtime_error("event capacity exhausted");
    events.push_back(e);
}
const char* kind_name(Kind k) {
    static const char* names[] = {
        "context",  "connection",   "scenario",      "transition",    "assemble",
        "process",  "protect",      "unprotect",     "send",          "receive",
        "wait",     "message",      "record",        "batch",         "verify",
        "lookup",   "lookup-query", "lookup-verify", "lookup-insert", "framework-preparation",
        "transport", "listener-preparation"};
    return names[unsigned(k)];
}
const char* availability_name(Availability a) {
    static const char* names[] = {"available", "not-collected", "unsupported", "missing"};
    return names[unsigned(a)];
}
} // namespace turtle
