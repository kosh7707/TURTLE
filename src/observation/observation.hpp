#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "allocation/allocation.hpp"
namespace turtle {
enum class Kind {
    Context,
    Connection,
    Scenario,
    Transition,
    Assemble,
    Process,
    Protect,
    Unprotect,
    Send,
    Receive,
    Wait,
    Message,
    Record,
    Batch,
    Verify,
    Lookup,
    LookupQuery,
    LookupVerify,
    LookupInsert,
    FrameworkPreparation,
    Transport,
    ListenerPreparation
};
enum class Availability { Available, NotCollected, Unsupported, Missing };
struct Stamp {
    AllocationSnapshot allocation{};
    std::uint64_t wall = 0, cpu = 0, cycles = 0, instructions = 0, enabled = 0, running = 0;
};
struct Event {
    Kind kind{};
    Stamp begin{}, end{};
    std::uint64_t connection = 0, message = 0, record = 0, batch = 0;
    std::uint64_t offset = 0, length = 0, plain_offset = 0, plain_length = 0;
    unsigned type = 0, detail = 0;
    bool outgoing = false;
};
class Observer {
    int perf_fd_ = -1;
    int instruction_fd_ = -1;
    bool cpu_;
    bool white_;
    std::size_t capacity_;

  public:
    Allocations allocations;
    bool allocation_enabled;
    Availability counters;
    std::vector<Event> events;
    Observer(bool cpu, bool perf, bool white, std::size_t capacity, bool allocation = false);
    ~Observer();
    Observer(const Observer&) = delete;
    Stamp now(bool detailed = true) const;
    void add(Event);
    Allocations* tracker() {
        return allocation_enabled ? &allocations : nullptr;
    }
    bool white() const {
        return white_;
    }
};
const char* kind_name(Kind);
const char* availability_name(Availability);
std::uint64_t monotonic_ns();
std::uint64_t thread_cpu_ns();
} // namespace turtle
