#pragma once

#include "model/model.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>

struct perf_event_attr;

namespace turtle::measure::detail {

// Narrow syscall boundary used to make perf setup failures deterministic in
// the component test. This is an internal implementation contract, not a
// general injection surface for framework callers.
struct PerfOperations {
    void* context = nullptr;
    int (*open)(void*, const perf_event_attr&, pid_t pid, int cpu, int group_fd,
                unsigned long flags) = nullptr;
    int (*control)(void*, int fd, unsigned long request, unsigned long argument) = nullptr;
    ssize_t (*read)(void*, int fd, void* output, std::size_t size) = nullptr;
    int (*close)(void*, int fd) = nullptr;
};

struct PerfReadValues {
    std::uint64_t count = 0;
    std::uint64_t enabled = 0;
    std::uint64_t running = 0;
    std::uint64_t cycles = 0;
    std::uint64_t instructions = 0;
};

struct PerfSetup {
    int cycles_fd = -1;
    int instructions_fd = -1;
    model::PerfStatus status = model::PerfStatus::Unsupported;
    std::optional<model::PerfScope> effective_scope;
    std::optional<model::PerfFailureStage> failure_stage;
    std::optional<int> error_number;
    std::string note;
};

perf_event_attr perf_event_attributes(std::uint64_t config, bool leader,
                                      model::PerfScope scope) noexcept;
PerfSetup setup_perf_group(model::PerfScope scope, const PerfOperations& operations);
std::optional<PerfReadValues> read_perf_group(int cycles_fd,
                                              const PerfOperations& operations) noexcept;
PerfOperations system_perf_operations() noexcept;
void require_perf_scope(const model::Capabilities& capabilities);
bool usable_calibration_interval(const model::Snapshot& before,
                                 const model::Snapshot& after) noexcept;

} // namespace turtle::measure::detail
