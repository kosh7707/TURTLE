#pragma once

// Shared value types only. This module performs no I/O or lifecycle work.
#include "turtle/adapter.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace turtle::model {

inline constexpr unsigned record_schema = 1;
// Identifies the measurement boundary semantics independently of the additive
// raw record schema. Revision 2 includes TLS key-share generation in the
// handshake window and framework return-path capture work in the I/O segment.
inline constexpr unsigned measurement_contract_revision = 2;
inline constexpr const char* framework_version = "0.1.0";

enum class Mode { Timing, Memory, Trace };
enum class PerfScope { User, UserKernel };
enum class PerfStatus { Disabled, Available, Unsupported };
enum class PerfFailureStage { CyclesOpen, InstructionsOpen, Reset, Enable, InitialRead };
enum class Direction { Sent, Received };
enum class Location { Boundary, Framework, Kernel, Hardware, Syscall, Library };
enum class Call {
    None,
    Setup,
    Open,
    Handshake,
    Verification,
    Negotiated,
    AppSend,
    AppRecv,
    Close,
    Save,
    Teardown
};
enum class EventKind {
    SetupBegin,
    SetupEnd,
    TcpReady,
    OpenBegin,
    OpenEnd,
    CallBegin,
    CallEnd,
    IoSendEnter,
    IoSendReturn,
    IoRecvEnter,
    IoRecvReturn,
    WaitBegin,
    WaitEnd,
    KernelRx,
    KernelTxSched,
    KernelTxSnd,
    KernelTxAck,
    CloseBegin,
    CloseEnd,
    Save
};

struct CpuSibling {
    int cpu = -1;
    // A disengaged value means sysfs did not expose whether this sibling was
    // online. It must not be interpreted as offline.
    std::optional<bool> online;
};

struct CpuTopology {
    int cpu = -1;
    std::optional<int> package_id;
    std::optional<int> core_id;
    // null means the sibling list could not be read; an empty vector means it
    // was read and contained no siblings.
    std::optional<std::vector<CpuSibling>> thread_siblings;
};

struct HeapSnapshot {
    std::uint64_t live = 0;
    std::uint64_t peak = 0;
    std::uint64_t interval_peak = 0;
    std::uint64_t allocations = 0;
    std::uint64_t frees = 0;
    std::uint64_t allocated_total = 0;
};

struct Snapshot {
    std::uint64_t monotonic_ns = 0;
    std::uint64_t thread_cpu_ns = 0;
    std::optional<std::uint64_t> cycles;
    std::optional<std::uint64_t> instructions;
    std::optional<std::uint64_t> perf_enabled;
    std::optional<std::uint64_t> perf_running;
    std::optional<HeapSnapshot> heap;
};

struct Event {
    EventKind kind = EventKind::CallBegin;
    Location location = Location::Boundary;
    Call call = Call::None;
    std::uint64_t sequence = 0;
    std::uint64_t call_id = 0;
    std::size_t connection = 0;
    Snapshot snapshot;
    std::uint64_t requested = 0;
    std::uint64_t transferred = 0;
    std::uint64_t stream_begin = 0;
    std::uint64_t stream_end = 0;
    std::int64_t result = 0;
    int system_error = 0;
    // Kernel observations retain their raw clock and reported coverage. They
    // are not inserted into the boundary partition as synthetic exact events.
    std::optional<std::uint64_t> raw_timestamp_ns;
    std::optional<std::uint32_t> timestamp_id;
    bool timestamp_coverage_exact = false;
};

struct ClockPair {
    std::uint64_t monotonic_before_ns = 0;
    std::uint64_t realtime_ns = 0;
    std::uint64_t monotonic_after_ns = 0;
};

struct Environment {
    std::string kernel;
    std::string cpu_model;
    std::string compiler;
    std::string governor;
    std::string boost;
    std::string environment_hash;
    bool wsl = false;
    std::optional<int> perf_event_paranoid;
    std::string perf_event_paranoid_reason;
    std::vector<int> allowed_cpus;
    std::vector<int> physical_cpus;
    std::vector<CpuTopology> cpu_topology;
    double load_before = 0;
    std::vector<std::string> warnings;
};

struct Capabilities {
    bool monotonic_clock = false;
    bool thread_cpu_clock = false;
    bool perf = false;
    PerfScope perf_requested_scope = PerfScope::User;
    PerfStatus perf_status = PerfStatus::Disabled;
    std::optional<PerfScope> perf_effective_scope;
    std::optional<PerfFailureStage> perf_failure_stage;
    std::optional<int> perf_error_number;
    bool heap_tracking = false;
    bool stack_tracking = false;
    bool kernel_timestamp_configured = false;
    bool hardware_timestamps = false;
    bool affinity = false;
    std::uint64_t monotonic_resolution_ns = 0;
    std::uint64_t thread_cpu_resolution_ns = 0;
    std::string perf_note;
    std::string stack_note;
    std::string hardware_note;
    std::string trace_note;
    std::vector<std::string> warnings;
};

struct Calibration {
    std::vector<std::uint64_t> elapsed_ns;
    std::vector<std::uint64_t> cpu_ns;
    std::vector<std::uint64_t> cycles;
    std::vector<std::uint64_t> instructions;
};

struct SocketSettings {
    bool nonblocking = false;
    bool tcp_nodelay = false;
    int send_buffer = 0;
    int receive_buffer = 0;
    bool kernel_timestamps = false;
};

// A disengaged field is unsupported or was not collected; it is never an
// observed zero. `structure_bytes` is the TCP_INFO length returned by Linux.
// `note` explains a missing snapshot or fields unavailable at that length.
struct TcpInfoSnapshot {
    std::size_t structure_bytes = 0;
    std::optional<std::uint8_t> state;
    std::optional<std::uint8_t> retransmits;
    std::optional<std::uint32_t> retrans;
    std::optional<std::uint32_t> total_retrans;
    std::optional<std::uint32_t> unacked;
    std::optional<std::uint32_t> lost;
    std::optional<std::uint32_t> snd_mss;
    std::optional<std::uint32_t> rcv_mss;
    std::optional<std::uint32_t> segs_out;
    std::optional<std::uint32_t> segs_in;
    std::optional<std::uint32_t> data_segs_out;
    std::optional<std::uint32_t> data_segs_in;
    std::optional<std::uint64_t> bytes_acked;
    std::optional<std::uint64_t> bytes_received;
    std::string note;
};

struct ConnectionInfo {
    std::size_t index = 0;
    bool warmup = false;
    Verification verification = Verification::Failed;
    Negotiated negotiated;
    bool application_verified = false;
    // The primary measurement start is absent when its observation boundary
    // cannot be seen (not an observed sequence zero).
    std::optional<std::uint64_t> start_sequence;
    std::uint64_t end_sequence = 0;
    bool primary_window_available = false;
    std::string primary_window_reason = "measurement_boundaries_incomplete";
    std::optional<SocketSettings> socket;
    std::optional<TcpInfoSnapshot> tcp_start;
    std::optional<TcpInfoSnapshot> tcp_end;
};

const char* name(Role value) noexcept;
const char* name(Mode value) noexcept;
const char* name(PerfScope value) noexcept;
const char* name(PerfStatus value) noexcept;
const char* name(PerfFailureStage value) noexcept;
const char* name(Direction value) noexcept;
const char* name(Location value) noexcept;
const char* name(Call value) noexcept;
const char* name(EventKind value) noexcept;
const char* name(Verification value) noexcept;
const char* name(Step value) noexcept;
std::string fingerprint(const std::string& text);
std::uint64_t fnv1a64(std::span<const std::uint8_t> bytes) noexcept;
std::string fingerprint(std::span<const std::uint8_t> bytes);
const char* build_information() noexcept;

} // namespace turtle::model
