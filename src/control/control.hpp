#pragma once
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <sys/types.h>
namespace turtle::control {
using Deadline = std::chrono::steady_clock::time_point;

enum class Phase { Setup, Scenario, Cleanup };
enum class PhaseEdge { Begin, End };
enum class MessageKind {
    NamespaceReady,
    ReadyAddress,
    TcpReady,
    Start,
    ResponseComplete,
    LookupSkipped,
    ConnectionComplete,
    Flush,
    AbortFlush,
    Flushed,
    Failed,
    Exit
};

// Control messages travel only over the inherited Unix control channel. They
// are never multiplexed onto TLS or lookup TCP streams.
struct Message {
    MessageKind kind = MessageKind::NamespaceReady;
    std::uint64_t sample = 0;
    std::uint32_t connection = 0;
    std::uint64_t request_id = 0;
    // Absolute steady-clock deadline chosen once by the parent for Flush and
    // AbortFlush. Other message kinds keep this zero.
    std::uint64_t cleanup_deadline_monotonic_ns = 0;
    bool cache_hit = false;
    std::string address; // READY_ADDRESS only; numeric IPv4 prepared pre-limit
    std::uint16_t port = 0;
    std::string reason; // FAILED only; receiver marks wire truncation
};

struct PhaseAck {
    std::uint64_t attempt = 0;
    Phase phase = Phase::Setup;
    PhaseEdge edge = PhaseEdge::Begin;
    std::string observation_id; // exactly <attempt>:<phase>:<edge> on success
};

const char* name(Phase value) noexcept;
const char* name(PhaseEdge value) noexcept;
const char* name(MessageKind value) noexcept;

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

// A deliberately limited readiness set for the CA data socket plus its parent
// control socket. All fds are borrowed and registration happens at construction
// before resource limits. This is not a general adapter multi-I/O interface.
class WaitSet {
  public:
    enum class Ready { Data, Control };
    WaitSet(int data_fd, int control_fd);
    ~WaitSet();
    WaitSet(const WaitSet&) = delete;
    WaitSet& operator=(const WaitSet&) = delete;
    Ready wait(bool data_writing, Deadline deadline);

  private:
    int data_fd_;
    int control_fd_;
    int epoll_;
};

// Typed lifecycle messages use a fixed-size binary frame on the inherited
// Unix control channel. The waiter and its descriptor remain caller-owned.
void send_message(Waiter& waiter, const Message& message, Deadline deadline);
Message receive_message(Waiter& waiter, Deadline deadline);

void wait(int fd, bool writing, Deadline deadline);
void barrier(Waiter& waiter, Deadline deadline);
void barrier(int fd, Deadline deadline);
void isolate();
bool reap(pid_t server, pid_t client, Deadline deadline);

// Enter a borrowed network namespace before creating any data listener/socket.
// A successful role process stays in that namespace until it exits.
void enter_network_namespace(int namespace_fd);

// Reap every positive PID in the caller-owned list. The function never signals
// any PID outside the list and returns only after all owned children are waited,
// or false if bounded recovery could not prove that outcome. Once the supplied
// grace expires, SIGKILL recovery has a separate fixed 250 ms OS-reaping bound.
struct ReapResult {
    bool all_reaped = true;
    bool all_success = true;
    bool forced_kill = false;
};
ReapResult reap_result(std::span<const pid_t> children, Deadline deadline);
bool reap_owned(std::span<const pid_t> children, Deadline deadline);

// Exchange the C3 UTF-8 JSON-line phase request/ack (maximum 4096 bytes,
// including the trailing newline) on the borrowed Python coordinator socket.
// EOF is a run-level abort. Callers use the attempt deadline normally and the
// already-established grace deadline after abort; this helper never extends it.
PhaseAck exchange_phase(int phase_control_fd, std::uint64_t attempt, Phase phase,
                        PhaseEdge edge, Deadline deadline);
} // namespace turtle::control
