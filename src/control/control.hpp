#pragma once
#include "control/protocol.hpp"
#include <chrono>
#include <cstdint>
#include <string>
namespace turtle::control {
using Deadline = std::chrono::steady_clock::time_point;

enum class Phase { Setup, Scenario, Cleanup };
enum class PhaseEdge { Begin, End };
enum class MessageKind {
    TcpReady,
    Start,
    ResponseComplete,
    LookupSkipped,
    ConnectionComplete,
    Flush,
    Flushed,
    Failed
};

// Control messages travel only over the separate TCP control connection. They
// are never multiplexed onto TLS or lookup TCP streams.
struct Message {
    MessageKind kind = MessageKind::TcpReady;
    std::uint64_t sample = 0;
    std::uint32_t connection = 0;
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

// A deliberately limited readiness set for the CA data socket plus its peer
// control socket. All fds are borrowed and registration happens at construction
// before resource limits. This is not a general adapter multi-I/O interface.
class WaitSet {
  public:
    enum class Ready { Data, Control };
    WaitSet(int data_fd, int control_fd, bool monitor_control = true);
    ~WaitSet();
    WaitSet(const WaitSet&) = delete;
    WaitSet& operator=(const WaitSet&) = delete;
    Ready wait(bool data_writing, Deadline deadline);
    void wait_data(bool writing, Deadline deadline);

  private:
    int data_fd_;
    int control_fd_;
    int epoll_;
};

// Typed lifecycle messages use a fixed-size binary frame on the separate
// TCP control connection. The waiter and its descriptor remain caller-owned.
void send_message(Waiter& waiter, const Message& message, Deadline deadline);
Message receive_message(Waiter& waiter, Deadline deadline);

void wait(int fd, bool writing, Deadline deadline);
void isolate(bool allow_new_connections = false);

// Exchange the C3 UTF-8 JSON-line phase request/ack (maximum 4096 bytes,
// including the trailing newline) on the borrowed Python coordinator socket.
// EOF is a run-level abort. Callers use the attempt deadline normally and the
// already-established grace deadline after abort; this helper never extends it.
PhaseAck exchange_phase(int phase_control_fd, std::uint64_t attempt, Phase phase, PhaseEdge edge,
                        Deadline deadline);
} // namespace turtle::control
