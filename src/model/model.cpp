#include "model/model.hpp"
#include "model/build_info.hpp"

#include <iomanip>
#include <sstream>

namespace turtle::model {

const char* build_information() noexcept {
    return detail::build_information;
}

const char* name(Role value) noexcept {
    return value == Role::Client ? "client" : "server";
}
const char* name(Mode value) noexcept {
    switch (value) {
    case Mode::Timing:
        return "timing";
    case Mode::Memory:
        return "memory";
    case Mode::Trace:
        return "trace";
    }
    return "unknown";
}
const char* name(PerfScope value) noexcept {
    return value == PerfScope::User ? "user" : "user+kernel";
}
const char* name(PerfStatus value) noexcept {
    switch (value) {
    case PerfStatus::Disabled:
        return "disabled";
    case PerfStatus::Available:
        return "available";
    case PerfStatus::Unsupported:
        return "unsupported";
    }
    return "unknown";
}
const char* name(PerfFailureStage value) noexcept {
    switch (value) {
    case PerfFailureStage::CyclesOpen:
        return "cycles_open";
    case PerfFailureStage::InstructionsOpen:
        return "instructions_open";
    case PerfFailureStage::Reset:
        return "reset";
    case PerfFailureStage::Enable:
        return "enable";
    case PerfFailureStage::InitialRead:
        return "initial_read";
    }
    return "unknown";
}
const char* name(Direction value) noexcept {
    return value == Direction::Sent ? "sent" : "received";
}
const char* name(ParticipantKind value) noexcept {
    switch (value) {
    case ParticipantKind::TlsClient:
        return "tls-client";
    case ParticipantKind::TlsServer:
        return "tls-server";
    case ParticipantKind::MockCa:
        return "mock-ca";
    }
    return "unknown";
}
const char* name(CacheMode value) noexcept {
    return value == CacheMode::Empty ? "empty" : "fixed-snapshot";
}
const char* name(FailurePolicy value) noexcept {
    return value == FailurePolicy::FailFast ? "fail-fast" : "fixed-attempts";
}
const char* name(AttemptStatus value) noexcept {
    switch (value) {
    case AttemptStatus::NotAttempted:
        return "not_attempted";
    case AttemptStatus::Success:
        return "success";
    case AttemptStatus::Timeout:
        return "timeout";
    case AttemptStatus::Error:
        return "error";
    case AttemptStatus::Incomplete:
        return "incomplete";
    }
    return "unknown";
}
const char* name(FailurePhase value) noexcept {
    switch (value) {
    case FailurePhase::None:
        return "none";
    case FailurePhase::Startup:
        return "startup";
    case FailurePhase::Listener:
        return "listener";
    case FailurePhase::TcpReady:
        return "tcp_ready";
    case FailurePhase::Scenario:
        return "scenario";
    case FailurePhase::Flush:
        return "flush";
    case FailurePhase::Exit:
        return "exit";
    }
    return "unknown";
}
const char* name(ArtifactStatus value) noexcept {
    switch (value) {
    case ArtifactStatus::Complete:
        return "complete";
    case ArtifactStatus::Partial:
        return "partial";
    case ArtifactStatus::Missing:
        return "missing";
    }
    return "unknown";
}
const char* name(HeapDomain value) noexcept {
    switch (value) {
    case HeapDomain::Tls:
        return "tls";
    case HeapDomain::Lookup:
        return "lookup";
    case HeapDomain::MockCa:
        return "mock_ca";
    }
    return "unknown";
}
const char* name(ServiceEventKind value) noexcept {
    switch (value) {
    case ServiceEventKind::CacheLookup:
        return "CACHE_LOOKUP";
    case ServiceEventKind::CacheHit:
        return "CACHE_HIT";
    case ServiceEventKind::CacheMiss:
        return "CACHE_MISS";
    case ServiceEventKind::CacheInsert:
        return "CACHE_INSERT";
    case ServiceEventKind::RequestBegin:
        return "REQUEST_BEGIN";
    case ServiceEventKind::ResponseComplete:
        return "RESPONSE_COMPLETE";
    case ServiceEventKind::UsableObject:
        return "USABLE_OBJECT";
    case ServiceEventKind::ScenarioBegin:
        return "SCENARIO_BEGIN";
    case ServiceEventKind::ScenarioEnd:
        return "SCENARIO_END";
    case ServiceEventKind::CaProcessBegin:
        return "CA_PROCESS_BEGIN";
    case ServiceEventKind::CaProcessEnd:
        return "CA_PROCESS_END";
    case ServiceEventKind::IoSendEnter:
        return "IO_SEND_ENTER";
    case ServiceEventKind::IoSendReturn:
        return "IO_SEND_RETURN";
    case ServiceEventKind::IoRecvEnter:
        return "IO_RECV_ENTER";
    case ServiceEventKind::IoRecvReturn:
        return "IO_RECV_RETURN";
    case ServiceEventKind::WaitBegin:
        return "WAIT_BEGIN";
    case ServiceEventKind::WaitEnd:
        return "WAIT_END";
    }
    return "unknown";
}
const char* name(Location value) noexcept {
    switch (value) {
    case Location::Boundary:
        return "implementation_boundary";
    case Location::Framework:
        return "framework";
    case Location::Kernel:
        return "kernel";
    case Location::Hardware:
        return "hardware";
    case Location::Syscall:
        return "syscall";
    case Location::Library:
        return "library_hook";
    }
    return "unknown";
}
const char* name(Call value) noexcept {
    switch (value) {
    case Call::None:
        return "none";
    case Call::Setup:
        return "setup";
    case Call::Open:
        return "open";
    case Call::Handshake:
        return "handshake";
    case Call::Verification:
        return "verification";
    case Call::Negotiated:
        return "negotiated";
    case Call::AppSend:
        return "app_send";
    case Call::AppRecv:
        return "app_recv";
    case Call::Close:
        return "close";
    case Call::Save:
        return "save";
    case Call::Teardown:
        return "teardown";
    }
    return "unknown";
}
const char* name(EventKind value) noexcept {
    switch (value) {
    case EventKind::SetupBegin:
        return "SETUP_BEGIN";
    case EventKind::SetupEnd:
        return "SETUP_END";
    case EventKind::TcpReady:
        return "TCP_READY";
    case EventKind::OpenBegin:
        return "OPEN_BEGIN";
    case EventKind::OpenEnd:
        return "OPEN_END";
    case EventKind::CallBegin:
        return "CALL_BEGIN";
    case EventKind::CallEnd:
        return "CALL_END";
    case EventKind::IoSendEnter:
        return "IO_SEND_ENTER";
    case EventKind::IoSendReturn:
        return "IO_SEND_RETURN";
    case EventKind::IoRecvEnter:
        return "IO_RECV_ENTER";
    case EventKind::IoRecvReturn:
        return "IO_RECV_RETURN";
    case EventKind::WaitBegin:
        return "WAIT_BEGIN";
    case EventKind::WaitEnd:
        return "WAIT_END";
    case EventKind::KernelRx:
        return "KERNEL_RX";
    case EventKind::KernelTxSched:
        return "KERNEL_TX_SCHED";
    case EventKind::KernelTxSnd:
        return "KERNEL_TX_SND";
    case EventKind::KernelTxAck:
        return "KERNEL_TX_ACK";
    case EventKind::CloseBegin:
        return "CLOSE_BEGIN";
    case EventKind::CloseEnd:
        return "CLOSE_END";
    case EventKind::Save:
        return "SAVE";
    }
    return "unknown";
}
const char* name(Verification value) noexcept {
    switch (value) {
    case Verification::Passed:
        return "passed";
    case Verification::Failed:
        return "failed";
    case Verification::NotApplicable:
        return "not_applicable";
    }
    return "unknown";
}
const char* name(Step value) noexcept {
    switch (value) {
    case Step::WantRead:
        return "want_read";
    case Step::WantWrite:
        return "want_write";
    case Step::Done:
        return "done";
    case Step::Failed:
        return "failed";
    }
    return "unknown";
}

std::string fingerprint(const std::string& text) {
    return fingerprint(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

std::uint64_t fnv1a64(std::span<const std::uint8_t> bytes) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const std::uint8_t byte : bytes) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::string fingerprint(std::span<const std::uint8_t> bytes) {
    std::ostringstream out;
    out << "fnv1a64:" << std::hex << std::setfill('0') << std::setw(16)
        << fnv1a64(bytes);
    return out.str();
}

} // namespace turtle::model
