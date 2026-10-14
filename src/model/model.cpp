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
const char* name(Direction value) noexcept {
    return value == Direction::Sent ? "sent" : "received";
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
    // Stable identification only, not an integrity or security assertion. Do
    // not initialize libcrypto in the director before adapter allocator hooks.
    std::uint64_t hash = 14695981039346656037ULL;
    for (const unsigned char byte : text) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    std::ostringstream out;
    out << "fnv1a64:" << std::hex << std::setfill('0') << std::setw(16) << hash;
    return out.str();
}

} // namespace turtle::model
