#define turtle_adapter_v3 turtle_mock_api
#include "../../implementations/mock/mock.cpp"
#undef turtle_adapter_v3
#include "transport/tcp.hpp"
#include <cerrno>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
namespace {
turtle::Context* checked_setup(turtle::Role role, const turtle::TlsConfig& config,
                               const turtle::HostServices& host,
                               std::span<const std::uint8_t> saved) {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur == 0)
        return nullptr;
    return turtle_mock_api().setup(role, config, host, saved);
}
turtle::Connection* checked_open(turtle::Context* context, const turtle::Io& io) {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NPROC, &limit) || limit.rlim_cur != 0)
        return nullptr;
    if (::getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur == 0)
        return nullptr;
    // The peer may already have sent ClientHello: readiness synchronization
    // finishes before connect, not after adapter open.
    return turtle_mock_api().open(context, io);
}
} // namespace
extern "C" turtle::ImplementationApi turtle_adapter_v3() {
    auto api = turtle_mock_api();
    api.setup = checked_setup;
    api.open = checked_open;
    return api;
}
