#define turtle_adapter_v1 turtle_mock_api
#include "../../implementations/mock/mock.cpp"
#undef turtle_adapter_v1
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
    if (::getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur != 0)
        return nullptr;
    errno = 0;
    const int isolated_socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (isolated_socket >= 0) {
        ::close(isolated_socket);
        return nullptr;
    }
    if (errno != EMFILE)
        return nullptr;
    // Every open must receive a fresh, established and still empty TCP stream.
    if (!turtle::tcp::check_ready(io.native_socket).empty())
        return nullptr;
    return turtle_mock_api().open(context, io);
}
} // namespace
extern "C" turtle::ImplementationApi turtle_adapter_v1() {
    auto api = turtle_mock_api();
    api.setup = checked_setup;
    api.open = checked_open;
    return api;
}
