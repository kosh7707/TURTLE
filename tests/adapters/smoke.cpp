#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <chrono>
#include <dlfcn.h>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <turtle/adapter.hpp>
#include <unistd.h>

using namespace turtle;
namespace {
void check(bool value, const std::string& error) {
    if (!value)
        throw std::runtime_error(error);
}
IoResult send_bytes(void* context, const std::uint8_t* data, std::size_t size) noexcept {
    auto count = ::send(*static_cast<int*>(context), data, size, MSG_NOSIGNAL);
    if (count >= 0)
        return {IoStatus::Ok, static_cast<std::size_t>(count), 0};
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return {IoStatus::WantWrite, 0, errno};
    return {IoStatus::Failed, 0, errno};
}
IoResult recv_bytes(void* context, std::uint8_t* data, std::size_t size) noexcept {
    auto count = ::recv(*static_cast<int*>(context), data, size, 0);
    if (count > 0)
        return {IoStatus::Ok, static_cast<std::size_t>(count), 0};
    if (count == 0)
        return {IoStatus::Closed, 0, 0};
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return {IoStatus::WantRead, 0, errno};
    return {IoStatus::Failed, 0, errno};
}
struct Endpoint {
    void* module = nullptr;
    ImplementationApi api{};
    Context* context = nullptr;
    Connection* connection = nullptr;
    int socket = -1;
    Io io;
    ~Endpoint() {
        if (connection)
            api.close(connection);
        if (context)
            api.teardown(context);
        if (socket >= 0)
            ::close(socket);
        if (module)
            dlclose(module);
    }
    void load(const char* path) {
        module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        check(module, "dlopen failed: " + std::string(path));
        auto entry = reinterpret_cast<AdapterEntry>(dlsym(module, adapter_entry_name));
        check(entry, "adapter entry missing");
        api = entry();
        check(api.version == adapter_api_version, "adapter API mismatch");
    }
};
} // namespace
int main(int argc, char** argv) {
    try {
        check(argc >= 4, "usage: smoke CLIENT.so SERVER.so PKI_DIR [mutual] [native]");
        Endpoint client, server;
        client.load(argv[1]);
        server.load(argv[2]);
        TlsConfig config;
        const std::string pki = argv[3];
        config.ca_file = pki + "/ca.pem";
        config.server_certificate = pki + "/server-chain.pem";
        config.server_key = pki + "/server.key";
        config.client_certificate = pki + "/client-chain.pem";
        config.client_key = pki + "/client.key";
        config.mutual_auth = argc > 4 && std::string(argv[4]) == "mutual";
        config.framework_io = !(argc > 5 && std::string(argv[5]) == "native");
        std::size_t key_lines = 0;
        HostServices services;
        services.key_log = {&key_lines, [](void* p, const char*, std::size_t n) noexcept {
                                if (n)
                                    ++*static_cast<std::size_t*>(p);
                                return true;
                            }};
        for (const auto* cipher : {"TLS_AES_256_GCM_SHA384",
                                  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"}) {
            auto unsupported = config;
            unsupported.cipher = cipher;
            for (auto* endpoint : {&client, &server}) {
                Context* unexpected = nullptr;
                Connection* pending = nullptr;
                bool rejected = false;
                std::size_t io_calls = 0;
                try {
                    const auto role = endpoint == &client ? Role::Client : Role::Server;
                    unexpected = endpoint->api.setup(role, unsupported, services, {});
                    rejected = !unexpected;
                    if (unexpected) {
                        // Some adapters carry setup errors to the first operation.
                        Io probe;
                        probe.context = &io_calls;
                        probe.send = [](void* p, const std::uint8_t*, std::size_t) noexcept {
                            ++*static_cast<std::size_t*>(p);
                            return IoResult{IoStatus::WantWrite, 0, 0};
                        };
                        probe.recv = [](void* p, std::uint8_t*, std::size_t) noexcept {
                            ++*static_cast<std::size_t*>(p);
                            return IoResult{IoStatus::WantRead, 0, 0};
                        };
                        pending = endpoint->api.open(unexpected, probe);
                        if (pending && endpoint->api.handshake_step(pending) == Step::Failed &&
                            endpoint->api.error) {
                            const auto* reason = endpoint->api.error(pending);
                            rejected = reason && std::string(reason).find("TLS_AES_128_GCM_SHA256") !=
                                                     std::string::npos;
                        }
                    }
                } catch (const std::exception& error) {
                    rejected = std::string(error.what()).find("TLS_AES_128_GCM_SHA256") !=
                               std::string::npos;
                }
                if (pending)
                    endpoint->api.close(pending);
                if (unexpected)
                    endpoint->api.teardown(unexpected);
                check(rejected && io_calls == 0,
                      "adapter accepted an out-of-scope cipher suite before TLS I/O");
            }
        }
        client.context = client.api.setup(Role::Client, config, services, {});
        server.context = server.api.setup(Role::Server, config, services, {});
        check(client.context && server.context, "setup failed");
        int listener = ::socket(AF_INET, SOCK_STREAM, 0);
        check(listener >= 0, "listener creation failed");
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        check(bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
                  listen(listener, 1) == 0,
              "listen failed");
        socklen_t length = sizeof(addr);
        check(getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &length) == 0,
              "address failed");
        client.socket = ::socket(AF_INET, SOCK_STREAM, 0);
        check(connect(client.socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0,
              "connect failed");
        server.socket = accept(listener, nullptr, nullptr);
        ::close(listener);
        check(server.socket >= 0, "accept failed");
        for (auto* ep : {&client, &server}) {
            check(fcntl(ep->socket, F_SETFL, O_NONBLOCK) == 0, "nonblocking failed");
            ep->io = {&ep->socket, send_bytes, recv_bytes, ep->socket};
            ep->connection = ep->api.open(ep->context, ep->io);
            check(ep->connection, "open failed");
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        auto wait = [&] {
            check(std::chrono::steady_clock::now() < deadline, "TLS deadline exceeded");
            pollfd fds[]{{client.socket, POLLIN, 0}, {server.socket, POLLIN, 0}};
            poll(fds, 2, 1);
        };
        Step cs = Step::WantRead, ss = Step::WantRead;
        while (cs != Step::Done || ss != Step::Done) {
            if (cs != Step::Done)
                cs = client.api.handshake_step(client.connection);
            if (ss != Step::Done)
                ss = server.api.handshake_step(server.connection);
            check(cs != Step::Failed,
                  std::string("client handshake: ") + client.api.error(client.connection));
            check(ss != Step::Failed,
                  std::string("server handshake: ") + server.api.error(server.connection));
            wait();
        }
        check(client.api.peer_verification(client.connection) == Verification::Passed,
              "client verification failed");
        check(server.api.peer_verification(server.connection) ==
                  (config.mutual_auth ? Verification::Passed : Verification::NotApplicable),
              "server verification failed");
        for (auto* ep : {&client, &server}) {
            auto n = ep->api.negotiated(ep->connection);
            check(n.version == "TLS1.3" || n.version == "TLSv1.3", "not TLS1.3");
            check(!n.resumed && !n.hello_retry_request, "not normal full handshake");
            check(n.cipher == config.cipher, "cipher mismatch");
            check(n.group == config.group, "group mismatch: " + n.group);
        }
        std::array<std::uint8_t, 32> payload{}, received{};
        for (std::size_t i = 0; i < payload.size(); ++i)
            payload[i] = static_cast<std::uint8_t>(i);
        auto exchange = [&](Endpoint& sender, Endpoint& receiver) {
            std::size_t sent = 0, read = 0;
            while (sent < payload.size() || read < payload.size()) {
                if (sent < payload.size()) {
                    auto r = sender.api.app_send(sender.connection, payload.data() + sent,
                                                 payload.size() - sent);
                    check(r.step != Step::Failed,
                          std::string("send failed: ") + sender.api.error(sender.connection));
                    sent += r.bytes;
                }
                if (read < payload.size()) {
                    auto r = receiver.api.app_recv(receiver.connection, received.data() + read,
                                                   received.size() - read);
                    check(r.step != Step::Failed,
                          std::string("recv failed: ") + receiver.api.error(receiver.connection));
                    read += r.bytes;
                }
                wait();
            }
            check(payload == received, "encrypted payload mismatch");
        };
        exchange(client, server);
        exchange(server, client);
        if (client.api.declaration(client.context).key_log ||
            server.api.declaration(server.context).key_log)
            check(key_lines > 0, "declared key logging produced no lines");
        check(client.api.save(client.context).empty() && server.api.save(server.context).empty(),
              "unexpected retained state");
        std::cout << "PASS real TCP TLS1.3 " << client.api.name() << " -> " << server.api.name()
                  << (config.mutual_auth ? " mTLS" : " server-auth")
                  << " encrypted pingpong; key lines=" << key_lines << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
