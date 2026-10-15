#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <turtle/adapter.hpp>
#include <unistd.h>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using namespace turtle;

constexpr std::string_view client_ping = "turtle-client-ping\n";
constexpr std::string_view server_pong = "openssl-server-pong\n";
constexpr std::string_view openssl_ping = "openssl-client-ping\n";
constexpr std::string_view turtle_pong = "turtle-server-pong\n";

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

std::string json_escape(std::string_view value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20) {
                result += "\\u00";
                result += digits[ch >> 4];
                result += digits[ch & 0xf];
            } else {
                result += static_cast<char>(ch);
            }
        }
    }
    return result;
}

const char* verification_name(Verification value) {
    switch (value) {
    case Verification::Passed: return "passed";
    case Verification::Failed: return "failed";
    case Verification::NotApplicable: return "not_applicable";
    }
    return "unknown";
}

struct Options {
    std::string adapter;
    std::string pki;
    std::string auth;
    std::string result;
    Role role = Role::Client;
    std::uint16_t port = 0;
};

Options parse_options(int argc, char** argv) {
    Options options;
    bool have_role = false;
    bool have_port = false;
    for (int i = 1; i < argc; i += 2) {
        require(i + 1 < argc, "option requires a value: " + std::string(argv[i]));
        const std::string key = argv[i];
        const std::string value = argv[i + 1];
        if (key == "--adapter")
            options.adapter = value;
        else if (key == "--pki")
            options.pki = value;
        else if (key == "--auth")
            options.auth = value;
        else if (key == "--result")
            options.result = value;
        else if (key == "--role") {
            require(value == "client" || value == "server", "role must be client or server");
            options.role = value == "client" ? Role::Client : Role::Server;
            have_role = true;
        } else if (key == "--port") {
            std::size_t used = 0;
            const auto parsed = std::stoul(value, &used);
            require(used == value.size() && parsed <= 65535, "invalid port");
            options.port = static_cast<std::uint16_t>(parsed);
            have_port = true;
        } else {
            throw std::runtime_error("unknown option: " + key);
        }
    }
    require(!options.adapter.empty() && !options.pki.empty() && !options.result.empty() &&
                have_role && have_port,
            "usage: --adapter FILE --role client|server --pki DIR --auth server|mutual "
            "--port PORT --result FILE");
    require(options.auth == "server" || options.auth == "mutual",
            "auth must be server or mutual");
    require(options.role == Role::Server || options.port != 0,
            "client role requires a nonzero port");
    return options;
}

IoResult send_bytes(void* context, const std::uint8_t* data, std::size_t size) noexcept {
    const auto count = ::send(*static_cast<int*>(context), data, size, MSG_NOSIGNAL);
    if (count >= 0)
        return {IoStatus::Ok, static_cast<std::size_t>(count), 0};
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return {IoStatus::WantWrite, 0, errno};
    return {IoStatus::Failed, 0, errno};
}

IoResult recv_bytes(void* context, std::uint8_t* data, std::size_t size) noexcept {
    const auto count = ::recv(*static_cast<int*>(context), data, size, 0);
    if (count > 0)
        return {IoStatus::Ok, static_cast<std::size_t>(count), 0};
    if (count == 0)
        return {IoStatus::Closed, 0, 0};
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return {IoStatus::WantRead, 0, errno};
    return {IoStatus::Failed, 0, errno};
}

std::string socket_error(const char* operation) {
    return std::string(operation) + ": " + std::strerror(errno);
}

void make_nonblocking(int socket) {
    const int flags = fcntl(socket, F_GETFL, 0);
    require(flags >= 0 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0,
            socket_error("fcntl"));
}

int remaining_ms(Clock::time_point deadline) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    require(remaining > 0, "common 10 second deadline exceeded");
    return static_cast<int>(remaining);
}

void wait_socket(int socket, short events, Clock::time_point deadline) {
    pollfd descriptor{socket, events, 0};
    int status;
    do {
        status = poll(&descriptor, 1, remaining_ms(deadline));
    } while (status < 0 && errno == EINTR);
    require(status > 0, status == 0 ? "common 10 second deadline exceeded"
                                    : socket_error("poll"));
    require((descriptor.revents & (POLLERR | POLLNVAL)) == 0, "socket poll failure");
}

int create_listener(std::uint16_t requested_port, std::uint16_t& actual_port) {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    require(listener >= 0, socket_error("socket"));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(requested_port);
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(listener, 1) != 0) {
        const auto error = socket_error("bind/listen");
        ::close(listener);
        throw std::runtime_error(error);
    }
    socklen_t size = sizeof(address);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
        const auto error = socket_error("getsockname");
        ::close(listener);
        throw std::runtime_error(error);
    }
    actual_port = ntohs(address.sin_port);
    make_nonblocking(listener);
    return listener;
}

int accept_connection(int listener, Clock::time_point deadline) {
    for (;;) {
        const int socket = accept(listener, nullptr, nullptr);
        if (socket >= 0)
            return socket;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            throw std::runtime_error(socket_error("accept"));
        wait_socket(listener, POLLIN, deadline);
    }
}

int connect_with_startup_wait(std::uint16_t port, Clock::time_point deadline) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    for (;;) {
        remaining_ms(deadline);
        const int socket = ::socket(AF_INET, SOCK_STREAM, 0);
        require(socket >= 0, socket_error("socket"));
        make_nonblocking(socket);
        int status = connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        if (status == 0)
            return socket;
        if (errno == EINPROGRESS) {
            pollfd descriptor{socket, POLLOUT, 0};
            do {
                status = poll(&descriptor, 1, std::min(50, remaining_ms(deadline)));
            } while (status < 0 && errno == EINTR);
            if (status > 0) {
                int error = 0;
                socklen_t length = sizeof(error);
                require(getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length) == 0,
                        socket_error("getsockopt"));
                if (error == 0)
                    return socket;
                errno = error;
            }
        }
        const int error = errno;
        ::close(socket);
        if (error != ECONNREFUSED && error != EINPROGRESS && error != EAGAIN)
            throw std::runtime_error(std::string("connect: ") + std::strerror(error));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

std::string adapter_error(const ImplementationApi& api, Connection* connection) {
    if (!api.error)
        return "adapter operation failed";
    const char* message = api.error(connection);
    return message ? message : "adapter operation failed without a reason";
}

void wait_for_step(int socket, Step step, Clock::time_point deadline) {
    wait_socket(socket, step == Step::WantWrite ? POLLOUT : POLLIN, deadline);
}

void complete_handshake(const ImplementationApi& api, Connection* connection, int socket,
                        Clock::time_point deadline) {
    for (;;) {
        const Step step = api.handshake_step(connection);
        if (step == Step::Done)
            return;
        require(step != Step::Failed, "handshake failed: " + adapter_error(api, connection));
        wait_for_step(socket, step, deadline);
    }
}

std::size_t send_application(const ImplementationApi& api, Connection* connection, int socket,
                             std::string_view value, Clock::time_point deadline) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto result = api.app_send(
            connection, reinterpret_cast<const std::uint8_t*>(value.data()) + offset,
            value.size() - offset);
        require(result.step != Step::Failed,
                "application send failed: " + adapter_error(api, connection));
        require(result.bytes <= value.size() - offset, "adapter over-reported sent bytes");
        offset += result.bytes;
        if (offset < value.size()) {
            require(result.bytes != 0 || result.step != Step::Done,
                    "application send completed without all bytes");
            if (result.bytes == 0)
                wait_for_step(socket, result.step, deadline);
        }
    }
    return offset;
}

std::string receive_application(const ImplementationApi& api, Connection* connection, int socket,
                                std::string_view expected, Clock::time_point deadline) {
    std::string received(expected.size(), '\0');
    std::size_t offset = 0;
    while (offset < expected.size()) {
        const auto result = api.app_recv(
            connection, reinterpret_cast<std::uint8_t*>(received.data()) + offset,
            received.size() - offset);
        require(result.step != Step::Failed,
                "application receive failed: " + adapter_error(api, connection));
        require(result.bytes <= received.size() - offset, "adapter over-reported received bytes");
        offset += result.bytes;
        if (offset < expected.size()) {
            require(result.bytes != 0 || result.step != Step::Done,
                    "application receive completed without all bytes");
            if (result.bytes == 0)
                wait_for_step(socket, result.step, deadline);
        }
    }
    require(received == expected, "application plaintext mismatch");
    return received;
}

struct Evidence {
    bool success = false;
    std::string error;
    std::string adapter_name;
    Declaration declaration;
    Verification verification = Verification::Failed;
    Negotiated negotiated;
    std::uint16_t port = 0;
    std::size_t sent = 0;
    std::string received;
    std::string expected_sent;
    std::string expected_received;
    std::size_t key_log_lines = 0;
};

std::string source_for(std::string_view adapter, std::string_view field) {
    if (field == "version" || field == "cipher" || field == "peer_certificate_present")
        return "observed";
    if (adapter == "openssl") {
        if (field == "group" || field == "resumed" || field == "hello_retry_request")
            return "observed";
        return "unobserved";
    }
    if (adapter == "wolfssl") {
        if (field == "group" || field == "resumed" || field == "signature")
            return "observed";
        if (field == "hello_retry_request")
            return "inferred";
    }
    if (adapter == "Mbed TLS") {
        if (field == "group" || field == "signature" || field == "resumed" ||
            field == "hello_retry_request")
            return "inferred";
    }
    return "unobserved";
}

std::string source_basis(std::string_view adapter, std::string_view field) {
    if (field == "version" || field == "cipher" || field == "peer_certificate_present")
        return "adapter runtime query";
    if (adapter == "openssl") {
        if (field == "group")
            return "SSL_get_negotiated_group";
        if (field == "resumed")
            return "SSL_session_reused";
        if (field == "hello_retry_request")
            return "TLS message callback";
        return "OpenSSL adapter does not expose the negotiated signature";
    }
    if (adapter == "wolfssl") {
        if (field == "group")
            return "wolfSSL_get_curve_name";
        if (field == "signature")
            return "wolfSSL signature NID queries";
        if (field == "resumed")
            return "wolfSSL_session_reused";
        if (field == "hello_retry_request")
            return "inferred from the adapter's single permitted group; no runtime HRR query";
    }
    if (adapter == "Mbed TLS" &&
        (field == "group" || field == "signature" || field == "resumed" ||
         field == "hello_retry_request"))
        return "inferred from the adapter's fixed configuration; no runtime query";
    return "not exposed by the adapter";
}

void write_result(const Options& options, const Evidence& evidence) {
    std::ofstream output(options.result, std::ios::binary | std::ios::trunc);
    require(output.good(), "cannot open result file: " + options.result);
    const auto quoted = [](std::string_view value) { return '"' + json_escape(value) + '"'; };
    output << "{\n"
           << "  \"success\": " << (evidence.success ? "true" : "false") << ",\n"
           << "  \"error\": " << quoted(evidence.error) << ",\n"
           << "  \"role\": " << quoted(options.role == Role::Client ? "client" : "server")
           << ",\n  \"auth\": " << quoted(options.auth)
           << ",\n  \"framework_io\": true,\n  \"port\": " << evidence.port << ",\n"
           << "  \"adapter\": {\"name\": " << quoted(evidence.adapter_name)
           << ", \"library\": " << quoted(evidence.declaration.library)
           << ", \"version\": " << quoted(evidence.declaration.version)
           << ", \"build_options\": " << quoted(evidence.declaration.build_options)
           << ", \"callback_io\": "
           << (evidence.declaration.callback_io ? "true" : "false") << "},\n"
           << "  \"verification\": " << quoted(verification_name(evidence.verification))
           << ",\n  \"negotiated\": {\n"
           << "    \"version\": " << quoted(evidence.negotiated.version)
           << ", \"cipher\": " << quoted(evidence.negotiated.cipher)
           << ", \"group\": " << quoted(evidence.negotiated.group)
           << ", \"signature\": " << quoted(evidence.negotiated.signature)
           << ", \"resumed\": " << (evidence.negotiated.resumed ? "true" : "false")
           << ", \"hello_retry_request\": "
           << (evidence.negotiated.hello_retry_request ? "true" : "false")
           << ", \"peer_certificate_present\": "
           << (evidence.negotiated.peer_certificate_present ? "true" : "false") << "\n  },\n"
           << "  \"negotiated_sources\": {";
    const char* separator = "";
    for (const auto field : {"version", "cipher", "group", "signature", "resumed",
                             "hello_retry_request", "peer_certificate_present"}) {
        output << separator << quoted(field) << ": " << quoted(source_for(evidence.adapter_name, field));
        separator = ", ";
    }
    output << "},\n  \"negotiated_source_basis\": {";
    separator = "";
    for (const auto field : {"version", "cipher", "group", "signature", "resumed",
                             "hello_retry_request", "peer_certificate_present"}) {
        output << separator << quoted(field) << ": "
               << quoted(source_basis(evidence.adapter_name, field));
        separator = ", ";
    }
    output << "},\n  \"application\": {\"expected_sent\": "
           << quoted(evidence.expected_sent) << ", \"sent_bytes\": " << evidence.sent
           << ", \"expected_received\": " << quoted(evidence.expected_received)
           << ", \"received\": " << quoted(evidence.received)
           << ", \"received_bytes\": " << evidence.received.size() << "},\n"
           << "  \"key_log_lines\": " << evidence.key_log_lines
           << ",\n  \"shutdown\": \"connection close without a TLS close_notify API; peer EOF "
              "accommodation is required\"\n}\n";
    require(output.good(), "failed to write result file: " + options.result);
}

} // namespace

int main(int argc, char** argv) {
    Options options;
    Evidence evidence;
    bool parsed = false;
    void* module = nullptr;
    ImplementationApi api{};
    Context* context = nullptr;
    Connection* connection = nullptr;
    int socket = -1;
    int listener = -1;

    // These borrowed objects are created before setup and remain alive until explicit teardown.
    TlsConfig config;
    std::size_t key_log_lines = 0;
    HostServices services;
    Io io;

    try {
        options = parse_options(argc, argv);
        parsed = true;
        const auto deadline = Clock::now() + std::chrono::seconds(10);

        config.ca_file = options.pki + "/ca.pem";
        config.server_certificate = options.pki + "/server-chain.pem";
        config.server_key = options.pki + "/server.key";
        config.client_certificate = options.pki + "/client-chain.pem";
        config.client_key = options.pki + "/client.key";
        config.mutual_auth = options.auth == "mutual";
        config.framework_io = true;
        config.tickets = 0;
        services.key_log = {&key_log_lines, [](void* state, const char*, std::size_t size) noexcept {
                                if (size != 0)
                                    ++*static_cast<std::size_t*>(state);
                                return true;
                            }};

        module = dlopen(options.adapter.c_str(), RTLD_NOW | RTLD_LOCAL);
        const char* load_error = module ? nullptr : dlerror();
        require(module != nullptr,
                std::string("dlopen failed: ") + (load_error ? load_error : "unknown"));
        dlerror();
        auto entry = reinterpret_cast<AdapterEntry>(dlsym(module, adapter_entry_name));
        const char* symbol_error = dlerror();
        require(symbol_error == nullptr && entry != nullptr,
                std::string("adapter ABI v2 entry turtle_adapter_v2 is missing: ") +
                    (symbol_error ? symbol_error : "unknown"));
        api = entry();
        require(api.version == adapter_api_version, "adapter API version mismatch");
        require(api.name && api.declaration && api.setup && api.open && api.handshake_step &&
                    api.peer_verification && api.negotiated && api.app_send && api.app_recv &&
                    api.error && api.close && api.save && api.teardown,
                "adapter API function table is incomplete");
        const char* adapter_name = api.name();
        require(adapter_name != nullptr && *adapter_name != '\0', "adapter name is empty");
        evidence.adapter_name = adapter_name;

        context = api.setup(options.role, config, services, {});
        require(context != nullptr, "adapter setup failed");
        evidence.declaration = api.declaration(context);
        require(evidence.declaration.callback_io, "adapter did not declare callback I/O");

        if (options.role == Role::Server) {
            listener = create_listener(options.port, evidence.port);
            std::cout << "READY " << evidence.port << '\n' << std::flush;
            socket = accept_connection(listener, deadline);
            ::close(listener);
            listener = -1;
            evidence.expected_received = std::string(openssl_ping);
            evidence.expected_sent = std::string(turtle_pong);
        } else {
            evidence.port = options.port;
            socket = connect_with_startup_wait(options.port, deadline);
            evidence.expected_sent = std::string(client_ping);
            evidence.expected_received = std::string(server_pong);
        }
        make_nonblocking(socket);
        io = {&socket, send_bytes, recv_bytes, socket};
        connection = api.open(context, io);
        require(connection != nullptr, "adapter open failed");
        complete_handshake(api, connection, socket, deadline);

        evidence.verification = api.peer_verification(connection);
        const auto expected_verification =
            options.role == Role::Server && !config.mutual_auth ? Verification::NotApplicable
                                                                : Verification::Passed;
        require(evidence.verification == expected_verification, "peer verification mismatch");
        evidence.negotiated = api.negotiated(connection);
        require(evidence.negotiated.version == "TLS1.3" ||
                    evidence.negotiated.version == "TLSv1.3",
                "negotiated version is not TLS1.3");
        require(evidence.negotiated.cipher == config.cipher, "negotiated cipher mismatch");
        require(evidence.negotiated.peer_certificate_present ==
                    (options.role == Role::Client || config.mutual_auth),
                "peer certificate presence mismatch");
        const auto group_source = source_for(evidence.adapter_name, "group");
        if (group_source == "observed")
            require(evidence.negotiated.group == config.group, "observed group mismatch");
        else if (group_source == "inferred")
            require(evidence.negotiated.group == config.group, "inferred group contradicts config");
        const auto signature_source = source_for(evidence.adapter_name, "signature");
        if (signature_source == "observed")
            require(evidence.negotiated.signature == config.signature,
                    "observed signature mismatch");
        else if (signature_source == "inferred")
            require(evidence.negotiated.signature == config.signature,
                    "inferred signature contradicts config");
        const auto resumed_source = source_for(evidence.adapter_name, "resumed");
        if (resumed_source == "observed" || resumed_source == "inferred")
            require(!evidence.negotiated.resumed,
                    resumed_source + " resumption value contradicts a fresh connection");
        const auto hrr_source = source_for(evidence.adapter_name, "hello_retry_request");
        if (hrr_source == "observed" || hrr_source == "inferred")
            require(!evidence.negotiated.hello_retry_request,
                    hrr_source + " HelloRetryRequest value contradicts the single-group path");

        if (options.role == Role::Client) {
            evidence.sent = send_application(api, connection, socket, client_ping, deadline);
            evidence.received = receive_application(api, connection, socket, server_pong, deadline);
        } else {
            evidence.received = receive_application(api, connection, socket, openssl_ping, deadline);
            evidence.sent = send_application(api, connection, socket, turtle_pong, deadline);
        }
        evidence.key_log_lines = key_log_lines;
        evidence.success = true;
    } catch (const std::exception& error) {
        evidence.error = error.what();
        std::cerr << error.what() << '\n';
    }

    // The adapter borrows Io, config, services, and callback state. Release it before any of them,
    // and unload the module only after its connection and context destructors have run.
    if (connection && api.close)
        api.close(connection);
    connection = nullptr;
    if (context && api.teardown)
        api.teardown(context);
    context = nullptr;
    if (socket >= 0)
        ::close(socket);
    if (listener >= 0)
        ::close(listener);
    if (module)
        dlclose(module);

    if (parsed) {
        try {
            write_result(options, evidence);
        } catch (const std::exception& error) {
            std::cerr << error.what() << '\n';
            return 1;
        }
    }
    return evidence.success ? 0 : 1;
}
