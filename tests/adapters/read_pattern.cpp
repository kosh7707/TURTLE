#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <dlfcn.h>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <turtle/adapter.hpp>
#include <vector>

using namespace turtle;
namespace {
void check(bool value, const std::string& message) {
    if (!value)
        throw std::runtime_error(message);
}

struct ReadEvent {
    std::size_t requested = 0;
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct MemoryChannel {
    std::deque<std::uint8_t> inbound;
    std::vector<std::uint8_t> sent;
    std::vector<std::uint8_t> received;
    std::vector<ReadEvent> successful_reads;
    MemoryChannel* peer = nullptr;
    std::size_t maximum_read = std::numeric_limits<std::size_t>::max();
};

IoResult send_bytes(void* context, const std::uint8_t* data, std::size_t size) noexcept {
    auto& channel = *static_cast<MemoryChannel*>(context);
    channel.sent.insert(channel.sent.end(), data, data + size);
    channel.peer->inbound.insert(channel.peer->inbound.end(), data, data + size);
    return {IoStatus::Ok, size, 0};
}

IoResult receive_bytes(void* context, std::uint8_t* data, std::size_t size) noexcept {
    auto& channel = *static_cast<MemoryChannel*>(context);
    if (channel.inbound.empty())
        return {IoStatus::WantRead, 0, 0};
    const auto count = std::min({size, channel.maximum_read, channel.inbound.size()});
    const auto begin = channel.received.size();
    for (std::size_t i = 0; i < count; ++i) {
        data[i] = channel.inbound.front();
        channel.inbound.pop_front();
    }
    channel.received.insert(channel.received.end(), data, data + count);
    channel.successful_reads.push_back({size, begin, begin + count});
    return {IoStatus::Ok, count, 0};
}

struct LoadedAdapter {
    void* module = nullptr;
    ImplementationApi api{};
    explicit LoadedAdapter(const char* path) {
        module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        check(module != nullptr, "dlopen failed: " + std::string(path));
        const auto entry = reinterpret_cast<AdapterEntry>(dlsym(module, adapter_entry_name));
        check(entry != nullptr, "adapter ABI v3 entry is missing");
        api = entry();
        check(api.version == adapter_api_version, "adapter API version mismatch");
        check(api.name && api.declaration && api.setup && api.open && api.handshake_step &&
                  api.peer_verification && api.negotiated && api.app_send && api.app_recv &&
                  api.error && api.close && api.save && api.teardown,
              "adapter API function table is incomplete");
    }
    ~LoadedAdapter() {
        if (module)
            dlclose(module);
    }
};

struct Endpoint {
    const ImplementationApi& api;
    Context* context = nullptr;
    Connection* connection = nullptr;
    MemoryChannel channel;
    Io io;
    Endpoint(const ImplementationApi& value, Role role, const TlsConfig& config,
             const HostServices& services)
        : api(value), context(api.setup(role, config, services, {})),
          io{&channel, send_bytes, receive_bytes, -1} {
        check(context != nullptr, "adapter setup failed");
    }
    ~Endpoint() {
        if (connection)
            api.close(connection);
        if (context)
            api.teardown(context);
    }
    void open() {
        connection = api.open(context, io);
        check(connection != nullptr, "adapter connection open failed");
    }
};

struct Record {
    std::size_t begin = 0;
    std::size_t header_end = 0;
    std::size_t end = 0;
};

std::vector<Record> records(const std::vector<std::uint8_t>& stream) {
    std::vector<Record> result;
    for (std::size_t offset = 0; offset < stream.size();) {
        check(stream.size() - offset >= 5, "incomplete TLS record header in sent stream");
        const auto payload = (std::size_t(stream[offset + 3]) << 8) | stream[offset + 4];
        check(payload <= stream.size() - offset - 5,
              "incomplete TLS record payload in sent stream");
        result.push_back({offset, offset + 5, offset + 5 + payload});
        offset += 5 + payload;
    }
    return result;
}

const Record& containing_record(const std::vector<Record>& parsed, std::size_t offset) {
    const auto item = std::find_if(parsed.begin(), parsed.end(), [=](const Record& record) {
        return record.begin <= offset && offset < record.end;
    });
    check(item != parsed.end(), "successful receive lies outside the TLS record stream");
    return *item;
}

void validate_full_reads(const MemoryChannel& sender, const MemoryChannel& receiver,
                         const std::string& label) {
    const auto parsed = records(sender.sent);
    check(receiver.received == sender.sent && receiver.inbound.empty(),
          label + ": receiver did not consume the exact TLS stream");
    check(receiver.successful_reads.size() == parsed.size() * 2,
          label + ": all-bytes-ready condition did not use header then body returns");
    for (std::size_t i = 0; i < parsed.size(); ++i) {
        const auto& record = parsed[i];
        const auto& header = receiver.successful_reads[i * 2];
        const auto& body = receiver.successful_reads[i * 2 + 1];
        check(header.begin == record.begin && header.end == record.header_end &&
                  header.requested == 5,
              label + ": controlled header receive differs from five exact bytes");
        check(body.begin == record.header_end && body.end == record.end &&
                  body.requested == record.end - record.header_end,
              label + ": controlled body receive differs from the exact remaining payload");
    }
}

void validate_short_reads(const MemoryChannel& sender, const MemoryChannel& receiver,
                          std::size_t chunk, const std::string& label) {
    const auto parsed = records(sender.sent);
    check(receiver.received == sender.sent && receiver.inbound.empty(),
          label + ": short reads changed the TLS stream");
    check(receiver.successful_reads.size() > parsed.size() * 2,
          label + ": short-read condition did not exercise additional returns");
    for (const auto& read : receiver.successful_reads) {
        const auto& record = containing_record(parsed, read.begin);
        const auto boundary = read.begin < record.header_end ? record.header_end : record.end;
        check(read.requested == boundary - read.begin,
              label + ": adapter did not request the exact header/body remainder");
        check(read.end == read.begin + std::min(chunk, read.requested) && read.end <= boundary,
              label + ": short receive crossed a header, body, or next-record boundary");
    }
}

void drive_handshake(Endpoint& client, Endpoint& server) {
    Step client_step = Step::WantRead;
    Step server_step = Step::WantRead;
    for (std::size_t iteration = 0; iteration < 10000; ++iteration) {
        if (client_step != Step::Complete)
            client_step = client.api.handshake_step(client.connection);
        if (server_step != Step::Complete)
            server_step = server.api.handshake_step(server.connection);
        check(client_step != Step::Failed,
              std::string("client handshake failed: ") + client.api.error(client.connection));
        check(server_step != Step::Failed,
              std::string("server handshake failed: ") + server.api.error(server.connection));
        if (client_step == Step::Complete && server_step == Step::Complete)
            return;
    }
    throw std::runtime_error("in-memory TLS handshake did not converge");
}

void exchange(Endpoint& sender, Endpoint& receiver) {
    std::array<std::uint8_t, 32> payload{}, output{};
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<std::uint8_t>(i + 1);
    std::size_t sent = 0;
    std::size_t read = 0;
    for (std::size_t iteration = 0; iteration < 10000; ++iteration) {
        if (sent < payload.size()) {
            const auto result = sender.api.app_send(sender.connection, payload.data() + sent,
                                                    payload.size() - sent);
            check(result.step != Step::Failed,
                  std::string("application send failed: ") + sender.api.error(sender.connection));
            sent += result.bytes;
        }
        if (read < output.size()) {
            const auto result = receiver.api.app_recv(receiver.connection, output.data() + read,
                                                      output.size() - read);
            check(result.step != Step::Failed, std::string("application receive failed: ") +
                                                   receiver.api.error(receiver.connection));
            read += result.bytes;
        }
        if (sent == payload.size() && read == output.size()) {
            check(output == payload, "encrypted application payload differs");
            return;
        }
    }
    throw std::runtime_error("in-memory application exchange did not converge");
}

void run_condition(const ImplementationApi& api, const std::string& pki, std::size_t maximum_read,
                   const std::string& condition) {
    TlsConfig config;
    config.ca_file = pki + "/ca.pem";
    config.server_certificate = pki + "/server-chain.pem";
    config.server_key = pki + "/server.key";
    config.client_certificate = pki + "/client-chain.pem";
    config.client_key = pki + "/client.key";
    config.framework_io = true;
    HostServices services;
    Endpoint client(api, Role::Client, config, services);
    Endpoint server(api, Role::Server, config, services);
    client.channel.peer = &server.channel;
    server.channel.peer = &client.channel;
    client.channel.maximum_read = maximum_read;
    server.channel.maximum_read = maximum_read;
    client.open();
    server.open();
    drive_handshake(client, server);
    check(client.api.peer_verification(client.connection) == Verification::Passed,
          condition + ": client certificate verification failed");
    check(server.api.peer_verification(server.connection) == Verification::NotApplicable,
          condition + ": server verification state changed");
    exchange(client, server);
    exchange(server, client);
    for (auto* endpoint : {&client, &server}) {
        const auto negotiated = endpoint->api.negotiated(endpoint->connection);
        check((negotiated.version == "TLS1.3" || negotiated.version == "TLSv1.3") &&
                  negotiated.cipher == config.cipher && negotiated.group == config.group &&
                  !negotiated.resumed && !negotiated.hello_retry_request,
              condition + ": TLS negotiation changed");
        const auto declaration = endpoint->api.declaration(endpoint->context);
        check(declaration.read_ahead == std::optional<bool>(false) &&
                  !declaration.read_ahead_note.empty(),
              condition + ": real adapter read policy is not explicitly declared");
    }
    if (maximum_read == std::numeric_limits<std::size_t>::max()) {
        validate_full_reads(client.channel, server.channel, condition + " client-to-server");
        validate_full_reads(server.channel, client.channel, condition + " server-to-client");
    } else {
        validate_short_reads(client.channel, server.channel, maximum_read,
                             condition + " client-to-server");
        validate_short_reads(server.channel, client.channel, maximum_read,
                             condition + " server-to-client");
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        check(argc == 3, "usage: read_pattern ADAPTER.so PKI_DIR");
        LoadedAdapter adapter(argv[1]);
        const std::string pki = argv[2];
        run_condition(adapter.api, pki, std::numeric_limits<std::size_t>::max(), "all-bytes-ready");
        run_condition(adapter.api, pki, 3, "normal-three-byte-returns");
        std::cout << "PASS real TLS controlled read policy: " << adapter.api.name() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
