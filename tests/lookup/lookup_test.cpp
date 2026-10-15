#include "lookup/lookup.hpp"
#include "measure/measure.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
bool forbid_global_allocation = false;
}

void* operator new(std::size_t size) {
    if (forbid_global_allocation)
        std::abort();
    if (void* memory = std::malloc(size == 0 ? 1 : size))
        return memory;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) {
    return ::operator new(size);
}
void operator delete(void* memory) noexcept {
    std::free(memory);
}
void operator delete(void* memory, std::size_t) noexcept {
    std::free(memory);
}
void operator delete[](void* memory) noexcept {
    std::free(memory);
}
void operator delete[](void* memory, std::size_t) noexcept {
    std::free(memory);
}

namespace {
using turtle::Io;
using turtle::IoResult;
using turtle::IoStatus;
using turtle::lookup::Progress;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

constexpr std::string_view certificate_fixture =
    "-----BEGIN CERTIFICATE-----\n"
    "TURTLE fixed opaque fixture 01\n"
    "-----END CERTIFICATE-----\n";
constexpr std::uint64_t fixture_id = 0xc9bb1a237fa2501aULL;

std::vector<std::uint8_t> bytes(std::string_view text) {
    return {text.begin(), text.end()};
}

std::uint64_t reference_fnv1a(std::span<const std::uint8_t> input) {
    std::uint64_t value = 14695981039346656037ULL;
    for (const auto byte : input) {
        value ^= byte;
        value *= 1099511628211ULL;
    }
    return value;
}

struct EventLog {
    std::vector<turtle::lookup::Observation> events;
    static void record(void* opaque, const turtle::lookup::Observation& event) noexcept {
        static_cast<EventLog*>(opaque)->events.push_back(event);
    }
    turtle::lookup::Observer observer() {
        events.reserve(4096);
        return {this, record};
    }
    std::size_t count(turtle::lookup::SemanticEventKind kind) const {
        return static_cast<std::size_t>(std::count_if(
            events.begin(), events.end(), [kind](const auto& event) { return event.kind == kind; }));
    }
    std::size_t first(turtle::lookup::SemanticEventKind kind) const {
        const auto found = std::find_if(events.begin(), events.end(),
                                        [kind](const auto& event) { return event.kind == kind; });
        require(found != events.end(), "required observation is missing");
        return static_cast<std::size_t>(found - events.begin());
    }
    void require_identity(std::uint64_t sample, std::uint32_t connection,
                          std::uint64_t object_id) const {
        require(std::all_of(events.begin(), events.end(), [&](const auto& event) {
                    return event.sample == sample && event.connection == connection &&
                           event.request_id == turtle::lookup::single_request_id &&
                           event.object_id == object_id;
                }),
                "semantic event lost its lookup identity");
    }
};

struct Endpoint {
    Endpoint* peer = nullptr;
    std::vector<std::uint8_t> incoming;
    std::size_t consumed = 0;
    std::size_t chunk = 7;
    bool defer_send = true;
    bool defer_recv = true;
    std::size_t send_calls = 0;
    std::size_t recv_calls = 0;

    static IoResult send(void* opaque, const std::uint8_t* data, std::size_t size) noexcept {
        auto& self = *static_cast<Endpoint*>(opaque);
        ++self.send_calls;
        if (self.defer_send) {
            self.defer_send = false;
            return {IoStatus::WantWrite, 0, 0};
        }
        self.defer_send = true;
        const auto amount = std::min(size, self.chunk);
        self.peer->incoming.insert(self.peer->incoming.end(), data, data + amount);
        return {IoStatus::Ok, amount, 0};
    }

    static IoResult recv(void* opaque, std::uint8_t* data, std::size_t size) noexcept {
        auto& self = *static_cast<Endpoint*>(opaque);
        ++self.recv_calls;
        if (self.consumed == self.incoming.size())
            return {IoStatus::WantRead, 0, 0};
        if (self.defer_recv) {
            self.defer_recv = false;
            return {IoStatus::WantRead, 0, 0};
        }
        self.defer_recv = true;
        const auto available = self.incoming.size() - self.consumed;
        const auto amount = std::min({size, self.chunk, available});
        std::copy_n(self.incoming.data() + self.consumed, amount, data);
        self.consumed += amount;
        return {IoStatus::Ok, amount, 0};
    }

    Io io() noexcept {
        return {this, send, recv, -1};
    }
};

struct ExchangeResult {
    std::size_t request_bytes = 0;
    std::size_t response_bytes = 0;
    bool client_want_read = false;
    bool client_want_write = false;
    bool server_want_read = false;
    bool server_want_write = false;
    bool client_send_state = false;
    bool client_header_state = false;
    bool client_payload_state = false;
    bool server_receive_state = false;
    bool server_header_state = false;
    bool server_payload_state = false;
};

ExchangeResult exchange(turtle::lookup::Client& client, turtle::lookup::Responder& responder,
                        Endpoint& client_endpoint, Endpoint& server_endpoint) {
    auto client_io = client_endpoint.io();
    auto server_io = server_endpoint.io();
    client.begin(19, 3);
    responder.begin(19, 3);
    ExchangeResult result;
    for (std::size_t iteration = 0; iteration != 200000; ++iteration) {
        forbid_global_allocation = true;
        const auto client_progress = client.advance(client_io);
        const auto server_progress = responder.advance(server_io);
        forbid_global_allocation = false;
        result.client_want_read |= client_progress == Progress::WantRead;
        result.client_want_write |= client_progress == Progress::WantWrite;
        result.server_want_read |= server_progress == Progress::WantRead;
        result.server_want_write |= server_progress == Progress::WantWrite;
        result.client_send_state |=
            client.state() == turtle::lookup::ClientState::SendingRequest;
        result.client_header_state |=
            client.state() == turtle::lookup::ClientState::ReceivingHeader;
        result.client_payload_state |=
            client.state() == turtle::lookup::ClientState::ReceivingPayload;
        result.server_receive_state |=
            responder.state() == turtle::lookup::ResponderState::ReceivingHeader;
        result.server_header_state |=
            responder.state() == turtle::lookup::ResponderState::SendingHeader;
        result.server_payload_state |=
            responder.state() == turtle::lookup::ResponderState::SendingPayload;
        require(client_progress != Progress::Failed, client.error());
        require(server_progress != Progress::Failed, responder.error());
        if (client_progress == Progress::Complete && server_progress == Progress::Complete) {
            result.request_bytes = server_endpoint.incoming.size();
            result.response_bytes = client_endpoint.incoming.size();
            return result;
        }
    }
    throw std::runtime_error("lookup exchange did not converge");
}

void test_wire_contract() {
    const turtle::lookup::WireHeader header{
        turtle::lookup::WireKind::Response,
        0x0102030405060708ULL,
        0x11121314U,
        0x2122232425262728ULL,
        0x3132333435363738ULL,
        static_cast<std::uint32_t>(turtle::lookup::maximum_object_size),
        turtle::lookup::WireStatus::Error,
    };
    const turtle::lookup::EncodedHeader expected{
        'T',  'C',  'A',  '1',  0x00, 0x01, 0x00, 0x02, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22,
        0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    static_assert(expected.size() == 44);
    require(turtle::lookup::encode_header(header) == expected,
            "wire header differs from the 44-byte big-endian golden value");
    turtle::lookup::WireHeader decoded;
    std::string_view error;
    require(turtle::lookup::decode_header(expected, decoded, error), error);
    require(decoded.kind == header.kind && decoded.sample == header.sample &&
                decoded.connection == header.connection &&
                decoded.request_id == header.request_id && decoded.object_id == header.object_id &&
                decoded.payload_length == header.payload_length && decoded.status == header.status,
            "golden wire header did not round-trip");

    auto maximum = header;
    maximum.status = turtle::lookup::WireStatus::Ok;
    maximum.payload_length = turtle::lookup::maximum_object_size;
    const auto maximum_wire = turtle::lookup::encode_header(maximum);
    require(maximum_wire[36] == 0x00 && maximum_wire[37] == 0x01 &&
                maximum_wire[38] == 0x00 && maximum_wire[39] == 0x00,
            "maximum payload length is not encoded in network byte order");
}

void test_snapshot_cache_and_events() {
    const auto fixture = bytes(certificate_fixture);
    require(reference_fnv1a(fixture) == fixture_id, "test fixture FNV reference changed");
    turtle::lookup::Snapshot snapshot(fixture);
    require(!snapshot.empty() && snapshot.object().id == fixture_id,
            "snapshot did not retain the fixed opaque object's identity");
    require(std::equal(snapshot.object().bytes.begin(), snapshot.object().bytes.end(),
                       fixture.begin(), fixture.end()),
            "snapshot changed the opaque PEM-like bytes");
    const auto stable_view = snapshot.object();
    require(turtle::lookup::Snapshot{}.empty(), "default snapshot is not empty");
    bool rejected_empty = false;
    try {
        turtle::lookup::Snapshot invalid(std::vector<std::uint8_t>{});
    } catch (const std::invalid_argument&) {
        rejected_empty = true;
    }
    require(rejected_empty, "explicit empty snapshot was silently normalized to cold state");
    bool rejected_oversize = false;
    try {
        turtle::lookup::Snapshot invalid(
            std::vector<std::uint8_t>(turtle::lookup::maximum_object_size + 1, 0x5a));
    } catch (const std::invalid_argument&) {
        rejected_oversize = true;
    }
    require(rejected_oversize, "oversize snapshot was accepted");

    turtle::measure::HeapTracker lookup_heap(true);
    turtle::measure::HeapTracker ca_heap(true);
    turtle::measure::Meter tls_meter(turtle::model::Mode::Memory, false);
    const auto reference_bytes = snapshot.object().bytes.size();
    std::vector<std::uint8_t> framework_reserved;
    framework_reserved.reserve(2048);
    const auto framework_reserved_bytes = framework_reserved.capacity();
    require(lookup_heap.read()->live == 0 && ca_heap.read()->live == 0 &&
                tls_meter.read(false).heap->live == 0,
            "reference and framework reservations entered a tracked heap domain");

    {
        turtle::lookup::Snapshot empty;
        turtle::lookup::Cache cache(lookup_heap.allocator());
        cache.restore(empty);
        EventLog client_events;
        EventLog ca_events;
        turtle::lookup::Client client(cache, snapshot.object(), lookup_heap.allocator(),
                                      client_events.observer());
        turtle::lookup::Responder responder(snapshot.object(), ca_heap.allocator(),
                                            ca_events.observer());
        Endpoint client_endpoint, server_endpoint;
        client_endpoint.peer = &server_endpoint;
        server_endpoint.peer = &client_endpoint;
        client_endpoint.incoming.reserve(turtle::lookup::wire_header_size + fixture.size());
        server_endpoint.incoming.reserve(turtle::lookup::wire_header_size);
        const auto lookup_before = *lookup_heap.read(false);
        const auto ca_before = *ca_heap.read(false);
        require(lookup_before.live == turtle::lookup::maximum_object_size + fixture.size() &&
                    ca_before.live == fixture.size(),
                "allocator-backed payload reservations have the wrong heap ownership");
        require(cache.fixed_reserved_bytes() > 0 && client.fixed_reserved_bytes() > 0 &&
                    responder.fixed_reserved_bytes() > 0,
                "fixed framework reservations were not exposed as metadata");
        const auto result = exchange(client, responder, client_endpoint, server_endpoint);
        require(result.request_bytes == turtle::lookup::wire_header_size,
                "cold lookup request size is not one header");
        require(result.response_bytes == turtle::lookup::wire_header_size + fixture.size(),
                "cold lookup response did not carry the exact object");
        require(result.client_want_read && result.client_want_write && result.server_want_read &&
                    result.server_want_write,
                "partial I/O did not expose all normal retry directions");
        require(result.client_send_state && result.client_header_state &&
                    result.client_payload_state && result.server_receive_state &&
                    result.server_header_state && result.server_payload_state,
                "partial I/O did not preserve the observable re-entry states");
        require(client.object().id == fixture_id && client.object().bytes.size() == fixture.size() &&
                    std::equal(client.object().bytes.begin(), client.object().bytes.end(),
                               fixture.begin()),
                "cold lookup did not consume the original object bytes");
        require(cache.logical_bytes() == fixture.size() && cache.capacity() >= fixture.size(),
                "cache logical bytes and allocated capacity are not distinguished");
        require(client_events.count(turtle::lookup::SemanticEventKind::CacheLookup) == 1 &&
                    client_events.count(turtle::lookup::SemanticEventKind::CacheMiss) == 1 &&
                    client_events.count(turtle::lookup::SemanticEventKind::CacheHit) == 0 &&
                    client_events.count(turtle::lookup::SemanticEventKind::CacheInsert) == 1 &&
                    client_events.count(turtle::lookup::SemanticEventKind::RequestBegin) == 1 &&
                    client_events.count(turtle::lookup::SemanticEventKind::ResponseComplete) == 1 &&
                    client_events.count(turtle::lookup::SemanticEventKind::UsableObject) == 1,
                "cold cache event contract is incomplete");
        client_events.require_identity(19, 3, fixture_id);
        ca_events.require_identity(19, 3, fixture_id);
        const auto process_begin = ca_events.first(turtle::lookup::SemanticEventKind::CaProcessBegin);
        const auto process_end = ca_events.first(turtle::lookup::SemanticEventKind::CaProcessEnd);
        require(process_begin < process_end, "CA processing boundary is reversed");
        require(process_end == process_begin + 1,
                "CA semantic processing interval contains unrelated events");

        const auto lookup_accounting = *lookup_heap.read(false);
        const auto ca_accounting = *ca_heap.read(false);
        const auto tls_accounting = *tls_meter.read(false).heap;
        require(lookup_accounting.live > 0 && ca_accounting.live > 0 &&
                    tls_accounting.live == 0,
                "lookup, CA, and TLS heaps were mixed");
        require(lookup_accounting.allocations == lookup_before.allocations &&
                    lookup_accounting.allocated_total == lookup_before.allocated_total &&
                    ca_accounting.allocations == ca_before.allocations &&
                    ca_accounting.allocated_total == ca_before.allocated_total,
                "advance/cache insert allocated after construction");
        require(reference_bytes == fixture.size() && framework_reserved_bytes >= 2048,
                "reference and framework-reserved metadata assumptions changed");
    }
    require(lookup_heap.read(false)->live == 0 && ca_heap.read(false)->live == 0,
            "lookup or CA tracked allocation outlived its owner");
    require(snapshot.object().bytes.data() == stable_view.bytes.data() &&
                snapshot.object().bytes.size() == stable_view.bytes.size(),
            "immutable snapshot view changed during connection-local work");

    turtle::lookup::Cache warm_cache(lookup_heap.allocator());
    warm_cache.restore(snapshot);
    EventLog warm_events;
    turtle::lookup::Client warm(warm_cache, snapshot.object(), lookup_heap.allocator(),
                                warm_events.observer());
    Endpoint unused_a, unused_b;
    unused_a.peer = &unused_b;
    unused_b.peer = &unused_a;
    auto unused_io = unused_a.io();
    warm.begin(20, 0);
    require(warm.advance(unused_io) == Progress::Complete && warm.cache_hit(),
            "fixed snapshot did not produce a usable warm hit");
    require(unused_a.send_calls == 0 && unused_a.recv_calls == 0,
            "warm hit performed remote I/O");
    require(warm_events.count(turtle::lookup::SemanticEventKind::CacheLookup) == 1 &&
                warm_events.count(turtle::lookup::SemanticEventKind::CacheHit) == 1 &&
                warm_events.count(turtle::lookup::SemanticEventKind::CacheMiss) == 0 &&
                warm_events.count(turtle::lookup::SemanticEventKind::UsableObject) == 1 &&
                warm_events.count(turtle::lookup::SemanticEventKind::RequestBegin) == 0,
            "warm cache event contract is incorrect");
    warm_events.require_identity(20, 0, fixture_id);

    auto different = fixture;
    different[20] ^= 1;
    require(different.size() == fixture.size(), "same-size fixture setup failed");
    turtle::lookup::Snapshot different_snapshot(different);
    require(different_snapshot.object().id != snapshot.object().id,
            "same-size distinct state was not distinguished by ID");
    warm_cache.restore(different_snapshot);
    require(warm_cache.find(snapshot.object().id).bytes.empty(),
            "same-size cache state was treated as the expected object");

    // A pending operation is explicitly abandoned before restoring the next
    // connection's immutable initial state. Cache has no hidden global state.
    EventLog abandoned_events;
    turtle::lookup::Client abandoned(warm_cache, snapshot.object(), lookup_heap.allocator(),
                                     abandoned_events.observer());
    abandoned.begin(21, 0);
    abandoned.abandon();
    warm_cache.restore(snapshot);
    EventLog restored_events;
    turtle::lookup::Client restored(warm_cache, snapshot.object(), lookup_heap.allocator(),
                                    restored_events.observer());
    restored.begin(21, 1);
    require(restored.advance(unused_io) == Progress::Complete && restored.cache_hit(),
            "abandon followed by next-connection restore did not recover initial state");
}

void test_maximum_payload_partial_io() {
    std::vector<std::uint8_t> payload(turtle::lookup::maximum_object_size);
    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] = static_cast<std::uint8_t>((index * 131U + 17U) & 0xffU);
    turtle::lookup::Snapshot expected(payload);
    turtle::lookup::Snapshot empty;
    turtle::measure::HeapTracker client_heap(true), server_heap(true);
    turtle::lookup::Cache cache(client_heap.allocator());
    cache.restore(empty);
    turtle::lookup::Client client(cache, expected.object(), client_heap.allocator());
    turtle::lookup::Responder server(expected.object(), server_heap.allocator());
    Endpoint client_endpoint, server_endpoint;
    client_endpoint.peer = &server_endpoint;
    server_endpoint.peer = &client_endpoint;
    client_endpoint.chunk = 4093;
    server_endpoint.chunk = 4093;
    client_endpoint.incoming.reserve(turtle::lookup::wire_header_size + payload.size());
    server_endpoint.incoming.reserve(turtle::lookup::wire_header_size);
    const auto result = exchange(client, server, client_endpoint, server_endpoint);
    require(result.response_bytes == turtle::lookup::wire_header_size + payload.size() &&
                client.object().bytes.size() == turtle::lookup::maximum_object_size &&
                std::equal(client.object().bytes.begin(), client.object().bytes.end(),
                           payload.begin()),
            "maximum normal payload failed partial transfer");
}
} // namespace

int main() {
    try {
        test_wire_contract();
        test_snapshot_cache_and_events();
        test_maximum_payload_partial_io();
        std::cout << "lookup contract tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
