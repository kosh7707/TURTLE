#include "lookup/lookup.hpp"

#include <algorithm>
#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>

namespace turtle::lookup {
namespace {

template <typename Integer>
void put_big_endian(EncodedHeader& bytes, std::size_t offset, Integer value) noexcept {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
        const auto shift = 8U * (sizeof(Integer) - index - 1U);
        bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
    }
}

template <typename Integer>
Integer get_big_endian(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
    Integer value = 0;
    for (std::size_t index = 0; index < sizeof(Integer); ++index)
        value = static_cast<Integer>((value << 8U) | bytes[offset + index]);
    return value;
}

bool usable_object(const ObjectView& object) noexcept {
    return object.bytes.size() >= 1 && object.bytes.size() <= maximum_object_size &&
           object.id == model::fnv1a64(object.bytes);
}

bool allocator_usable(const Allocator& allocator) noexcept {
    return allocator.allocate != nullptr && allocator.reallocate != nullptr &&
           allocator.deallocate != nullptr;
}

void observe(const Observer& observer, SemanticEventKind kind, std::uint64_t sample,
             std::uint32_t connection, std::uint64_t request_id, std::uint64_t id,
             std::size_t requested, std::size_t transferred) noexcept {
    if (observer.observe == nullptr)
        return;
    observer.observe(observer.context,
                     {kind, sample, connection, request_id, id, requested, transferred,
                      IoStatus::Ok, 0});
}

Progress io_progress(IoStatus status) noexcept {
    return status == IoStatus::WantRead ? Progress::WantRead : Progress::WantWrite;
}

} // namespace

EncodedHeader encode_header(const WireHeader& header) {
    EncodedHeader bytes{};
    std::copy(wire_magic.begin(), wire_magic.end(), bytes.begin() + magic_offset);
    put_big_endian(bytes, version_offset, wire_version);
    put_big_endian(bytes, kind_offset, static_cast<std::uint16_t>(header.kind));
    put_big_endian(bytes, sample_offset, header.sample);
    put_big_endian(bytes, connection_offset, header.connection);
    put_big_endian(bytes, request_id_offset, header.request_id);
    put_big_endian(bytes, object_id_offset, header.object_id);
    put_big_endian(bytes, payload_length_offset, header.payload_length);
    put_big_endian(bytes, status_offset, static_cast<std::uint32_t>(header.status));
    return bytes;
}

bool decode_header(std::span<const std::uint8_t> bytes, WireHeader& header,
                   std::string_view& error) noexcept {
    error = {};
    if (bytes.size() != wire_header_size) {
        error = "lookup header size is not 44 bytes";
        return false;
    }
    if (!std::equal(wire_magic.begin(), wire_magic.end(), bytes.begin())) {
        error = "lookup header magic is invalid";
        return false;
    }
    if (get_big_endian<std::uint16_t>(bytes, version_offset) != wire_version) {
        error = "lookup header version is unsupported";
        return false;
    }

    const auto kind = get_big_endian<std::uint16_t>(bytes, kind_offset);
    const auto status = get_big_endian<std::uint32_t>(bytes, status_offset);
    if (kind != static_cast<std::uint16_t>(WireKind::Request) &&
        kind != static_cast<std::uint16_t>(WireKind::Response)) {
        error = "lookup header kind is invalid";
        return false;
    }
    if (status != static_cast<std::uint32_t>(WireStatus::Ok) &&
        status != static_cast<std::uint32_t>(WireStatus::Error)) {
        error = "lookup header status is invalid";
        return false;
    }

    WireHeader decoded;
    decoded.kind = static_cast<WireKind>(kind);
    decoded.sample = get_big_endian<std::uint64_t>(bytes, sample_offset);
    decoded.connection = get_big_endian<std::uint32_t>(bytes, connection_offset);
    decoded.request_id = get_big_endian<std::uint64_t>(bytes, request_id_offset);
    decoded.object_id = get_big_endian<std::uint64_t>(bytes, object_id_offset);
    decoded.payload_length =
        get_big_endian<std::uint32_t>(bytes, payload_length_offset);
    decoded.status = static_cast<WireStatus>(status);
    if (decoded.payload_length > maximum_object_size) {
        error = "lookup payload exceeds the maximum object size";
        return false;
    }
    header = decoded;
    return true;
}

Snapshot::Snapshot() = default;

Snapshot::Snapshot(std::vector<std::uint8_t> object) : object_(std::move(object)) {
    if (object_.empty() || object_.size() > maximum_object_size)
        throw std::invalid_argument("lookup snapshot object size must be 1..65536 bytes");
    object_id_ = model::fnv1a64(object_);
}

ObjectView Snapshot::object() const noexcept {
    return {object_id_, object_};
}

bool Snapshot::empty() const noexcept {
    return object_.empty();
}

std::size_t Snapshot::capacity() const noexcept {
    return object_.capacity();
}

const char* name(WireKind value) noexcept {
    switch (value) {
    case WireKind::Request:
        return "request";
    case WireKind::Response:
        return "response";
    }
    return "unknown";
}

const char* name(WireStatus value) noexcept {
    switch (value) {
    case WireStatus::Ok:
        return "ok";
    case WireStatus::Error:
        return "error";
    }
    return "unknown";
}

const char* name(SemanticEventKind value) noexcept {
    switch (value) {
    case SemanticEventKind::CacheLookup:
        return "CACHE_LOOKUP";
    case SemanticEventKind::CacheHit:
        return "CACHE_HIT";
    case SemanticEventKind::CacheMiss:
        return "CACHE_MISS";
    case SemanticEventKind::CacheInsert:
        return "CACHE_INSERT";
    case SemanticEventKind::RequestBegin:
        return "REQUEST_BEGIN";
    case SemanticEventKind::ResponseComplete:
        return "RESPONSE_COMPLETE";
    case SemanticEventKind::UsableObject:
        return "USABLE_OBJECT";
    case SemanticEventKind::CaProcessBegin:
        return "CA_PROCESS_BEGIN";
    case SemanticEventKind::CaProcessEnd:
        return "CA_PROCESS_END";
    }
    return "unknown";
}

const char* name(Progress value) noexcept {
    switch (value) {
    case Progress::WantRead:
        return "want_read";
    case Progress::WantWrite:
        return "want_write";
    case Progress::Complete:
        return "complete";
    case Progress::Failed:
        return "failed";
    }
    return "unknown";
}

const char* name(ClientState value) noexcept {
    switch (value) {
    case ClientState::Idle:
        return "idle";
    case ClientState::CacheLookup:
        return "cache_lookup";
    case ClientState::SendingRequest:
        return "sending_request";
    case ClientState::ReceivingHeader:
        return "receiving_header";
    case ClientState::ReceivingPayload:
        return "receiving_payload";
    case ClientState::Validating:
        return "validating";
    case ClientState::Complete:
        return "complete";
    case ClientState::Failed:
        return "failed";
    }
    return "unknown";
}

const char* name(ResponderState value) noexcept {
    switch (value) {
    case ResponderState::Idle:
        return "idle";
    case ResponderState::ReceivingHeader:
        return "receiving_header";
    case ResponderState::Processing:
        return "processing";
    case ResponderState::SendingHeader:
        return "sending_header";
    case ResponderState::SendingPayload:
        return "sending_payload";
    case ResponderState::Complete:
        return "complete";
    case ResponderState::Failed:
        return "failed";
    }
    return "unknown";
}

struct Cache::State {
    explicit State(const Allocator& source) : allocator(source) {
        if (!allocator_usable(allocator))
            throw std::invalid_argument("lookup cache allocator is invalid");
        bytes = static_cast<std::uint8_t*>(
            allocator.allocate(allocator.context, maximum_object_size));
        if (bytes == nullptr)
            throw std::bad_alloc();
    }
    ~State() {
        if (bytes != nullptr && allocator.deallocate != nullptr)
            allocator.deallocate(allocator.context, bytes);
    }

    Allocator allocator;
    std::uint8_t* bytes = nullptr;
    std::size_t size = 0;
    std::size_t allocated = maximum_object_size;
    std::uint64_t id = 0;

    void clear() noexcept {
        size = 0;
        id = 0;
    }

    bool replace(const ObjectView& object) noexcept {
        if (!usable_object(object) || object.bytes.size() > allocated)
            return false;
        std::memmove(bytes, object.bytes.data(), object.bytes.size());
        size = object.bytes.size();
        id = object.id;
        return true;
    }
};

Cache::Cache(const Allocator& allocator) : state_(std::make_unique<State>(allocator)) {}
Cache::~Cache() = default;

void Cache::restore(const Snapshot& snapshot) {
    const auto object = snapshot.object();
    if (object.bytes.empty()) {
        state_->clear();
        return;
    }
    if (!state_->replace(object))
        throw std::invalid_argument("lookup snapshot object is invalid");
}

ObjectView Cache::find(std::uint64_t id) const noexcept {
    if (state_->bytes == nullptr || state_->id != id)
        return {};
    return {state_->id, {state_->bytes, state_->size}};
}

bool Cache::insert(const ObjectView& object) noexcept {
    return state_->replace(object);
}

std::size_t Cache::logical_bytes() const noexcept {
    return state_->size;
}

std::size_t Cache::capacity() const noexcept {
    return state_->allocated;
}

std::size_t Cache::fixed_reserved_bytes() const noexcept {
    return sizeof(State);
}

struct Client::State {
    State(Cache& destination, ObjectView reference, const Allocator& source, Observer sink)
        : cache(destination), expected(reference), allocator(source), observer(sink) {
        if (!allocator_usable(allocator))
            throw std::invalid_argument("lookup client allocator is invalid");
        if (!usable_object(expected))
            throw std::invalid_argument("lookup expected object is invalid");
        payload = static_cast<std::uint8_t*>(
            allocator.allocate(allocator.context, expected.bytes.size()));
        if (payload == nullptr)
            throw std::bad_alloc();
        payload_capacity = expected.bytes.size();
    }

    ~State() {
        if (payload != nullptr && allocator.deallocate != nullptr)
            allocator.deallocate(allocator.context, payload);
    }

    Cache& cache;
    ObjectView expected;
    Allocator allocator;
    Observer observer;
    ClientState phase = ClientState::Idle;
    bool hit = false;
    ObjectView result;
    std::string_view failure;
    std::uint64_t sample = 0;
    std::uint32_t connection = 0;
    EncodedHeader request{};
    EncodedHeader response{};
    std::size_t request_offset = 0;
    std::size_t response_offset = 0;
    std::uint8_t* payload = nullptr;
    std::size_t payload_capacity = 0;
    std::size_t payload_size = 0;
    WireHeader response_header;

    Progress fail(std::string_view message) noexcept {
        failure = message;
        result = {};
        phase = ClientState::Failed;
        return Progress::Failed;
    }

    void emit(SemanticEventKind kind, std::size_t requested = 0,
              std::size_t transferred = 0) const noexcept {
        observe(observer, kind, sample, connection, single_request_id, expected.id, requested,
                transferred);
    }
};

Client::Client(Cache& cache, ObjectView expected, const Allocator& allocator, Observer observer)
    : state_(std::make_unique<State>(cache, expected, allocator, observer)) {}
Client::~Client() = default;

void Client::begin(std::uint64_t sample, std::uint32_t connection) {
    auto& self = *state_;
    if (self.phase != ClientState::Idle && self.phase != ClientState::Complete &&
        self.phase != ClientState::Failed) {
        self.fail("lookup client operation is already active");
        return;
    }
    self.sample = sample;
    self.connection = connection;
    self.phase = ClientState::CacheLookup;
    self.hit = false;
    self.result = {};
    self.failure = {};
    self.request_offset = 0;
    self.response_offset = 0;
    self.payload_size = 0;
    if (sample == 0) {
        self.fail("lookup sample id must be one-based");
        return;
    }
    self.emit(SemanticEventKind::CacheLookup, self.expected.bytes.size());
    const auto cached = self.cache.find(self.expected.id);
    if (!cached.bytes.empty()) {
        if (cached.bytes.size() != self.expected.bytes.size() ||
            !std::equal(cached.bytes.begin(), cached.bytes.end(), self.expected.bytes.begin())) {
            self.fail("lookup cache object does not match the expected bytes");
            return;
        }
        self.hit = true;
        self.result = cached;
        self.emit(SemanticEventKind::CacheHit, self.expected.bytes.size(), cached.bytes.size());
        self.emit(SemanticEventKind::UsableObject, self.expected.bytes.size(),
                  cached.bytes.size());
        self.phase = ClientState::Complete;
        return;
    }

    self.emit(SemanticEventKind::CacheMiss, self.expected.bytes.size());
    self.request = encode_header({WireKind::Request, sample, connection, single_request_id,
                                  self.expected.id, 0, WireStatus::Ok});
    self.emit(SemanticEventKind::RequestBegin, wire_header_size);
    self.phase = ClientState::SendingRequest;
}

Progress Client::advance(Io& io) noexcept {
    auto& self = *state_;
    if (self.phase == ClientState::Complete)
        return Progress::Complete;
    if (self.phase == ClientState::Failed)
        return Progress::Failed;
    if (self.phase == ClientState::Idle || self.phase == ClientState::CacheLookup ||
        self.phase == ClientState::Validating)
        return self.fail("lookup client is not ready for I/O");

    if (self.phase == ClientState::SendingRequest) {
        if (io.send == nullptr)
            return self.fail("lookup send callback is missing");
        const auto remaining = wire_header_size - self.request_offset;
        const auto result =
            io.send(io.context, self.request.data() + self.request_offset, remaining);
        if (result.status == IoStatus::WantRead || result.status == IoStatus::WantWrite) {
            if (result.bytes != 0)
                return self.fail("lookup send retry reported transferred bytes");
            return io_progress(result.status);
        }
        if (result.status != IoStatus::Ok)
            return self.fail(result.status == IoStatus::Closed
                                 ? "lookup connection closed while sending"
                                 : "lookup request send failed");
        if (result.bytes == 0 || result.bytes > remaining)
            return self.fail("lookup request send made invalid progress");
        self.request_offset += result.bytes;
        if (self.request_offset != wire_header_size)
            return Progress::WantWrite;
        self.phase = ClientState::ReceivingHeader;
        return Progress::WantRead;
    }

    if (self.phase == ClientState::ReceivingHeader) {
        if (io.recv == nullptr)
            return self.fail("lookup receive callback is missing");
        const auto remaining = wire_header_size - self.response_offset;
        const auto result =
            io.recv(io.context, self.response.data() + self.response_offset, remaining);
        if (result.status == IoStatus::WantRead || result.status == IoStatus::WantWrite) {
            if (result.bytes != 0)
                return self.fail("lookup receive retry reported transferred bytes");
            return io_progress(result.status);
        }
        if (result.status != IoStatus::Ok)
            return self.fail(result.status == IoStatus::Closed
                                 ? "lookup connection closed while receiving header"
                                 : "lookup response receive failed");
        if (result.bytes == 0 || result.bytes > remaining)
            return self.fail("lookup response header receive made invalid progress");
        self.response_offset += result.bytes;
        if (self.response_offset != wire_header_size)
            return Progress::WantRead;

        std::string_view decode_error;
        if (!decode_header(self.response, self.response_header, decode_error))
            return self.fail(decode_error);
        const auto& header = self.response_header;
        if (header.kind != WireKind::Response || header.sample != self.sample ||
            header.connection != self.connection || header.request_id != single_request_id ||
            header.object_id != self.expected.id)
            return self.fail("lookup response identity does not match the request");
        if (header.status == WireStatus::Error) {
            if (header.payload_length != 0)
                return self.fail("lookup error response has a payload");
            return self.fail("lookup responder does not have the requested object");
        }
        if (header.payload_length != self.expected.bytes.size() || header.payload_length == 0 ||
            header.payload_length > self.payload_capacity)
            return self.fail("lookup response length does not match the expected object");
        self.phase = ClientState::ReceivingPayload;
        return Progress::WantRead;
    }

    if (io.recv == nullptr)
        return self.fail("lookup receive callback is missing");
    const auto remaining = self.response_header.payload_length - self.payload_size;
    const auto result = io.recv(io.context, self.payload + self.payload_size, remaining);
    if (result.status == IoStatus::WantRead || result.status == IoStatus::WantWrite) {
        if (result.bytes != 0)
            return self.fail("lookup receive retry reported transferred bytes");
        return io_progress(result.status);
    }
    if (result.status != IoStatus::Ok)
        return self.fail(result.status == IoStatus::Closed
                             ? "lookup connection closed while receiving payload"
                             : "lookup response receive failed");
    if (result.bytes == 0 || result.bytes > remaining)
        return self.fail("lookup response payload receive made invalid progress");
    self.payload_size += result.bytes;
    if (self.payload_size != self.response_header.payload_length)
        return Progress::WantRead;

    self.emit(SemanticEventKind::ResponseComplete, self.expected.bytes.size(),
              self.payload_size);
    self.phase = ClientState::Validating;
    if (!std::equal(self.expected.bytes.begin(), self.expected.bytes.end(), self.payload))
        return self.fail("lookup response bytes do not match the expected object");
    if (!self.cache.insert({self.expected.id, {self.payload, self.payload_size}}))
        return self.fail("lookup cache insert failed");
    self.emit(SemanticEventKind::CacheInsert, self.payload_size, self.payload_size);
    self.result = self.cache.find(self.expected.id);
    if (self.result.bytes.empty())
        return self.fail("lookup cache insert produced no usable object");
    self.emit(SemanticEventKind::UsableObject, self.expected.bytes.size(),
              self.result.bytes.size());
    self.phase = ClientState::Complete;
    return Progress::Complete;
}

void Client::abandon() noexcept {
    auto& self = *state_;
    self.phase = ClientState::Idle;
    self.hit = false;
    self.result = {};
    self.failure = {};
    self.request_offset = 0;
    self.response_offset = 0;
    self.payload_size = 0;
}

ClientState Client::state() const noexcept {
    return state_->phase;
}

bool Client::cache_hit() const noexcept {
    return state_->phase == ClientState::Complete && state_->hit;
}

ObjectView Client::object() const noexcept {
    return state_->phase == ClientState::Complete ? state_->result : ObjectView{};
}

std::string_view Client::error() const noexcept {
    return state_->failure;
}

std::size_t Client::fixed_reserved_bytes() const noexcept {
    return sizeof(State);
}

struct Responder::State {
    State(ObjectView object, const Allocator& source, Observer sink)
        : repository(object), allocator(source), observer(sink) {
        if (!allocator_usable(allocator))
            throw std::invalid_argument("lookup responder allocator is invalid");
        if (!usable_object(repository))
            throw std::invalid_argument("lookup repository object is invalid");
        payload = static_cast<std::uint8_t*>(
            allocator.allocate(allocator.context, repository.bytes.size()));
        if (payload == nullptr)
            throw std::bad_alloc();
        std::memcpy(payload, repository.bytes.data(), repository.bytes.size());
        payload_size = repository.bytes.size();
    }

    ~State() {
        if (payload != nullptr)
            allocator.deallocate(allocator.context, payload);
    }

    ObjectView repository;
    Allocator allocator;
    Observer observer;
    ResponderState phase = ResponderState::Idle;
    std::string_view failure;
    std::uint64_t sample = 0;
    std::uint32_t connection = 0;
    EncodedHeader request{};
    EncodedHeader response{};
    std::size_t request_offset = 0;
    std::size_t response_offset = 0;
    std::size_t payload_offset = 0;
    WireHeader request_header;
    std::uint64_t parsed_request_id = 0;
    bool send_payload = false;
    std::uint8_t* payload = nullptr;
    std::size_t payload_size = 0;

    Progress fail(std::string_view message) noexcept {
        failure = message;
        phase = ResponderState::Failed;
        return Progress::Failed;
    }

    void emit(SemanticEventKind kind, std::size_t requested = 0,
              std::size_t transferred = 0) const noexcept {
        observe(observer, kind, sample, connection,
                parsed_request_id == 0 ? single_request_id : parsed_request_id,
                parsed_request_id == 0 ? repository.id : request_header.object_id, requested,
                transferred);
    }
};

Responder::Responder(ObjectView repository_object, const Allocator& allocator, Observer observer)
    : state_(std::make_unique<State>(repository_object, allocator, observer)) {}
Responder::~Responder() = default;

void Responder::begin(std::uint64_t sample, std::uint32_t connection) {
    auto& self = *state_;
    if (self.phase != ResponderState::Idle && self.phase != ResponderState::Complete &&
        self.phase != ResponderState::Failed) {
        self.fail("lookup responder operation is already active");
        return;
    }
    self.sample = sample;
    self.connection = connection;
    self.phase = ResponderState::ReceivingHeader;
    self.failure = {};
    self.request_offset = 0;
    self.response_offset = 0;
    self.payload_offset = 0;
    self.parsed_request_id = 0;
    self.send_payload = false;
    if (sample == 0) {
        self.fail("lookup sample id must be one-based");
        return;
    }
}

Progress Responder::advance(Io& io) noexcept {
    auto& self = *state_;
    if (self.phase == ResponderState::Complete)
        return Progress::Complete;
    if (self.phase == ResponderState::Failed)
        return Progress::Failed;
    if (self.phase == ResponderState::Idle || self.phase == ResponderState::Processing)
        return self.fail("lookup responder is not ready for I/O");

    if (self.phase == ResponderState::ReceivingHeader) {
        if (io.recv == nullptr)
            return self.fail("lookup receive callback is missing");
        const auto remaining = wire_header_size - self.request_offset;
        const auto result =
            io.recv(io.context, self.request.data() + self.request_offset, remaining);
        if (result.status == IoStatus::WantRead || result.status == IoStatus::WantWrite) {
            if (result.bytes != 0)
                return self.fail("lookup receive retry reported transferred bytes");
            return io_progress(result.status);
        }
        if (result.status != IoStatus::Ok)
            return self.fail(result.status == IoStatus::Closed
                                 ? "lookup connection closed while receiving request"
                                 : "lookup request receive failed");
        if (result.bytes == 0 || result.bytes > remaining)
            return self.fail("lookup request receive made invalid progress");
        self.request_offset += result.bytes;
        if (self.request_offset != wire_header_size)
            return Progress::WantRead;

        self.phase = ResponderState::Processing;
        self.emit(SemanticEventKind::CaProcessBegin, wire_header_size, wire_header_size);
        std::string_view decode_error;
        if (!decode_header(self.request, self.request_header, decode_error))
            return self.fail(decode_error);
        const auto& request = self.request_header;
        self.parsed_request_id = request.request_id;
        if (request.kind != WireKind::Request || request.sample != self.sample ||
            request.connection != self.connection || request.request_id != single_request_id ||
            request.payload_length != 0 || request.status != WireStatus::Ok)
            return self.fail("lookup request does not match the active operation");

        self.send_payload = request.object_id == self.repository.id;
        const auto status = self.send_payload ? WireStatus::Ok : WireStatus::Error;
        const auto length = self.send_payload
                                ? static_cast<std::uint32_t>(self.repository.bytes.size())
                                : 0U;
        self.response = encode_header({WireKind::Response, self.sample, self.connection,
                                       request.request_id, request.object_id, length, status});
        self.emit(SemanticEventKind::CaProcessEnd, self.repository.bytes.size(), length);
        self.phase = ResponderState::SendingHeader;
        return Progress::WantWrite;
    }

    if (self.phase == ResponderState::SendingHeader) {
        if (io.send == nullptr)
            return self.fail("lookup send callback is missing");
        const auto remaining = wire_header_size - self.response_offset;
        const auto result =
            io.send(io.context, self.response.data() + self.response_offset, remaining);
        if (result.status == IoStatus::WantRead || result.status == IoStatus::WantWrite) {
            if (result.bytes != 0)
                return self.fail("lookup send retry reported transferred bytes");
            return io_progress(result.status);
        }
        if (result.status != IoStatus::Ok)
            return self.fail(result.status == IoStatus::Closed
                                 ? "lookup connection closed while sending response header"
                                 : "lookup response header send failed");
        if (result.bytes == 0 || result.bytes > remaining)
            return self.fail("lookup response header send made invalid progress");
        self.response_offset += result.bytes;
        if (self.response_offset != wire_header_size)
            return Progress::WantWrite;
        if (!self.send_payload) {
            self.phase = ResponderState::Complete;
            return Progress::Complete;
        }
        self.phase = ResponderState::SendingPayload;
        return Progress::WantWrite;
    }

    if (io.send == nullptr)
        return self.fail("lookup send callback is missing");
    const auto remaining = self.payload_size - self.payload_offset;
    const auto result = io.send(io.context, self.payload + self.payload_offset, remaining);
    if (result.status == IoStatus::WantRead || result.status == IoStatus::WantWrite) {
        if (result.bytes != 0)
            return self.fail("lookup send retry reported transferred bytes");
        return io_progress(result.status);
    }
    if (result.status != IoStatus::Ok)
        return self.fail(result.status == IoStatus::Closed
                             ? "lookup connection closed while sending response payload"
                             : "lookup response payload send failed");
    if (result.bytes == 0 || result.bytes > remaining)
        return self.fail("lookup response payload send made invalid progress");
    self.payload_offset += result.bytes;
    if (self.payload_offset != self.payload_size)
        return Progress::WantWrite;
    self.phase = ResponderState::Complete;
    return Progress::Complete;
}

void Responder::abandon() noexcept {
    auto& self = *state_;
    self.phase = ResponderState::Idle;
    self.failure = {};
    self.request_offset = 0;
    self.response_offset = 0;
    self.payload_offset = 0;
    self.parsed_request_id = 0;
    self.send_payload = false;
}

ResponderState Responder::state() const noexcept {
    return state_->phase;
}

std::uint64_t Responder::request_id() const noexcept {
    return state_->parsed_request_id;
}

std::string_view Responder::error() const noexcept {
    return state_->failure;
}

std::size_t Responder::fixed_reserved_bytes() const noexcept {
    return sizeof(State);
}

} // namespace turtle::lookup
