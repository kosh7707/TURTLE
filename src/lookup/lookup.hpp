#pragma once

// Certificate-object lookup only. This module owns no clock, perf group,
// file, JSON, control channel, or socket. Callers provide a borrowed Io,
// Allocator, and optional borrowed observer; all must outlive the operation.
#include "model/model.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace turtle::lookup {

inline constexpr std::array<std::uint8_t, 4> wire_magic{'T', 'C', 'A', '1'};
inline constexpr std::uint16_t wire_version = 1;
inline constexpr std::size_t wire_header_size = 44;
inline constexpr std::size_t magic_offset = 0;
inline constexpr std::size_t version_offset = 4;
inline constexpr std::size_t kind_offset = 6;
inline constexpr std::size_t sample_offset = 8;
inline constexpr std::size_t connection_offset = 16;
inline constexpr std::size_t request_id_offset = 20;
inline constexpr std::size_t object_id_offset = 28;
inline constexpr std::size_t payload_length_offset = 36;
inline constexpr std::size_t status_offset = 40;
inline constexpr std::size_t maximum_object_size = 65536;
inline constexpr std::uint64_t single_request_id = 1;
inline constexpr const char* snapshot_type = "turtle-lookup-cache";
inline constexpr unsigned snapshot_schema = 1;

enum class WireKind : std::uint16_t { Request = 1, Response = 2 };
enum class WireStatus : std::uint32_t { Ok = 0, Error = 1 };

// This is the decoded value model, not an on-wire C structure. Encoding and
// decoding visit fields explicitly in network byte order; never memcpy it.
struct WireHeader {
    WireKind kind = WireKind::Request;
    std::uint64_t sample = 0;       // attempt/sample id, 1-based
    std::uint32_t connection = 0;   // warmups included, 0-based
    std::uint64_t request_id = single_request_id;
    std::uint64_t object_id = 0;    // FNV-1a value; not a security hash
    std::uint32_t payload_length = 0;
    WireStatus status = WireStatus::Ok;
};

using EncodedHeader = std::array<std::uint8_t, wire_header_size>;
EncodedHeader encode_header(const WireHeader& header);
bool decode_header(std::span<const std::uint8_t> bytes, WireHeader& header,
                   std::string_view& error) noexcept;

struct ObjectView {
    std::uint64_t id = 0;
    std::span<const std::uint8_t> bytes;
};

// Immutable parent-owned input. A view obtained from object() remains valid
// until this Snapshot is destroyed. It is reference input, not measured cache
// storage, and its bytes/capacity must be reported separately.
class Snapshot {
  public:
    // The default is the only empty snapshot. The explicit constructor throws
    // invalid_argument for 0 or > maximum_object_size bytes; invalid input is
    // a preparation failure and is never normalized to an empty cache.
    Snapshot();
    explicit Snapshot(std::vector<std::uint8_t> object);
    ObjectView object() const noexcept;
    bool empty() const noexcept;
    std::size_t capacity() const noexcept;

  private:
    std::vector<std::uint8_t> object_;
    std::uint64_t object_id_ = 0;
};

enum class SemanticEventKind {
    CacheLookup,
    CacheHit,
    CacheMiss,
    CacheInsert,
    RequestBegin,
    ResponseComplete,
    UsableObject,
    CaProcessBegin,
    CaProcessEnd
};

struct Observation {
    SemanticEventKind kind = SemanticEventKind::CacheLookup;
    std::uint64_t sample = 0;
    std::uint32_t connection = 0;
    std::uint64_t request_id = single_request_id;
    std::uint64_t object_id = 0;
    std::size_t requested = 0;
    std::size_t transferred = 0;
    IoStatus io_status = IoStatus::Ok;
    int system_error = 0;
};

// This observer receives only semantic cache/request/response/CA-processing
// events. I/O call boundaries and successful wire-byte capture belong to the
// transport::Channel observer, avoiding duplicate observations here.
struct Observer {
    void* context = nullptr; // borrowed; no ownership transfer
    void (*observe)(void*, const Observation&) noexcept = nullptr;
};

enum class Progress { WantRead, WantWrite, Complete, Failed };
enum class ClientState {
    Idle,
    CacheLookup,
    SendingRequest,
    ReceivingHeader,
    ReceivingPayload,
    Validating,
    Complete,
    Failed
};
enum class ResponderState {
    Idle,
    ReceivingHeader,
    Processing,
    SendingHeader,
    SendingPayload,
    Complete,
    Failed
};

const char* name(WireKind value) noexcept;
const char* name(WireStatus value) noexcept;
const char* name(SemanticEventKind value) noexcept;
const char* name(Progress value) noexcept;
const char* name(ClientState value) noexcept;
const char* name(ResponderState value) noexcept;

// Connection-local measured cache. Construction validates all Allocator
// callbacks and reserves maximum_object_size bytes through it; a missing
// allocator throws invalid_argument and allocation failure throws bad_alloc.
// restore()/insert() only copy or clear within that capacity and allocate
// nothing. They are permitted only while the client is idle and after prior
// I/O completed or was explicitly abandoned. Thus Client::advance() can insert
// without allocation. Returned views remain valid until restore(), insert(),
// or destruction, whichever comes first.
class Cache {
  public:
    explicit Cache(const Allocator& allocator);
    ~Cache();
    Cache(const Cache&) = delete;
    Cache& operator=(const Cache&) = delete;
    void restore(const Snapshot& snapshot);
    ObjectView find(std::uint64_t object_id) const noexcept;
    bool insert(const ObjectView& object) noexcept;
    std::size_t logical_bytes() const noexcept;
    std::size_t capacity() const noexcept;
    // Non-Allocator-owned PImpl/fixed storage only. Do not include allocator
    // payload capacity here or add logical/capacity metadata to heap totals.
    std::size_t fixed_reserved_bytes() const noexcept;

  private:
    struct State;
    std::unique_ptr<State> state_;
};

// One lookup per connection. begin() first consumes Cache; a hit completes
// without wire I/O. A miss sends exactly one request and validates response ID,
// length, and byte-for-byte equality with expected before inserting. The
// response staging allocation is reserved through allocator to expected.size()
// at construction; a missing allocator throws invalid_argument and allocation
// failure throws bad_alloc. object() is usable only after Complete and has
// Cache's view lifetime.
class Client {
  public:
    Client(Cache& cache, ObjectView expected, const Allocator& allocator,
           Observer observer = {});
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    void begin(std::uint64_t sample, std::uint32_t connection);
    Progress advance(Io& io) noexcept;
    void abandon() noexcept;
    ClientState state() const noexcept;
    bool cache_hit() const noexcept;
    ObjectView object() const noexcept;
    std::string_view error() const noexcept;
    // Excludes allocator-backed response staging, which belongs to lookup heap.
    std::size_t fixed_reserved_bytes() const noexcept;

  private:
    struct State;
    std::unique_ptr<State> state_;
};

// CA-side normal-object responder. The repository view and observer are
// borrowed and must outlive the responder. All variable request/response
// storage uses allocator and is reserved during construction. A missing
// allocator throws invalid_argument and allocation failure throws bad_alloc.
// Complete means all response bytes were accepted by send;
// lifecycle must still wait for the client's RESPONSE_COMPLETE control notice
// before taking the final TCP_INFO snapshot.
class Responder {
  public:
    Responder(ObjectView repository_object, const Allocator& allocator,
              Observer observer = {});
    ~Responder();
    Responder(const Responder&) = delete;
    Responder& operator=(const Responder&) = delete;
    void begin(std::uint64_t sample, std::uint32_t connection);
    Progress advance(Io& io) noexcept;
    void abandon() noexcept;
    ResponderState state() const noexcept;
    std::uint64_t request_id() const noexcept;
    std::string_view error() const noexcept;
    // Excludes allocator-backed CA payload storage, which belongs to CA heap.
    std::size_t fixed_reserved_bytes() const noexcept;

  private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace turtle::lookup
