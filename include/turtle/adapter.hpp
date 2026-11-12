#pragma once

// Public adapter contract. No framework-internal headers are exposed here.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace turtle {

enum class Role { Client, Server };
// Keep completion/failure numeric values stable in historical raw events.
enum class Step { WantRead, WantWrite, Complete, Done = Complete, Failed, ApplicationWriteReady };
enum class Scenario { Handshake, ServerPing, FinishedPing, ClientRequest };
enum class SendPolicy { Native, ServerHelloFirst };
enum class TraceOperation {
    MessageGenerate,
    MessageProcess,
    RecordEncrypt,
    RecordDecrypt,
    LibraryMessageWrite,
    CachedCertificateWrite,
    KemKeygen,
    KemEncapsulate,
    KemDecapsulate,
    KemPolynomialKeygen,
    KemPolynomialEncapsulate,
    KemPolynomialDecapsulate
};
enum class TracePhase { Begin, End };
struct TraceEvent {
    TraceOperation operation;
    TracePhase phase;
    std::uint64_t message_id = 0; // stable across retries, scoped to this connection
    unsigned message_type = 0;
    int result = 0;
};
struct TraceSink {
    void* context = nullptr;
    bool (*append)(void*, const TraceEvent&) noexcept = nullptr;
};
enum class Verification { Passed, Failed, NotApplicable };
enum class IoStatus { Ok, WantRead, WantWrite, Closed, Failed };

struct IoResult {
    IoStatus status = IoStatus::Failed;
    std::size_t bytes = 0;
    int system_error = 0;
};

struct AppResult {
    Step step = Step::Failed;
    std::size_t bytes = 0;
};

struct Io {
    void* context = nullptr;
    IoResult (*send)(void*, const std::uint8_t*, std::size_t) noexcept = nullptr;
    IoResult (*recv)(void*, std::uint8_t*, std::size_t) noexcept = nullptr;
    int native_socket = -1; // borrowed; only for explicitly declared native-I/O comparisons
};

struct Allocator {
    void* context = nullptr;
    void* (*allocate)(void*, std::size_t) noexcept = nullptr;
    void* (*reallocate)(void*, void*, std::size_t) noexcept = nullptr;
    void (*deallocate)(void*, void*) noexcept = nullptr;
};

struct KeyLogSink {
    void* context = nullptr;
    bool (*append)(void*, const char*, std::size_t) noexcept = nullptr;
};

struct PlaintextSink {
    void* context = nullptr;
    bool (*append)(void*, bool outgoing, unsigned content_type, const std::uint8_t*,
                   std::size_t) noexcept = nullptr;
};

struct HostServices {
    Allocator allocator;
    KeyLogSink key_log;
    PlaintextSink plaintext;
    bool memory_mode = false;
    bool trace_mode = false;
    TraceSink trace{};
};

struct TlsConfig {
    std::string cipher = "TLS_AES_128_GCM_SHA256"; // fixed benchmark suite, not a preference list
    std::string group = "secp256r1";
    std::string signature = "ecdsa_secp256r1_sha256";
    std::string server_name = "localhost";
    std::string ca_file;
    std::string server_certificate;
    std::string server_key;
    std::string client_certificate;
    std::string client_key;
    bool mutual_auth = false;
    bool compatibility_ccs = true;
    bool framework_io = true;
    std::uint32_t tickets = 0;
    Scenario scenario = Scenario::ClientRequest;
    SendPolicy send_policy = SendPolicy::Native;
    std::size_t application_bytes = 32; // fallback for either direction
    std::optional<std::size_t> client_application_bytes;
    std::optional<std::size_t> server_application_bytes;
    std::size_t record_size_limit = 0; // zero means no requested extension
    bool certificate_compression = false;
};

struct Declaration {
    std::vector<Scenario> scenarios{Scenario::Handshake, Scenario::ClientRequest,
                                    Scenario::ServerPing};
    std::vector<SendPolicy> send_policies{SendPolicy::Native};
    std::vector<TraceOperation> internal_events;
    std::string internal_events_note = "internal generation/processing/record spans unavailable";
    std::string server_ping_note = "application write after local handshake API completion";
    std::string source_version;
    std::string source_url;
    std::string technique = "standard-tls13";
    std::string implementation = "baseline";
    std::string patch_hash;
    std::string library;
    std::string version;
    std::string build_options;
    std::string context_description;
    bool callback_io = true;
    bool allocator_hooks = false;
    bool key_log = false;
    bool plaintext_hook = false;
    bool extra_threads = false;
    bool context_serialization = false;
    bool is_mock = false;
    std::optional<bool> read_ahead;
    std::string read_ahead_note;
    std::string memory_note;
};

struct Negotiated {
    std::string version;
    std::string cipher;
    std::string group;
    std::string signature;
    bool resumed = false;
    bool hello_retry_request = false;
    bool peer_certificate_present = false;
};

struct Context {
    virtual ~Context() = default;
};
struct Connection {
    virtual ~Connection() = default;
};

// The role runtime owns contexts and connections through these lifecycle calls.
// Config and HostServices outlive Context; Io outlives Connection. A retry uses
// the same operation and buffer until that operation reports progress or Done.
struct ImplementationApi {
    std::uint32_t version = 3;
    const char* (*name)() noexcept = nullptr;
    Declaration (*declaration)(const Context*) = nullptr;
    Context* (*setup)(Role, const TlsConfig&, const HostServices&,
                      std::span<const std::uint8_t> saved) = nullptr;
    Connection* (*open)(Context*, const Io&) = nullptr;
    Step (*handshake_step)(Connection*) = nullptr;
    Verification (*peer_verification)(Connection*) = nullptr;
    Negotiated (*negotiated)(Connection*) = nullptr;
    AppResult (*app_send)(Connection*, const std::uint8_t*, std::size_t) = nullptr;
    AppResult (*app_recv)(Connection*, std::uint8_t*, std::size_t) = nullptr;
    const char* (*error)(const Connection*) noexcept = nullptr;
    void (*close)(Connection*) noexcept = nullptr;
    std::vector<std::uint8_t> (*save)(Context*) = nullptr;
    void (*teardown)(Context*) noexcept = nullptr;
};

using AdapterEntry = ImplementationApi (*)();
inline constexpr std::uint32_t adapter_api_version = 3;
inline constexpr const char* adapter_entry_name = "turtle_adapter_v3";

} // namespace turtle

// Each adapter module exports this function. It returns a function table by
// value, not a singleton instance. Library initialization belongs to setup().
extern "C" turtle::ImplementationApi turtle_adapter_v3();
