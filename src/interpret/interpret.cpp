#include "interpret/interpret.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace turtle::interpret {
namespace {
using Bytes = std::vector<std::uint8_t>;
using Json = nlohmann::json;
using Span = std::span<const std::uint8_t>;
std::string hex(Span bytes) {
    constexpr char chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out += chars[b >> 4];
        out += chars[b & 15];
    }
    return out;
}
Bytes unhex(const std::string& text) {
    if (text.size() % 2)
        throw std::runtime_error("odd key log hex length");
    Bytes out;
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::runtime_error("invalid key log hex");
    };
    for (std::size_t i = 0; i < text.size(); i += 2)
        out.push_back((digit(text[i]) << 4) | digit(text[i + 1]));
    return out;
}
std::size_t u24(Span s) {
    return (std::size_t(s[0]) << 16) | (std::size_t(s[1]) << 8) | s[2];
}
struct Record {
    std::size_t begin, end, index;
    unsigned type;
    Span payload;
};
std::vector<Record> records(Span stream) {
    std::vector<Record> out;
    for (std::size_t p = 0; p < stream.size();) {
        if (stream.size() - p < 5)
            throw std::runtime_error("incomplete TLS record header");
        const std::size_t length = (std::size_t(stream[p + 3]) << 8) | stream[p + 4];
        if (length > stream.size() - p - 5)
            throw std::runtime_error("incomplete TLS record payload");
        out.push_back({p, p + 5 + length, out.size(), stream[p], stream.subspan(p + 5, length)});
        p += 5 + length;
    }
    return out;
}
Bytes expand(Span secret, std::string_view label, std::size_t size) {
    const std::string full = "tls13 " + std::string(label);
    Bytes info{static_cast<std::uint8_t>(size >> 8), static_cast<std::uint8_t>(size),
               static_cast<std::uint8_t>(full.size())};
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    Bytes out(size);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(), static_cast<int>(secret.size())) <=
            0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) <= 0 ||
        EVP_PKEY_derive(ctx.get(), out.data(), &size) <= 0)
        throw std::runtime_error("HKDF expansion failed");
    return out;
}
struct Traffic {
    Bytes key, iv;
    std::uint64_t sequence = 0;
    explicit Traffic(Span secret) : key(expand(secret, "key", 16)), iv(expand(secret, "iv", 12)) {}
};
Bytes decrypt(Traffic& traffic, Span header, Span encrypted) {
    if (encrypted.size() < 17)
        throw std::runtime_error("encrypted TLS record too short");
    auto nonce = traffic.iv;
    for (unsigned i = 0; i < 8; ++i)
        nonce[nonce.size() - 1 - i] ^= static_cast<std::uint8_t>(traffic.sequence >> (i * 8));
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                        EVP_CIPHER_CTX_free);
    Bytes plain(encrypted.size());
    int length = 0, total = 0;
    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, traffic.key.data(),
                           nonce.data()) != 1 ||
        EVP_DecryptUpdate(ctx.get(), nullptr, &length, header.data(),
                          static_cast<int>(header.size())) != 1 ||
        EVP_DecryptUpdate(ctx.get(), plain.data(), &length, encrypted.data(),
                          static_cast<int>(encrypted.size() - 16)) != 1)
        throw std::runtime_error("AES-GCM decryption failed");
    total = length;
    std::array<unsigned char, 16> tag{};
    std::copy(encrypted.end() - 16, encrypted.end(), tag.begin());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plain.data() + total, &length) != 1)
        throw std::runtime_error("record cannot be decrypted with logged traffic secret");
    plain.resize(total + length);
    ++traffic.sequence;
    return plain;
}
const char* message_name(unsigned type) {
    switch (type) {
    case 1:
        return "ClientHello";
    case 2:
        return "ServerHello";
    case 4:
        return "NewSessionTicket";
    case 8:
        return "EncryptedExtensions";
    case 11:
        return "Certificate";
    case 13:
        return "CertificateRequest";
    case 15:
        return "CertificateVerify";
    case 20:
        return "Finished";
    case 24:
        return "KeyUpdate";
    case 25:
        return "CompressedCertificate";
    default:
        return "UnknownHandshake";
    }
}
struct Fragment {
    std::size_t begin, end, record;
};
struct Handshakes {
    Bytes pending;
    std::vector<Fragment> fragments;
    std::size_t consumed = 0;
    bool finished = false;
    void feed(Span data, const Record& record, Json& messages) {
        const auto offset = pending.size();
        pending.insert(pending.end(), data.begin(), data.end());
        fragments.push_back({offset, pending.size(), record.index});
        while (pending.size() - consumed >= 4) {
            const auto length = 4 + u24(Span(pending).subspan(consumed + 1, 3));
            if (length > pending.size() - consumed)
                break;
            const auto type = pending[consumed];
            Json covered = Json::array(), parts = Json::array();
            for (const auto& f : fragments)
                if (f.end > consumed && f.begin < consumed + length) {
                    covered.push_back(f.record);
                    parts.push_back(
                        {{"record", f.record},
                         {"plaintext_begin", std::max(f.begin, consumed) - f.begin},
                         {"plaintext_end", std::min(f.end, consumed + length) - f.begin}});
                }
            messages.push_back({{"name", message_name(type)},
                                {"handshake_type", type},
                                {"length", length},
                                {"records", covered},
                                {"plaintext_fragments", parts},
                                {"exact_ciphertext_range", false}});
            if (type == 20)
                finished = true;
            consumed += length;
        }
    }
};
Bytes hello_body(const std::vector<Record>& recs, unsigned type) {
    Bytes plain;
    for (const auto& r : recs) {
        if (r.type != 22)
            continue;
        plain.insert(plain.end(), r.payload.begin(), r.payload.end());
        std::size_t p = 0;
        while (plain.size() - p >= 4) {
            const auto n = u24(Span(plain).subspan(p + 1, 3));
            if (n > plain.size() - p - 4)
                break;
            if (plain[p] == type)
                return Bytes(plain.begin() + p + 4, plain.begin() + p + 4 + n);
            p += 4 + n;
        }
    }
    return {};
}
Json direction(Span bytes, const std::vector<Record>& recs,
               const std::map<std::string, Bytes>& secrets, const std::string& prefix,
               bool supported) {
    Json out = {
        {"records", Json::array()}, {"messages", Json::array()}, {"decryption_complete", true}};
    Handshakes handshake;
    std::unique_ptr<Traffic> hs, app;
    auto get = [&](const std::string& label) -> std::unique_ptr<Traffic> {
        auto it = secrets.find(label);
        if (it == secrets.end() || it->second.size() != 32)
            return {};
        return std::make_unique<Traffic>(it->second);
    };
    if (supported) {
        hs = get(prefix + "_HANDSHAKE_TRAFFIC_SECRET");
        app = get(prefix + "_TRAFFIC_SECRET_0");
    }
    bool unavailable = false;
    for (const auto& r : recs) {
        Json entry = {{"index", r.index},     {"stream_begin", r.begin},
                      {"stream_end", r.end},  {"header_bytes", 5},
                      {"outer_type", r.type}, {"payload_bytes", r.payload.size()},
                      {"decrypted", false},   {"tag_bytes", r.type == 23 ? 16 : 0}};
        unsigned type = r.type;
        Bytes plain;
        Span content = r.payload;
        if (type == 23) {
            try {
                Traffic* traffic = handshake.finished ? app.get() : hs.get();
                if (unavailable || !supported || !traffic)
                    throw std::runtime_error(
                        !supported ? "unsupported cipher suite"
                                   : "traffic secret unavailable or earlier record undecodable");
                plain = decrypt(*traffic, bytes.subspan(r.begin, 5), r.payload);
                std::size_t end = plain.size();
                while (end && plain[end - 1] == 0)
                    --end;
                if (!end)
                    throw std::runtime_error("TLSInnerPlaintext content type unavailable");
                type = plain[end - 1];
                content = Span(plain).first(end - 1);
                entry["decrypted"] = true;
                entry["padding_bytes"] = plain.size() - end;
                entry["inner_type_bytes"] = 1;
                entry["content_type"] = type;
                entry["key_epoch"] = handshake.finished ? "application" : "handshake";
            } catch (const std::exception& e) {
                unavailable = true;
                out["decryption_complete"] = false;
                entry["note"] = e.what();
                entry["name"] = "EncryptedUnavailable";
                out["records"].push_back(entry);
                continue;
            }
        }
        const auto before = out["messages"].size();
        if (type == 22)
            handshake.feed(content, r, out["messages"]);
        else {
            const char* name = type == 20   ? "ChangeCipherSpec"
                               : type == 21 ? "Alert"
                               : type == 23 ? "ApplicationData"
                                            : "UnknownContent";
            out["messages"].push_back({{"name", name},
                                       {"content_type", type},
                                       {"length", content.size()},
                                       {"records", Json::array({r.index})},
                                       {"exact_ciphertext_range", false}});
        }
        entry["content_bytes"] = content.size();
        entry["message_completions"] = out["messages"].size() - before;
        out["records"].push_back(entry);
    }
    if (handshake.consumed != handshake.pending.size()) {
        out["decryption_complete"] = false;
        out["note"] = "incomplete handshake message";
    }
    // Record envelopes are exact; decrypted message bytes are not ciphertext offsets.
    for (auto& m : out["messages"]) {
        Json ranges = Json::array();
        for (const auto& i : m["records"]) {
            const auto& r = recs.at(i.get<std::size_t>());
            ranges.push_back({{"begin", r.begin}, {"end", r.end}});
        }
        m["record_stream_ranges"] = ranges;
        std::size_t sharing = 0;
        for (const auto& other : out["messages"]) {
            bool overlap = false;
            for (const auto& r : m["records"])
                for (const auto& s : other["records"])
                    overlap = overlap || r == s;
            if (overlap)
                ++sharing;
        }
        m["bundled"] = sharing > 1;
    }
    return out;
}
Bytes read_bytes(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("cannot open stream: " + path.string());
    return Bytes(std::istreambuf_iterator<char>(f), {});
}
} // namespace
Json decode(Span client, Span server, std::string_view keylog) {
    const auto cr = records(client), sr = records(server);
    const auto ch = hello_body(cr, 1), sh = hello_body(sr, 2);
    std::string random;
    if (ch.size() >= 34)
        random = hex(Span(ch).subspan(2, 32));
    bool supported = false;
    unsigned cipher = 0;
    if (sh.size() >= 35) {
        const std::size_t p = 35 + sh[34];
        if (sh.size() >= p + 2) {
            cipher = (unsigned(sh[p]) << 8) | sh[p + 1];
            supported = cipher == 0x1301;
        }
    }
    std::map<std::string, Bytes> secrets;
    std::istringstream lines{std::string(keylog)};
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream parts(line);
        std::string label, id, secret;
        if (!(parts >> label >> id >> secret))
            continue;
        if (!random.empty() && hex(unhex(id)) == random)
            secrets[label] = unhex(secret);
    }
    Json result = {{"schema", 1},
                   {"cipher_suite", cipher},
                   {"supported_cipher", supported},
                   {"client_random", random},
                   {"client_sent", direction(client, cr, secrets, "CLIENT", supported)},
                   {"server_sent", direction(server, sr, secrets, "SERVER", supported)}};
    result["decryption_complete"] = result["client_sent"]["decryption_complete"].get<bool>() &&
                                    result["server_sent"]["decryption_complete"].get<bool>();
    result["note"] =
        "Message plaintext ranges are within record content, never exact ciphertext byte ranges.";
    return result;
}
Json analyze(const std::filesystem::path& raw, const std::filesystem::path& output) {
    std::ifstream file(raw);
    std::string line;
    if (!std::getline(file, line))
        throw std::runtime_error("missing sample header");
    const auto header = Json::parse(line);
    if (header.at("schema") != 1 || header.at("type") != "sample")
        throw std::runtime_error("unsupported sample schema");
    const auto role = header.at("role").get<std::string>();
    const auto prefix = raw.parent_path() / role;
    std::ifstream keys(prefix.string() + ".keys.log");
    const std::string keylog{std::istreambuf_iterator<char>(keys), {}};
    std::vector<Json> events;
    while (std::getline(file, line))
        if (!line.empty())
            events.push_back(Json::parse(line));
    Json connections = Json::array();
    for (const auto& c : header.at("connections")) {
        const auto index = c.at("index").get<std::size_t>();
        const auto p = prefix.string() + ".conn-" + std::to_string(index);
        const auto sent = read_bytes(p + ".sent.bin"), received = read_bytes(p + ".received.bin");
        auto decoded =
            role == "client" ? decode(sent, received, keylog) : decode(received, sent, keylog);
        decoded["connection"] = index;
        Json annotations = Json::array();
        for (const auto& event : events) {
            if (event.at("connection") != index)
                continue;
            const auto kind = event.value("kind", "");
            if (kind != "IO_SEND_RETURN" && kind != "IO_RECV_RETURN")
                continue;
            const bool client_direction = (kind == "IO_SEND_RETURN") == (role == "client");
            Json names = Json::array();
            const auto begin = event.value("stream_begin", 0ULL),
                       end = event.value("stream_end", 0ULL);
            for (const auto& message :
                 decoded[client_direction ? "client_sent" : "server_sent"]["messages"]) {
                bool overlaps = false;
                for (const auto& range : message["record_stream_ranges"])
                    overlaps =
                        overlaps || (end > begin && range["begin"].get<std::uint64_t>() < end &&
                                     range["end"].get<std::uint64_t>() > begin);
                if (overlaps)
                    names.push_back(message["name"]);
            }
            annotations.push_back({{"sequence", event.at("sequence")},
                                   {"names", names},
                                   {"mapping", "record_envelope_overlap"},
                                   {"bundled", names.size() > 1}});
        }
        decoded["event_annotations"] = annotations;
        connections.push_back(decoded);
    }
    Json result = {{"schema", 1},
                   {"sample", header.at("sample")},
                   {"role", role},
                   {"connections", connections}};
    std::ofstream out(output);
    out.exceptions(std::ios::badbit | std::ios::failbit);
    out << result.dump(2) << '\n';
    return result;
}
} // namespace turtle::interpret
