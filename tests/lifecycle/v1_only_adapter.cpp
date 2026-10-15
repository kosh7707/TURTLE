#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

namespace {

std::uint32_t entry_calls = 0;
std::uint32_t declaration_calls = 0;
std::uint32_t setup_calls = 0;

void mark_call(const char* label, std::size_t size) {
    const char* path = std::getenv("TURTLE_V1_FIXTURE_SENTINEL");
    if (path == nullptr) {
        return;
    }
    const int descriptor = ::open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (descriptor >= 0) {
        (void)::write(descriptor, label, size);
        (void)::close(descriptor);
    }
}

void declaration_marker() {
    ++declaration_calls;
    constexpr char label[] = "declaration\n";
    mark_call(label, sizeof(label) - 1);
}

void setup_marker() {
    ++setup_calls;
    constexpr char label[] = "setup\n";
    mark_call(label, sizeof(label) - 1);
}

struct LegacyApi {
    std::uint32_t version;
    void (*declaration)();
    void (*setup)();
};

} // namespace

extern "C" LegacyApi turtle_adapter_v1() {
    ++entry_calls;
    constexpr char label[] = "entry\n";
    mark_call(label, sizeof(label) - 1);
    return {1, declaration_marker, setup_marker};
}

extern "C" std::uint32_t turtle_v1_fixture_entry_calls() {
    return entry_calls;
}

extern "C" std::uint32_t turtle_v1_fixture_declaration_calls() {
    return declaration_calls;
}

extern "C" std::uint32_t turtle_v1_fixture_setup_calls() {
    return setup_calls;
}
