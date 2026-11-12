#include "lifecycle/lifecycle.hpp"
#include "model/run_config.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <turtle/adapter.hpp>
#include <unistd.h>

namespace {

void require(bool condition, const char* reason) {
    if (!condition) {
        throw std::runtime_error(reason);
    }
}

using CallCount = std::uint32_t (*)();

CallCount counter(void* module, const char* name) {
    auto result = reinterpret_cast<CallCount>(::dlsym(module, name));
    require(result != nullptr, "v1-only fixture counter is missing");
    return result;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        return 2;
    }
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-adapter-abi-" + std::to_string(::getpid()));
    const auto sentinel = root.string() + ".v1-called";
    void* module = nullptr;
    try {
        turtle::model::RunConfig config;
        // The director receives initial readiness from the server first. Put
        // the incompatible module there so its loader diagnostic cannot race
        // with the mock peer observing the server socket close.
        config.client_adapter = "mock";
        config.server_adapter = "v1_only";
        config.adapter_directory = std::filesystem::path(argv[1]).parent_path().string();
        config.output_directory = root.string();
        config.samples = 1;
        config.warmups = 0;
        config.connections = 1;
        config.perf = false;
        config.pin_cores = false;
        config.calibration_samples = 2;
        require(::setenv("TURTLE_V1_FIXTURE_SENTINEL", sentinel.c_str(), 1) == 0,
                "could not configure the v1 callback sentinel");
        const int result = turtle::lifecycle::run(config);
        ::unsetenv("TURTLE_V1_FIXTURE_SENTINEL");
        require(result != 0, "production lifecycle accepted a v1-only adapter");
        require(!std::filesystem::exists(sentinel),
                "production lifecycle called the v1 entry or one of its callbacks");

        std::ifstream attempts(root / "attempts.jsonl");
        std::ostringstream artifact;
        artifact << attempts.rdbuf();
        require(attempts.good() || attempts.eof(), "attempt ledger is unavailable");
        const auto attempt_text = artifact.str();
        if (attempt_text.find("adapter ABI v3 entry turtle_adapter_v3 is missing") ==
            std::string::npos) {
            throw std::runtime_error(
                "production lifecycle did not preserve the explicit ABI refusal: " + attempt_text);
        }

        // Keep a direct symbol check as a secondary fixture sanity check. The
        // lifecycle result and child-visible sentinel above are the primary proof.
        module = ::dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        require(module != nullptr, "could not open the v1-only fixture");
        ::dlerror();
        auto* current_entry = ::dlsym(module, turtle::adapter_entry_name);
        const char* error = ::dlerror();
        require(current_entry == nullptr, "v1-only fixture exposed the current ABI entry");
        require(error != nullptr && std::strstr(error, turtle::adapter_entry_name) != nullptr,
                "missing v2 entry did not produce a clear symbol diagnostic");
        require(::dlsym(module, "turtle_adapter_v1") != nullptr,
                "fixture does not expose its intentional v1 entry");
        require(counter(module, "turtle_v1_fixture_entry_calls")() == 0,
                "v1 entry was invoked before ABI rejection");
        require(counter(module, "turtle_v1_fixture_declaration_calls")() == 0,
                "v1 declaration was invoked before ABI rejection");
        require(counter(module, "turtle_v1_fixture_setup_calls")() == 0,
                "v1 setup was invoked before ABI rejection");
        ::dlclose(module);
        module = nullptr;
        std::filesystem::remove_all(root);
        std::cout << "PASS v1-only adapter rejected before entry, declaration, or setup\n";
        return 0;
    } catch (const std::exception& failure) {
        ::unsetenv("TURTLE_V1_FIXTURE_SENTINEL");
        std::cerr << failure.what() << '\n';
        if (module != nullptr) {
            ::dlclose(module);
        }
        std::filesystem::remove_all(root);
        std::filesystem::remove(sentinel);
        return 1;
    }
}
