#include <cstdlib>
#include <dlfcn.h>
#include <iostream>
#include <string>
#include <turtle/adapter.hpp>

struct Counter {
    std::size_t live = 0, allocations = 0;
};
void* allocate(void* state, std::size_t n) noexcept {
    auto* p = std::malloc(n);
    if (p) {
        ++static_cast<Counter*>(state)->live;
        ++static_cast<Counter*>(state)->allocations;
    }
    return p;
}
void* reallocate(void* state, void* old, std::size_t n) noexcept {
    if (!old)
        return allocate(state, n);
    if (!n) {
        std::free(old);
        --static_cast<Counter*>(state)->live;
        return nullptr;
    }
    return std::realloc(old, n);
}
void deallocate(void* state, void* p) noexcept {
    if (p) {
        std::free(p);
        --static_cast<Counter*>(state)->live;
    }
}
int main(int argc, char** argv) {
    if (argc != 3)
        return 2;
    void* module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module)
        return 2;
    auto entry = reinterpret_cast<turtle::AdapterEntry>(dlsym(module, turtle::adapter_entry_name));
    if (!entry) {
        std::cerr << "adapter ABI v2 entry turtle_adapter_v2 is missing\n";
        dlclose(module);
        return 2;
    }
    auto api = entry();
    if (api.version != turtle::adapter_api_version || !api.declaration || !api.setup ||
        !api.teardown) {
        std::cerr << "adapter API version or function table is incompatible\n";
        dlclose(module);
        return 2;
    }
    Counter counter;
    turtle::HostServices host;
    host.memory_mode = true;
    host.allocator = {&counter, allocate, reallocate, deallocate};
    turtle::TlsConfig config;
    config.ca_file = std::string(argv[2]) + "/ca.pem";
    try {
        auto* context = api.setup(turtle::Role::Client, config, host, {});
        bool hooks = api.declaration(context).allocator_hooks;
        api.teardown(context);
        if (!hooks || !counter.allocations || counter.live) {
            std::cerr << "allocator coverage/live mismatch: " << hooks << ' ' << counter.allocations
                      << ' ' << counter.live << '\n';
            return 1;
        }
        dlclose(module);
        std::cout << "PASS memory setup/teardown: allocations=" << counter.allocations
                  << ", live=0\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
