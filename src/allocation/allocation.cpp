#include "allocation.hpp"
#include <algorithm>
#include <limits>
namespace turtle {
// malloc has no user argument. This pointer borrows a tracker only during an implementation call.
static thread_local Allocations* active = nullptr;
Allocations::Allocations(bool enabled) : table_(enabled ? 262144 : 0) {}
AllocationScope::AllocationScope(Allocations* tracker) noexcept : previous_(active) {
    active = tracker;
}
AllocationScope::~AllocationScope() {
    active = previous_;
}
void Allocations::allocated(void* pointer, std::size_t size) noexcept {
    if (!pointer || table_.empty())
        return;
    auto start = (reinterpret_cast<std::uintptr_t>(pointer) >> 4) % table_.size();
    for (std::size_t i = 0; i < table_.size(); ++i) {
        auto& e = table_[(start + i) % table_.size()];
        if (!e.pointer) {
            e = {pointer, size, true};
            value.live += size;
            value.allocated += size;
            ++value.allocations;
            value.peak = std::max(value.peak, value.live);
            return;
        }
    }
    missing = true;
}
void Allocations::released(void* pointer) noexcept {
    if (!pointer || table_.empty())
        return;
    auto start = (reinterpret_cast<std::uintptr_t>(pointer) >> 4) % table_.size();
    for (std::size_t i = 0; i < table_.size(); ++i) {
        auto& e = table_[(start + i) % table_.size()];
        if (!e.used)
            break;
        if (e.pointer == pointer) {
            value.live -= e.size;
            value.freed += e.size;
            ++value.frees;
            e.pointer = nullptr;
            return;
        }
    }
    ++value.unowned_frees;
}
} // namespace turtle
extern "C" {
void* __real_malloc(std::size_t);
void* __real_calloc(std::size_t, std::size_t);
void* __real_realloc(void*, std::size_t);
void __real_free(void*);
void* __wrap_malloc(std::size_t n) {
    auto* p = __real_malloc(n);
    if (turtle::active)
        turtle::active->allocated(p, n);
    return p;
}
void* __wrap_calloc(std::size_t n, std::size_t s) {
    auto* p = __real_calloc(n, s);
    if (turtle::active && (s == 0 || n <= std::numeric_limits<std::size_t>::max() / s))
        turtle::active->allocated(p, n * s);
    return p;
}
void __wrap_free(void* p) {
    if (turtle::active)
        turtle::active->released(p);
    __real_free(p);
}
void* __wrap_realloc(void* p, std::size_t n) {
    auto* q = __real_realloc(p, n);
    if (turtle::active && (q || n == 0)) {
        turtle::active->released(p);
        turtle::active->allocated(q, n);
    }
    return q;
}
}
