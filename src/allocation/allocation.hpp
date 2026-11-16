#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
namespace turtle {
struct AllocationSnapshot {
    std::uint64_t live = 0, peak = 0, allocated = 0, freed = 0, allocations = 0, frees = 0,
                  unowned_frees = 0;
};
// Storage belongs to one Observer. Only calls through the scoped C allocator adapter are observed.
class Allocations {
    struct Entry {
        void* pointer = nullptr;
        std::size_t size = 0;
        bool used = false;
    };
    std::vector<Entry> table_;

  public:
    AllocationSnapshot value;
    bool missing = false;
    explicit Allocations(bool enabled);
    std::size_t storage_bytes() const {
        return table_.capacity() * sizeof(Entry);
    }
    void allocated(void*, std::size_t) noexcept;
    void released(void*) noexcept;
};
class AllocationScope {
    Allocations* previous_;

  public:
    explicit AllocationScope(Allocations*) noexcept;
    ~AllocationScope();
    AllocationScope(const AllocationScope&) = delete;
};
} // namespace turtle
