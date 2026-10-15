#pragma once

#include "lifecycle/endpoint_protocol.hpp"
#include "lookup/lookup.hpp"
#include "measure/measure.hpp"
#include "model/model.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace turtle::lifecycle::detail {

struct LookupInputs {
    std::unique_ptr<lookup::Snapshot> reference;
    std::unique_ptr<lookup::Snapshot> initial;
};

LookupInputs load_lookup_inputs(const model::RunConfig& config);

class ClientLookupRuntime {
  public:
    ClientLookupRuntime(const model::RunConfig& config, measure::Meter& meter,
                        std::uint64_t sample, const std::string& directory, int control_fd,
                        const lookup::Snapshot* reference, const lookup::Snapshot* initial,
                        std::vector<int> sockets) noexcept;
    ~ClientLookupRuntime();
    ClientLookupRuntime(const ClientLookupRuntime&) = delete;
    ClientLookupRuntime& operator=(const ClientLookupRuntime&) = delete;

    bool enabled() const noexcept;
    void prepare(model::SampleInfo& info);
    void run_connection(std::size_t connection, ChildProtocol& protocol,
                        control::Waiter& parent, control::Deadline deadline);
    void scenario_end() noexcept;
    void mark_partial(std::size_t connection, std::string_view reason);
    bool overflowed() const noexcept;
    void close_connection(std::size_t connection) noexcept;
    void close_sockets() noexcept;
    void write(bool valid, std::string_view failure);

  private:
    struct Impl;

    const model::RunConfig& config_;
    measure::Meter& meter_;
    std::uint64_t sample_;
    const std::string& directory_;
    int control_fd_;
    const lookup::Snapshot* reference_;
    const lookup::Snapshot* initial_;
    std::vector<int> sockets_;
    std::unique_ptr<Impl> impl_;
};

int ca_endpoint(const model::RunConfig& config, std::uint64_t sample,
                const std::string& directory, std::vector<int> sockets, int control_fd,
                control::Deadline deadline, const lookup::Snapshot& reference);

} // namespace turtle::lifecycle::detail
