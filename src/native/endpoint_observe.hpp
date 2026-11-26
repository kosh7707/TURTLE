#pragma once

#include <cstddef>
#include <cstdint>
#include <turtle/observe.h>

namespace turtle::native::detail {
// Publish preparation diagnostics before READY, without ending observation.
void flush_preparation();
// Private endpoint-only observations. The sequence returned by the full offer
// identifies immutable bytes on this connection, not configured test data.
uint64_t full_offer(const void *data, size_t length);
void suffix_offer(uint64_t seq, size_t offset, size_t length);
void ready_with_prepared_response();
void read_first_event(turtle_observe_stamp stamp, bool confirmation);
}
