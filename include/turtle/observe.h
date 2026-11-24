#ifndef TURTLE_OBSERVE_H
#define TURTLE_OBSERVE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Optional write-only native-stream.v1 observations. No TLS or socket handles.
 * One instrumented process per run/connection/role. No hooks are installed.
 * Environment: TURTLE_EVIDENCE_FD (inherited write-only fd, not owned),
 * TURTLE_RUN_ID, TURTLE_CONNECTION_ID, TURTLE_ROLE; optional TURTLE_PMU=1.
 * A stamp can be reused when a single TLS return covers multiple messages. */
typedef struct turtle_observe_stamp {
  uint64_t ns, tid, cycles, instructions, enabled_ns, running_ns, read_begin_ns,
      read_end_ns;
  uint64_t cycles_id, instructions_id;
  int pmu_available;
  int pmu_errno;
  const char *pmu_status, *pmu_reason; /* SDK-owned static strings. */
} turtle_observe_stamp;
turtle_observe_stamp turtle_observe_now(void);
/* Lifecycle only: ready, hs_begin (first entry), hs_progress, hs_complete
 * (full success), auth_accepted, end. Probe barrier observations are optional.
 * Use the _at variant to report a stamp captured at the actual boundary. */
void turtle_observe_event_at(turtle_observe_stamp, const char *name);
void turtle_observe_event(const char *name);
/* write_attempt: bytes about to be offered; write_accepted/read_return: only
 * the positive byte range actually accepted/returned by that native call;
 * validated: bytes the app has just successfully compared. A single callback
 * may span multiple benchmark messages. No offsets or message IDs required. */
void turtle_observe_plain_at(turtle_observe_stamp, const char *name,
                             const void *data, size_t length);
void turtle_observe_plain(const char *name, const void *data, size_t length);
/* hrr, resumed, early_data, server_first, sender_unpadded, verify_peer,
 * peer_verified, application_only_tail (only application records after
 * Finished through end). -1 unknown, 0 false, 1 true; per connection. */
void turtle_observe_fact(const char *name, int value);
/* Standard IANA numeric IDs; zero means unknown. Verified peer name or NULL. */
void turtle_observe_identity(unsigned version, unsigned suite, unsigned group,
                             const char *peer_name);
/* Coverage starts before READY and must continue beyond the measured tasks.
 * Sources: socket, library_io, stream, header. Report only observations at that
 * source.
 */
void turtle_observe_coverage(const char *source, int active);
/* socket/library_io: actual native operation interval; sent=1 or received=0.
 * result is the actual signed return; data is the result bytes (NULL permitted
 * for counts only); peek is nonconsuming receive. Call before unrelated I/O. */
void turtle_observe_io(turtle_observe_stamp begin, turtle_observe_stamp end,
                       const char *source, int sent, size_t requested,
                       int64_t result, const void *data, int peek);
/* Actual accepted/consumed ciphertext bytes, without native call boundaries.
 * Bind coverage source "stream". This never supplies timing or syscall counts.
 */
void turtle_observe_bytes(int sent, const void *data, size_t length);
/* A native header callback observing exactly the 5-byte TLS record header at
 * this source's directional wire offset. Never treated as a transport time. */
void turtle_observe_header(int sent, uint64_t offset, const void *header5);
#ifdef __cplusplus
}
#endif
#endif
