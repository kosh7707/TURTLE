#ifndef TURTLE_START_H
#define TURTLE_START_H
#ifdef __cplusplus
extern "C" {
#endif
/* Optional one-shot prepared-start rendezvous. Call once per participant,
 * after TCP and TLS configuration (and any READY observation), before the
 * first TLS progress call. Returns 1 for joint release, 0 for absent or
 * unsynchronized fallback, -1 for invalid channel/error. No socket ownership,
 * TLS calls, retry decisions or role-specific operations are transferred.
 * Local diagnostic work may continue on a nonpositive result. */
int turtle_wait_start(void);
#ifdef __cplusplus
}
#endif
#endif
