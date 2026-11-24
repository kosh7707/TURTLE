# Live boundary migration: regression coverage

Historical artifacts stay inputs to the existing offline analyzer. Running two
copies of the stock peer is **not** proof of a new independent participant.

| Old execution surface | Current check or remaining gap |
| --- | --- |
| Adapter registration, C callback contract and installed pull/submit SDK | Removed product; `independence-contract.sh` rejects the old surface and checks both installed peer roles. `installed_c_observer` builds and runs a C-only consumer of the one-way observer library. |
| Role-engine action ordering, app-owned OpenSSL loop, injected probe faults | No replacement TLS action dispatcher. `native_evidence` checks lifecycle, stream offsets, interrupted coverage and retry/peek evidence. Actual native process interoperability and separate paused-client probe require integration evidence in addition to these unit tests. |
| Partial/inaccurate request; missing certificate, incorrect SAN, CN-only client | `reference_rejects_invalid_request` runs the stock peer against an independent openssl CLI process, checking rejection, withheld response and raw stdout. |
| One-side and matrix callbacks, socket stress, same-vendor config swap, optional alternate-vendor/hybrid PKI pairings | Removed vendor test targets. `scenario_s4_plaintext_vectors` retains archived plaintext semantics; it is not a replacement for an actual role × auth × scenario matrix, small-window full-duplex stress, or alternate-PKI negotiation. |
| Same-launcher image drift across probe/ordinary runs | `participant_image_inventory` checks process ancestry, module inclusion/digest, drift and offline image-key determinism. Cross-trial binding also requires a native supervisor test. |
| Namespace PCAP, network impairment, external perf sampling, lifecycle retry and recording-overhead studies using old controlled peers | Not validated by the new packaging tests. `netem_evidence`, PMU live/denied/offline, `profile_catalog`, `atomic_artifact` and deterministic archived analysis cover their respective evidence formats, not native namespace or retry execution. |
| Incremental framing, external pair diagnostics, source language, archived specification and component boundaries | Retained as independent tests. Private historical recorder helpers are not installed. |

For vendor-specific test binaries that no longer exist, use git history to inspect
the original controlled protocol. Do not expose it as a second live path to
make an old assertion pass.

The opt-in `native_netem_capture` test now exercises the native route itself.
Set `TURTLE_TEST_NETEM=ON` and `TURTLE_NATIVE_TEST_APP` to the independently
built observed `chat` client from `native-matrix.sh`. It creates a network
namespace for each participant and a router namespace, verifies the applied
settings, captures both endpoint interfaces, replays without network access,
and rejects a modified PCAP, a rehashed inconsistent qdisc witness, and denied
namespace setup. The two `lo` collectors in a loopback capture do **not**
represent separate network vantages; `tcp_ack` is a packet-copy observation,
not a measurement of a TLS return.

For pre-CF capability, the trusted paused client's direct socket BIO is the
receive boundary. Replay checks consumed bytes plus the kernel receive queue
before release against bytes used through authenticated greeting validation
while the server remains stopped. A stock sender additionally supplies its
direct-BIO extent; an instrumented external sender can supply a continuous
socket-write extent. With **no sender wire observations**, the receiver-only
path can establish the bound. A custom sender with partial, header-only or
buffered-library-only instrumentation is currently left unconfirmed rather
than treating those observations as proof of a TCP flush or silently ignoring
them. This is a conservative limitation of this probe, not a TLS requirement.
