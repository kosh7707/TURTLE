#!/usr/bin/env python3
"""Exercise certificate lookup immediately before real, stock TLS 1.3.

This is deliberately an integration oracle, not a lookup protocol unit test.  It
requires the CA sidecar, the client lookup, the TLS endpoints, the interpreter,
and the reporter to agree on the same two-attempt/three-connection run.
"""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SCENARIO = "synthetic-lookup-plus-standard-tls"
SAMPLES = 2
WARMUPS = 1
CONNECTIONS = 2
TOTAL_CONNECTIONS = WARMUPS + CONNECTIONS


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args):
    command = [str(arg) for arg in args]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def json_lines(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    check(rows, f"empty JSONL artifact: {path}")
    return rows


def one(rows, kind, source):
    selected = [row for row in rows if row.get("record_kind") == kind]
    check(len(selected) == 1, f"{source}: expected one {kind}, got {len(selected)}")
    return selected[0]


def fnv1a64(data):
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def fingerprint(data):
    return f"fnv1a64:{fnv1a64(data):016x}"


def write_snapshot(path, certificate):
    # C1's complete portable snapshot shape.  Do not use a framework-produced
    # snapshot here: the test must independently prove that the original bytes
    # are the bytes restored into every connection-local cache.
    path.write_text(
        json.dumps(
            {
                "type": "turtle-lookup-cache",
                "schema": 1,
                "object_id": fingerprint(certificate),
                "object_size": len(certificate),
                "object_hex": certificate.hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def write_profile(path, pki, cache_mode, snapshot):
    document = {
        "name": f"lookup-{cache_mode}",
        "pki": str(pki),
        "tls": {
            "version": "TLS1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group": "secp256r1",
            "signature": "ecdsa_secp256r1_sha256",
            "server_name": "localhost",
            "mutual_auth": False,
            "compatibility_ccs": True,
            "framework_io": True,
            "tickets": 0,
            "application_bytes": 32,
            "record_size_limit": 0,
            "certificate_compression": False,
        },
        "socket": {
            "tcp_nodelay": True,
            "send_buffer": 65536,
            "receive_buffer": 65536,
        },
        "lookup": {
            "enabled": True,
            "object_file": str(pki / "server-chain.pem"),
            "cache_mode": cache_mode,
            "snapshot_file": str(snapshot) if snapshot else None,
        },
        "measurement": {
            "samples": SAMPLES,
            "warmups": WARMUPS,
            "connections": CONNECTIONS,
            "mode": "timing",
            "perf": False,
            "pin_cores": False,
        },
        "technique": {
            "name": SCENARIO,
            "note": "reference certificate is pre-held; stock TLS Certificate remains",
        },
    }
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")


def connection_rows(rows, source):
    result = {
        row["connection"]: row
        for row in rows
        if row.get("record_kind") == "connection_summary"
    }
    check(set(result) == set(range(TOTAL_CONNECTIONS)),
          f"{source}: missing warmup/measured connection summaries")
    return result


def events_for(rows, connection):
    events = [
        row for row in rows
        if row.get("record_kind") == "event" and row.get("connection") == connection
    ]
    check(all(a["sequence"] < b["sequence"] for a, b in zip(events, events[1:])),
          f"connection {connection}: non-increasing service event sequence")
    return events


def require_event_order(events, names, source):
    positions = []
    for name in names:
        matches = [index for index, event in enumerate(events) if event["kind"] == name]
        check(len(matches) == 1, f"{source}: expected one {name}, got {len(matches)}")
        positions.append(matches[0])
    check(positions == sorted(positions), f"{source}: event order differs from {' -> '.join(names)}")
    return [events[position] for position in positions]


def validate_heap(rows, mode, domain, source):
    events = [row for row in rows if row.get("record_kind") == "event"]
    summaries = connection_rows(rows, source)
    check(events, f"{source}: no service events")
    check(all(row.get("heap_domain") == domain for row in events),
          f"{source}: event heap domain is not {domain}")
    check(all(row.get("heap_domain") == domain for row in summaries.values()),
          f"{source}: summary heap domain is not {domain}")
    heaps = [row.get("heap") for row in events] + [row.get("heap") for row in summaries.values()]
    if mode == "timing":
        check(all(heap is None for heap in heaps), f"{source}: timing mode synthesized heap data")
    else:
        check(all(heap is not None for heap in heaps), f"{source}: memory mode omitted heap data")
        check(any(row["heap"]["peak"] > 0 for row in summaries.values()),
              f"{source}: allocator-backed storage was not observed")


def validate_tls(raw, mode, interpret, certificate):
    rows = json_lines(raw)
    header, events = rows[0], rows[1:]
    check(header["type"] == "sample" and header["schema"] == 2, f"{raw}: TLS schema changed")
    check(header["valid"], f"{raw}: {header['invalid_reason']}")
    check(not header["declaration"]["is_mock"], f"{raw}: mock is not TLS evidence")
    check(header["config"]["samples"] == SAMPLES, f"{raw}: sample count changed")
    check(header["config"]["warmups"] == WARMUPS, f"{raw}: warmup count changed")
    check(header["config"]["connections"] == CONNECTIONS, f"{raw}: connection count changed")
    lookup_config = header["config"].get("lookup")
    check(isinstance(lookup_config, dict) and lookup_config.get("enabled") is True,
          f"{raw}: effective lookup configuration is missing")
    check(header["config"].get("scenario_name") == SCENARIO,
          f"{raw}: TLS artifact hides the synthetic lookup scenario")
    profile = json.loads(header["config"]["profile_document"])
    server_input = profile["certificate_inputs"]["server"]
    check(server_input == {"bytes": len(certificate), "fingerprint": fingerprint(certificate)},
          f"{raw}: TLS input does not retain the reference certificate provenance")
    check(len(header["connections"]) == TOTAL_CONNECTIONS, f"{raw}: TLS connections missing")
    for index, connection in enumerate(header["connections"]):
        check(connection["index"] == index and connection["warmup"] == (index < WARMUPS),
              f"{raw}: warmup/connection identity changed")
        check(connection["verification"] in ("passed", "not_applicable"),
              f"{raw}: peer verification failed")
        negotiated = connection["negotiated"]
        check(negotiated["version"] == "TLS1.3", f"{raw}: TLS 1.3 not negotiated")
        check(negotiated["cipher"] == "TLS_AES_128_GCM_SHA256", f"{raw}: wrong cipher")
        check(not negotiated["resumed"] and not negotiated["hello_retry_request"],
              f"{raw}: not a direct full handshake")
        check(connection["application_verified"], f"{raw}: encrypted ping-pong not verified")
    if mode == "timing" or not header["capabilities"]["heap_tracking"]:
        check(all(event["heap"] is None for event in events), f"{raw}: unsupported TLS heap synthesized")
    else:
        check(any(event["heap"] and event["heap"]["peak"] > 0 for event in events),
              f"{raw}: TLS allocator hook produced no measurement")

    decoded_path = raw.with_suffix(".decoded.json")
    run(interpret, raw, decoded_path)
    decoded = json.loads(decoded_path.read_text())
    check(len(decoded["connections"]) == TOTAL_CONNECTIONS, f"{raw}: decoded connection missing")
    for connection in decoded["connections"]:
        check(connection["decryption_complete"], f"{raw}: TLS decryption incomplete")
        server_names = [item["name"] for item in connection["server_sent"]["messages"]]
        client_names = [item["name"] for item in connection["client_sent"]["messages"]]
        check("Certificate" in server_names, f"{raw}: stock TLS Certificate disappeared")
        check("CompressedCertificate" not in server_names,
              f"{raw}: certificate compression was unexpectedly used")
        check("Finished" in server_names and "Finished" in client_names,
              f"{raw}: full handshake messages missing")
        check("ApplicationData" in server_names and "ApplicationData" in client_names,
              f"{raw}: encrypted ping-pong records missing")
    return header, events


def validate_service(sample, cache_mode, mode, certificate, tls_events):
    lookup_path, ca_path = sample / "lookup.jsonl", sample / "ca.jsonl"
    lookup_rows, ca_rows = json_lines(lookup_path), json_lines(ca_path)
    lookup_header, ca_header = one(lookup_rows, "header", lookup_path), one(ca_rows, "header", ca_path)
    one(lookup_rows, "footer", lookup_path)
    one(ca_rows, "footer", ca_path)
    for header, expected_type, participant in (
        (lookup_header, "certificate-lookup", "tls-client"),
        (ca_header, "mock-ca", "mock-ca"),
    ):
        check(header["type"] == expected_type and header["schema"] == 1,
              f"{sample}: service schema changed")
        check(header["scenario_name"] == SCENARIO, f"{sample}: synthetic scenario hidden")
        check(header["cache_mode"] == cache_mode, f"{sample}: cache mode mismatch")
        check(header["object_id"] == fingerprint(certificate), f"{sample}: object identity mismatch")
        check(header["object_size"] == len(certificate), f"{sample}: object size mismatch")
        check(header["reference_bytes"] == len(certificate), f"{sample}: reference bytes omitted")
        check(header["reference_capacity"] >= len(certificate), f"{sample}: reference capacity omitted")
        check(header["pid"] > 0, f"{sample}: {participant} PID missing")
        check(header["capabilities"]["heap_tracking"] == (mode == "memory"),
              f"{sample}: heap support metadata disagrees with mode")
    check(lookup_header["cache_state_id"] ==
          ("empty" if cache_mode == "empty" else fingerprint(certificate)),
          f"{sample}: initial snapshot identity mismatch")
    check(lookup_header["cache_capacity"] >= len(certificate), f"{sample}: cache capacity omitted")
    check(lookup_header["framework_reserved_bytes"] > 0,
          f"{sample}: fixed lookup reservation omitted")
    validate_heap(lookup_rows, mode, "lookup", lookup_path)
    validate_heap(ca_rows, mode, "mock_ca", ca_path)

    lookup_connections = connection_rows(lookup_rows, lookup_path)
    ca_connections = connection_rows(ca_rows, ca_path)
    for connection in range(TOTAL_CONNECTIONS):
        lookup = lookup_connections[connection]
        ca = ca_connections[connection]
        expected_hit = cache_mode == "fixed-snapshot"
        check(lookup["warmup"] == (connection < WARMUPS), f"{sample}: lookup warmup flag wrong")
        check(lookup["object_id"] == fingerprint(certificate)
              and ca["object_id"] == fingerprint(certificate),
              f"{sample}: connection object identity mismatch")
        check(lookup["cache_hit"] == expected_hit and ca["cache_hit"] == expected_hit,
              f"{sample}: cache state leaked between connections")
        check(lookup["request_count"] == (0 if expected_hit else 1),
              f"{sample}: lookup request count is indirect or incorrect")
        check(ca["request_count"] == (0 if expected_hit else 1),
              f"{sample}: CA request count disagrees")
        check(lookup["logical_cache_bytes"] == len(certificate),
              f"{sample}: logical cache bytes do not describe the consumed object")
        check(lookup["cache_capacity"] >= len(certificate), f"{sample}: cache capacity missing")
        check(lookup["reference_bytes"] == len(certificate), f"{sample}: lookup reference bytes missing")
        check(lookup["framework_reserved_bytes"] > 0,
              f"{sample}: per-operation reservation missing")
        check(ca["logical_cache_bytes"] == 0 and ca["cache_capacity"] == 0,
              f"{sample}: CA repository was reported as lookup cache")
        check(ca["reference_bytes"] == len(certificate), f"{sample}: CA reference bytes missing")
        check(ca["framework_reserved_bytes"] > 0,
              f"{sample}: CA fixed reservation metadata missing")
        check(isinstance(lookup["tcp_start"], dict) and isinstance(lookup["tcp_end"], dict),
              f"{sample}: prepared lookup TCP connection was not observed")

        events = events_for(lookup_rows, connection)
        tls_handshakes = [
            event for event in tls_events
            if event.get("connection") == connection and event.get("kind") == "CALL_BEGIN"
            and event.get("call") == "handshake"
        ]
        check(tls_handshakes, f"{sample}: TLS handshake boundary missing")
        if expected_hit:
            ordered = require_event_order(
                events, ["SCENARIO_BEGIN", "CACHE_LOOKUP", "CACHE_HIT", "USABLE_OBJECT", "SCENARIO_END"],
                f"{sample}/connection-{connection}")
            check(not any(event["kind"] in ("CACHE_MISS", "REQUEST_BEGIN", "RESPONSE_COMPLETE", "CACHE_INSERT")
                          for event in events),
                  f"{sample}: warm cache performed a remote request")
            check(ordered[3]["monotonic_ns"] <= tls_handshakes[0]["monotonic_ns"],
                  f"{sample}: TLS began before warm object became usable")
        else:
            ordered = require_event_order(
                events,
                ["SCENARIO_BEGIN", "CACHE_LOOKUP", "CACHE_MISS", "REQUEST_BEGIN",
                 "RESPONSE_COMPLETE", "CACHE_INSERT", "USABLE_OBJECT", "SCENARIO_END"],
                f"{sample}/connection-{connection}")
            check(ordered[4]["monotonic_ns"] <= ordered[6]["monotonic_ns"]
                  <= tls_handshakes[0]["monotonic_ns"],
                  f"{sample}: response_complete -> usable -> TLS order violated")

        lookup_sent = (sample / f"lookup-{connection}.sent.bin").read_bytes()
        lookup_received = (sample / f"lookup-{connection}.received.bin").read_bytes()
        ca_sent = (sample / f"ca-{connection}.sent.bin").read_bytes()
        ca_received = (sample / f"ca-{connection}.received.bin").read_bytes()
        check(lookup_sent == ca_received and lookup_received == ca_sent,
              f"{sample}: lookup/CA directional bytes differ")
        if expected_hit:
            check(not lookup_sent and not lookup_received and not ca_sent and not ca_received,
                  f"{sample}: warm hit emitted application lookup bytes")
        else:
            check(len(lookup_sent) == 44 and len(ca_received) == 44,
                  f"{sample}: cold request is not one C1 wire header")
            check(len(ca_sent) == 44 + len(certificate), f"{sample}: cold response size wrong")
            check(ca_sent[44:] == certificate, f"{sample}: CA did not return original PEM bytes")

    return lookup_header["pid"], ca_header["pid"]


def validate_report(report_dir):
    summary = json.loads((report_dir / "summary.json").read_text())
    check(summary["invalid_samples"] == 0, "TLS report marked lookup run invalid")
    lookup_path = report_dir / "lookup-summary.json"
    check(lookup_path.exists(), "lookup-summary.json was not produced")
    lookup = json.loads(lookup_path.read_text())
    disclosure = lookup.get("scenario_disclosure", "")
    check(isinstance(disclosure, str) and "synthetic" in disclosure.lower()
          and "stock" in disclosure.lower() and "tls" in disclosure.lower(),
          "lookup report does not disclose the synthetic lookup plus stock TLS scenario")
    check(len(lookup.get("attempt_table", [])) == SAMPLES, "lookup report attempt denominator changed")
    check(len(lookup.get("connection_table", [])) == SAMPLES * TOTAL_CONNECTIONS,
          "lookup report connection denominator changed")


def main():
    check(len(sys.argv) == 7,
          "usage: lookup.py TURTLE REPORT INTERPRET ADAPTERS PKI IMPLEMENTATION")
    turtle, report, interpret, adapters, pki, implementation = sys.argv[1:]
    pki = Path(pki).resolve()
    certificate = (pki / "server-chain.pem").read_bytes()
    root = Path(tempfile.mkdtemp(prefix=f"turtle-lookup-{implementation}-"))
    try:
        snapshot = root / "snapshot.json"
        write_snapshot(snapshot, certificate)
        for cache_mode in ("empty", "fixed-snapshot"):
            profile = root / f"profile-{cache_mode}.json"
            write_profile(profile, pki, cache_mode,
                          snapshot if cache_mode == "fixed-snapshot" else None)
            for mode in ("timing", "memory"):
                output = root / f"raw-{cache_mode}-{mode}"
                report_output = root / f"report-{cache_mode}-{mode}"
                run(turtle, "run", "--profile", profile,
                    "--client", implementation, "--server", implementation,
                    "--adapter-dir", adapters, "--samples", str(SAMPLES),
                    "--warmups", str(WARMUPS), "--connections", str(CONNECTIONS),
                    "--mode", mode, "--server-auth", "--no-affinity", "--no-perf",
                    "--output", output)
                samples = sorted(output.glob("sample-*"))
                check(len(samples) == SAMPLES, f"{output}: attempt denominator changed")
                run_pids = []
                for sample in samples:
                    client_header, client_events = validate_tls(
                        sample / "client.jsonl", mode, interpret, certificate)
                    server_header, _ = validate_tls(
                        sample / "server.jsonl", mode, interpret, certificate)
                    lookup_pid, ca_pid = validate_service(
                        sample, cache_mode, mode, certificate, client_events)
                    pids = [client_header["pid"], server_header["pid"], ca_pid]
                    check(len(set(pids)) == 3, f"{sample}: TLS client/server/CA are not independent PIDs")
                    check(lookup_pid == client_header["pid"],
                          f"{sample}: lookup is not owned by the TLS client process")
                    run_pids.extend(pids)
                check(len(run_pids) == len(set(run_pids)),
                      f"{output}: a role process was reused across independent attempts")
                ledger = json_lines(output / "attempts.jsonl")
                final = [row for row in ledger if row.get("record_kind") == "attempt_final"]
                check(len(final) == SAMPLES and all(row["final_status"] == "success" for row in final),
                      f"{output}: attempts did not all complete")
                check(all(row["participants"] == ["tls-server", "tls-client", "mock-ca"] for row in final),
                      f"{output}: three-participant lifecycle was not recorded")
                run(report, output, report_output)
                validate_report(report_output)
        shutil.rmtree(root)
        print(
            f"PASS {implementation}: cold/warm certificate lookup, independent CA, "
            "real TLS 1.3, timing/memory, decode and report"
        )
    except Exception:
        print(f"Artifacts retained: {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
