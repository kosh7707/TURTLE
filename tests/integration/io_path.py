#!/usr/bin/env python3
"""Prove the real OpenSSL callback/native I/O paths and their external skb evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


SAMPLES = 2
TLS_PATHS = {"tls_c2s", "tls_s2c"}
PHASES = tuple(
    (phase, edge)
    for phase in ("setup", "scenario", "cleanup")
    for edge in ("begin", "end")
)
NATIVE_REASON = "native_socket_io_not_observed"
EXTERNAL_TOOLS = ("ip", "tc", "ethtool", "unshare", "nsenter")
UNSHARE_UNSUPPORTED_MESSAGES = (
    "operation not permitted",
    "permission denied",
    "user namespaces are not enabled",
    "user namespaces are disabled",
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("normal", "external"))
    parser.add_argument("--turtle", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--interpret", type=Path, required=True)
    parser.add_argument("--adapters", type=Path, required=True)
    parser.add_argument("--pki", type=Path, required=True)
    parser.add_argument("--netem", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def unique_run_directory(root: Path, mode: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stem = f"{mode}-{time.time_ns()}-{os.getpid()}"
    for suffix in range(100):
        candidate = root / (stem if suffix == 0 else f"{stem}-{suffix}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate a unique retained I/O-path result directory")


def command_record(argv: list[object], *, timeout: int) -> dict[str, object]:
    command = [str(item) for item in argv]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def require_success(record: dict[str, object]) -> None:
    if record["exit_code"] != 0:
        raise RuntimeError(
            f"command failed ({record['exit_code']}): {' '.join(record['argv'])}\n"
            f"stdout:\n{record['stdout']}\nstderr:\n{record['stderr']}"
        )


def unshare_capability_failure(record: dict[str, object]) -> bool:
    """Recognize only explicit OS permission/capability rejection, not arbitrary exit 2."""
    if record.get("exit_code") == 0:
        return False
    diagnostic = f"{record.get('stdout', '')}\n{record.get('stderr', '')}".lower()
    return "unshare" in diagnostic and any(
        marker in diagnostic for marker in UNSHARE_UNSUPPORTED_MESSAGES
    )


def external_support_preflight(manifest: dict[str, object]) -> bool:
    resolved = {name: shutil.which(name) for name in EXTERNAL_TOOLS}
    preflight: dict[str, object] = {
        "required_tools": resolved,
        "unshare_check": None,
        "supported": False,
        "reason": None,
    }
    manifest["support_preflight"] = preflight
    missing = [name for name, path in resolved.items() if path is None]
    if missing:
        preflight["reason"] = f"required program is missing: {', '.join(missing)}"
        return False
    argv = [
        resolved["unshare"], "--user", "--map-root-user", "--net", "--",
        sys.executable, "-c", "pass",
    ]
    try:
        record = command_record(argv, timeout=5)
    except subprocess.TimeoutExpired as error:
        record = {
            "argv": [str(item) for item in argv],
            "exit_code": None,
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "timed_out": True,
        }
        preflight["unshare_check"] = record
        raise RuntimeError("external support preflight timed out") from error
    except OSError as error:
        record = {
            "argv": [str(item) for item in argv],
            "exit_code": None,
            "stdout": "",
            "stderr": str(error),
            "os_error": True,
        }
        preflight["unshare_check"] = record
        raise RuntimeError(f"external support preflight could not execute: {error}") from error
    preflight["unshare_check"] = record
    if record["exit_code"] == 0:
        preflight["supported"] = True
        return True
    if unshare_capability_failure(record):
        preflight["reason"] = "rootless user/network namespace creation is not permitted"
        return False
    raise RuntimeError(
        f"external support preflight failed unexpectedly ({record['exit_code']}): "
        f"{record['stderr']}"
    )


def read_jsonl(path: Path) -> list[dict[str, object]]:
    check(path.is_file(), f"missing JSONL artifact: {path}")
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    check(bool(rows), f"empty JSONL artifact: {path}")
    return rows


def write_profile(path: Path, pki: Path, framework_io: bool, mutual_auth: bool,
                  samples: int) -> dict[str, object]:
    profile = {
        "name": "openssl-io-path",
        "pki": str(pki.resolve()),
        "tls": {
            "version": "TLS1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group": "secp256r1",
            "signature": "ecdsa_secp256r1_sha256",
            "server_name": "localhost",
            "mutual_auth": mutual_auth,
            "compatibility_ccs": True,
            "framework_io": framework_io,
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
        "lookup": {"enabled": False},
        "measurement": {
            "samples": samples,
            "warmups": 0,
            "connections": 1,
            "mode": "timing",
            "timeout_ms": 10000,
            "failure_policy": "fixed-attempts",
            "flush_grace_ms": 500,
            "pin_cores": False,
            "perf": False,
        },
        "technique": {"name": "unmodified-baseline"},
    }
    path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    return profile


def write_net_profile(path: Path) -> dict[str, object]:
    policy = {"delay_ms": 0, "loss_percent": 0.0, "limit_packets": 10000}
    profile = {
        "type": "turtle-netem-profile",
        "schema": 1,
        "qdisc": "netem",
        "mtu": 1500,
        "offload": {"tso": False, "gso": False, "gro": False},
        "trace": True,
        "loss_seed": None,
        "paths": {name: dict(policy) for name in sorted(TLS_PATHS)},
    }
    path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    return profile


def availability(header: dict[str, object], name: str) -> dict[str, object]:
    value = header.get("availability", {}).get(name)
    check(isinstance(value, dict), f"raw header lacks availability.{name}")
    check(set(value) == {"available", "reason"},
          f"availability.{name} schema changed: {value!r}")
    return value


def validate_role(raw: Path, role: str, framework_io: bool, mutual_auth: bool,
                  interpret: Path) -> dict[str, object]:
    rows = read_jsonl(raw)
    header = rows[0]
    check(header.get("type") == "sample" and header.get("schema") == 1,
          f"{raw}: wrong sample header")
    check(header.get("valid") is True, f"{raw}: invalid sample: {header.get('invalid_reason')}")
    declaration = header.get("declaration", {})
    check(declaration.get("is_mock") is False and declaration.get("library") == "OpenSSL",
          f"{raw}: test did not exercise the production OpenSSL adapter")
    check(declaration.get("callback_io") is framework_io,
          f"{raw}: adapter callback I/O declaration disagrees with the condition")
    check(header.get("observation_level") == ("L0" if framework_io else "library-only"),
          f"{raw}: observation level does not identify callback/native visibility")
    config = header.get("config", {})
    tls = config.get("tls", {})
    check(tls.get("framework_io") is framework_io and
          tls.get("mutual_auth") is mutual_auth and
          tls.get("tickets") == 0 and tls.get("application_bytes") == 32,
          f"{raw}: frozen I/O/auth/application configuration changed")
    check(config.get("warmups") == 0 and config.get("connections") == 1 and
          config.get("pin_cores") is False and config.get("perf") is False,
          f"{raw}: execution controls changed")
    connections = header.get("connections", [])
    check(len(connections) == 1, f"{raw}: expected one measured connection")
    connection = connections[0]
    negotiated = connection.get("negotiated", {})
    check(negotiated.get("version") == "TLS1.3" and
          negotiated.get("cipher") == "TLS_AES_128_GCM_SHA256" and
          negotiated.get("resumed") is False,
          f"{raw}: not a fresh TLS 1.3/AES-128-GCM handshake")
    check(connection.get("application_verified") is True,
          f"{raw}: encrypted 32-byte application exchange was not verified")
    expected_verification = "passed" if role == "client" or mutual_auth else "not_applicable"
    check(connection.get("verification") == expected_verification,
          f"{raw}: peer authentication result changed")

    stream = availability(header, "tls_stream")
    io_events = availability(header, "io_events")
    kernel = availability(header, "kernel_receive_events")
    if framework_io:
        check(stream == {"available": True, "reason": None} and
              io_events == {"available": True, "reason": None},
              f"{raw}: callback stream/I/O availability changed")
        kernel_expected = (
            {"available": True, "reason": None}
            if header.get("capabilities", {}).get("kernel_timestamp_configured") is True
            else {"available": False, "reason": "kernel_timestamps_not_configured"}
        )
        check(kernel == kernel_expected, f"{raw}: callback kernel receive availability changed")
    else:
        expected = {"available": False, "reason": NATIVE_REASON}
        check(stream == expected and io_events == expected and kernel == expected,
              f"{raw}: native unobserved data was not explicitly unavailable")
        if role == "server":
            check(connection.get("start_sequence") is None and
                  connection.get("primary_window") == {
                      "available": False,
                      "reason": "server_first_receive_not_observed",
                  }, f"{raw}: native server primary boundary was fabricated")

    decoded_path = raw.with_suffix(".decoded.json")
    interpreted = command_record([interpret, raw, decoded_path], timeout=10)
    require_success(interpreted)
    decoded = json.loads(decoded_path.read_text())
    decoded_connections = decoded.get("connections", [])
    check(len(decoded_connections) == 1, f"{raw}: decoded connection missing")
    decoded_connection = decoded_connections[0]
    decoded_stream = decoded_connection.get("availability", {}).get("tls_stream")
    check(decoded_stream == stream, f"{raw}: decoder changed stream availability")
    if framework_io:
        check(decoded_connection.get("decryption_complete") is True,
              f"{raw}: callback stream was not completely decrypted")
        for direction in ("client_sent", "server_sent"):
            names = [message.get("name") for message in
                     decoded_connection.get(direction, {}).get("messages", [])]
            check("Finished" in names and "ApplicationData" in names,
                  f"{raw}: callback decode lacks full handshake/application data")
    else:
        check(decoded_connection.get("decryption_complete") is False,
              f"{raw}: native empty stream was reported as successfully decrypted")
        for direction in ("client_sent", "server_sent"):
            value = decoded_connection.get(direction, {})
            check(value.get("availability") == {
                      "available": False, "reason": NATIVE_REASON,
                  } and value.get("decryption_complete") is False and
                  value.get("messages") == [] and value.get("records") == [],
                  f"{raw}: native {direction} was represented as observed data")
    return header


def validate_sample(sample: Path, framework_io: bool, mutual_auth: bool,
                    interpret: Path) -> None:
    check((sample / "director.txt").read_text().strip() == "valid",
          f"{sample}: parent director did not retain a valid child-pair outcome")
    check(not any((sample / name).exists() for name in
                  ("ca.jsonl", "lookup.jsonl", "lookup-summary.json", "snapshot.json")),
          f"{sample}: lookup=false run synthesized CA/lookup artifacts")
    validate_role(sample / "client.jsonl", "client", framework_io, mutual_auth, interpret)
    validate_role(sample / "server.jsonl", "server", framework_io, mutual_auth, interpret)
    for connection in (0,):
        pairs = (("client", "server"), ("server", "client"))
        for source, destination in pairs:
            sent_path = sample / f"{source}.conn-{connection}.sent.bin"
            received_path = sample / f"{destination}.conn-{connection}.received.bin"
            check(sent_path.is_file() and received_path.is_file(),
                  f"{sample}: directional stream artifact missing")
            sent, received = sent_path.read_bytes(), received_path.read_bytes()
            if framework_io:
                check(bool(sent) and sent == received,
                      f"{sample}: callback directional TLS stream differs")
            else:
                check(sent == b"" and received == b"",
                      f"{sample}: native mode fabricated framework TLS stream bytes")


def run_report(report: Path, source: Path, destination: Path,
               commands: list[dict[str, object]]) -> dict[str, object]:
    record = command_record([report, source, destination], timeout=20)
    commands.append(record)
    require_success(record)
    summary = json.loads((destination / "summary.json").read_text())
    check(summary.get("invalid_samples") == 0,
          f"{destination}: report rejected a successful real TLS sample")
    return summary


def validate_report_availability(summary: dict[str, object], samples_per_condition: int) -> None:
    samples = summary.get("samples", [])
    for sample in samples:
        check(sample.get("valid") is True and len(sample.get("connections", [])) == 1,
              "report lost a functionally valid TLS connection")
        connection = sample["connections"][0]
        native = any(part == "native" or part.startswith("native-")
                     for part in Path(sample.get("path", "")).parts)
        role = sample.get("role")
        if not native:
            check(connection.get("primary_window") == {"available": True, "reason": None} and
                  connection.get("io_breakdown") == {"available": True, "reason": None},
                  "callback report lost its observed primary/I/O breakdown")
            continue
        check(connection.get("io_breakdown") == {
                  "available": False, "reason": "io_events_not_observed",
              } and all(connection.get(name) is None
                        for name in ("computation_ns", "io_ns", "wait_ns", "gap_ns")),
              "native unobserved I/O decomposition was reported as numeric data")
        if role == "client":
            check(connection.get("primary_window") == {"available": True, "reason": None} and
                  isinstance(connection.get("elapsed_ns"), int) and
                  isinstance(connection.get("thread_cpu_ns"), int),
                  "native client call boundary was not retained")
        else:
            check(connection.get("primary_window") == {
                      "available": False, "reason": "server_first_receive_not_observed",
                  } and connection.get("elapsed_ns") is None and
                  connection.get("thread_cpu_ns") is None,
                  "native server primary values were fabricated")

    native_groups = [group for group in summary.get("groups", [])
                     if group.get("dimensions", {}).get("observation_level") == "library-only"]
    check(bool(native_groups), "report did not preserve native observation-level groups")
    for group in native_groups:
        role = group["dimensions"].get("role")
        metrics = group.get("metrics", {})
        check(group.get("automatic_comparison_eligible") is False,
              "callback/native result was promoted to automatic performance comparison")
        if role == "client":
            check(metrics.get("elapsed_ns", {}).get("count") == samples_per_condition and
                  metrics.get("thread_cpu_ns", {}).get("count") == samples_per_condition and
                  not any(name in metrics for name in
                          ("computation_ns", "io_ns", "wait_ns", "gap_ns")),
                  "native client report synthesized I/O decomposition metrics")
        else:
            check("elapsed_ns" not in metrics and "thread_cpu_ns" not in metrics,
                  "native server report synthesized primary metrics")


def normal(args: argparse.Namespace, root: Path, manifest: dict[str, object]) -> None:
    inputs, runs = root / "inputs", root / "runs"
    inputs.mkdir()
    runs.mkdir()
    for framework_io, io_name in ((True, "callback"), (False, "native")):
        for mutual_auth, auth_name in ((False, "serverauth"), (True, "mtls")):
            name = f"{io_name}-{auth_name}"
            profile = inputs / f"{name}.json"
            write_profile(profile, args.pki, framework_io, mutual_auth, 1)
            output = runs / name
            record = command_record([
                args.turtle, "run", "--profile", profile,
                "--client", "openssl", "--server", "openssl",
                "--adapter-dir", args.adapters, "--output", output,
            ], timeout=20)
            manifest["commands"].append(record)
            require_success(record)
            samples = sorted(output.glob("sample-*"))
            check(len(samples) == 1, f"{output}: sample denominator changed")
            rows = read_jsonl(output / "attempts.jsonl")
            final = [row for row in rows if row.get("record_kind") == "attempt_final"]
            summaries = [row for row in rows if row.get("record_kind") == "run_summary"]
            check(len(final) == 1 and final[0].get("final_status") == "success" and
                  final[0].get("artifacts") == {
                      "client.jsonl": "complete", "server.jsonl": "complete",
                  } and len(summaries) == 1 and
                  summaries[0].get("requested") == summaries[0].get("started") ==
                  summaries[0].get("success") == 1,
                  f"{output}: parent attempt/artifact ledger is incomplete")
            validate_sample(samples[0], framework_io, mutual_auth, args.interpret)
    summary = run_report(args.report, runs, root / "report", manifest["commands"])
    check(len(summary.get("samples", [])) == 8,
          "normal report omitted an I/O path, authentication mode, or endpoint role")
    validate_report_availability(summary, 1)
    manifest["status"] = "complete"
    manifest["scope"] = {
        "conditions": 4,
        "actual_tls": True,
        "application_bytes": 32,
        "ciphertext_or_timing_equality_required": False,
    }


def validate_ledger(output: Path) -> None:
    rows = read_jsonl(output / "attempts.jsonl")
    config = [row for row in rows if row.get("record_kind") == "run_config"]
    started = [row for row in rows if row.get("record_kind") == "attempt_started"]
    final = [row for row in rows if row.get("record_kind") == "attempt_final"]
    summary = [row for row in rows if row.get("record_kind") == "run_summary"]
    check(len(config) == 1 and config[0].get("requested_count") == SAMPLES,
          f"{output}: requested attempt denominator missing")
    check([row.get("attempt_id") for row in started] == [1, 2] and
          [row.get("attempt_id") for row in final] == [1, 2] and
          all(row.get("final_status") == "success" for row in final),
          f"{output}: two successful actual TLS attempts were not preserved")
    check(len(summary) == 1 and all(summary[0].get(key) == value for key, value in {
        "requested": 2, "started": 2, "success": 2,
        "timeout": 0, "error": 0, "not_attempted": 0,
    }.items()), f"{output}: attempt summary is incomplete")
    expected_ids = [[f"{attempt}:{phase}:{edge}" for phase, edge in PHASES]
                    for attempt in (1, 2)]
    check([row.get("network_observation_ids") for row in final] == expected_ids,
          f"{output}: six-phase observation references changed")


def packet_windows(rows: list[dict[str, object]]) -> dict[int, list[dict[str, object]]]:
    windows: dict[int, list[dict[str, object]]] = {}
    active: int | None = None
    for row in rows:
        if row.get("record_kind") == "marker" and row.get("kind") == "phase":
            if row.get("phase") == "scenario" and row.get("edge") == "begin":
                active = int(row["attempt"])
                windows[active] = []
            elif row.get("phase") == "scenario" and row.get("edge") == "end":
                check(active == row.get("attempt"), "packet scenario markers are out of order")
                active = None
        elif active is not None and row.get("record_kind") == "packet":
            windows[active].append(row)
    check(active is None and set(windows) == {1, 2},
          "packet trace lacks two bounded scenario observer-read-time windows")
    return windows


def validate_network(output: Path) -> dict[str, object]:
    manifest = json.loads((output / "network-manifest.json").read_text())
    provenance = json.loads((output / "network-provenance.json").read_text())
    identity = provenance.get("condition_identity", {})
    check(provenance.get("status") == "complete" and
          provenance.get("director", {}).get("returncode") == 0,
          f"{output}: coordinator did not complete")
    check(set(manifest.get("namespace_fds", {})) == {"client", "server"} and
          set(manifest.get("addresses", {})) == {"client_tls", "server"},
          f"{output}: lookup=false pure TLS topology changed")
    check(identity.get("topology", {}).get("kind") ==
          "three-netns-receiver-facing-router-egress",
          f"{output}: wrong router observation topology")
    requested = identity.get("requested", {})
    actual = identity.get("actual", {})
    check(requested.get("trace") is True and requested.get("mtu") == 1500 and
          requested.get("offload") == {"tso": False, "gso": False, "gro": False},
          f"{output}: requested trace/MTU/offload identity changed")
    check(set(requested.get("paths", {})) == TLS_PATHS and
          set(actual.get("paths", {})) == TLS_PATHS and
          set(provenance.get("applied_qdisc_readback", {})) == TLS_PATHS,
          f"{output}: requested/actual TLS-only qdisc identity missing")
    for path in TLS_PATHS:
        check(requested["paths"][path] == {
            "delay_ms": 0, "loss_percent": 0.0, "limit_packets": 10000,
        }, f"{output}: {path} is not the frozen zero-delay/zero-loss policy")
        observed = actual["paths"][path]
        check(observed.get("kind") == "netem" and observed.get("delay_ms") == 0 and
              observed.get("loss_percent") == 0 and observed.get("limit_packets") == 10000,
              f"{output}: {path} qdisc readback differs")
    check(identity.get("mtu", {}).get("actual") and identity.get("offload", {}).get("actual"),
          f"{output}: actual MTU/offload readback missing")

    observations = read_jsonl(output / "network-observations.jsonl")
    expected_ids = [f"{attempt}:{phase}:{edge}" for attempt in (1, 2)
                    for phase, edge in PHASES]
    check([row.get("observation_id") for row in observations] == expected_ids,
          f"{output}: canonical six phase observations changed")

    rows = read_jsonl(output / "packets.jsonl")
    headers = [row for row in rows if row.get("record_kind") == "header"]
    footers = [row for row in rows if row.get("record_kind") == "footer"]
    check(len(headers) == 1 and headers[0].get("observation_point") == "router-veth-af_packet" and
          headers[0].get("packet_unit") == "observed-skb-not-physical-wire" and
          set(headers[0].get("interfaces", [])) == {"rctls", "rstls"},
          f"{output}: packet trace observation boundary changed")
    check(len(footers) == 1, f"{output}: capture footer missing or duplicated")
    capture_stats = footers[0].get("capture_socket_statistics", {})
    check(set(capture_stats) == {"rctls", "rstls"} and
          all(isinstance(item.get("packets"), int) and isinstance(item.get("drops"), int)
              for item in capture_stats.values()),
          f"{output}: capture support/drop statistics unavailable")
    check(all(item["drops"] == 0 for item in capture_stats.values()),
          f"{output}: capture socket reported dropped skb observations")

    expected = {
        "tls_c2s": ("rstls", "10.203.1.2", "10.203.2.2"),
        "tls_s2c": ("rctls", "10.203.2.2", "10.203.1.2"),
    }
    totals = {path: {"observed_skb_count": 0, "payload_byte_sum": 0} for path in TLS_PATHS}
    for attempt, packet_rows in packet_windows(rows).items():
        selected: dict[str, list[dict[str, object]]] = {}
        for path, (interface, source, destination) in expected.items():
            selected[path] = [row for row in packet_rows
                              if row.get("logical_path") == path and
                              row.get("interface") == interface and
                              row.get("direction") == "egress" and
                              row.get("packet_unit") == "observed-skb-not-physical-wire" and
                              row.get("flow", {}).get("source") == source and
                              row.get("flow", {}).get("destination") == destination and
                              row.get("flow", {}).get("protocol") == "tcp" and
                              row.get("tcp", {}).get("payload_length", 0) > 0]
            check(bool(selected[path]),
                  f"{output}: attempt {attempt} lacks {path} receiver-facing outgoing payload")
        c2s_flows = {(
            row["flow"]["source_port"], row["flow"]["destination_port"]
        ) for row in selected["tls_c2s"]}
        s2c_flows = {(
            row["flow"]["destination_port"], row["flow"]["source_port"]
        ) for row in selected["tls_s2c"]}
        check(len(c2s_flows) == 1 and c2s_flows == s2c_flows,
              f"{output}: attempt {attempt} payload does not share one bidirectional TLS 4-tuple")
        for path in TLS_PATHS:
            totals[path]["observed_skb_count"] += len(selected[path])
            totals[path]["payload_byte_sum"] += sum(
                row["tcp"]["payload_length"] for row in selected[path]
            )

    check(provenance.get("host_network_identity", {}).get("unchanged") is True,
          f"{output}: host network identity was not proved unchanged")
    lifecycle = provenance.get("lifecycle", {})
    check(lifecycle.get("namespace_fds_closed") is True and
          lifecycle.get("owned_pipe_fds_closed") is True,
          f"{output}: owned descriptors were not proved closed")
    helper_cleanup = {row.get("helper"): row.get("result")
                      for row in provenance.get("cleanup", []) if "helper" in row}
    check(helper_cleanup == {"client": "reaped", "server": "reaped", "router": "reaped"},
          f"{output}: owned helpers were not all reaped")
    return {"selected": totals, "capture_socket_statistics": capture_stats}


def external(args: argparse.Namespace, root: Path, manifest: dict[str, object]) -> int:
    inputs, runs = root / "inputs", root / "runs"
    inputs.mkdir()
    runs.mkdir()
    if not external_support_preflight(manifest):
        manifest.update(status="unsupported", reason=(
            "external setup preflight is unsupported; this skip is not M6 success: "
            f"{manifest['support_preflight']['reason']}"
        ))
        return 77
    net_profile = inputs / "loss0-delay0-trace.json"
    frozen_net = write_net_profile(net_profile)
    comparison: dict[str, object] = {
        "type": "turtle-io-path-external-observation",
        "schema": 1,
        "timestamp_semantics": "user-space observer/decode read time",
        "phase_selection": "approximate observer-read-time scenario window",
        "packet_unit": "observed skb, not a physical packet",
        "payload_sum_semantics": "not unique TLS bytes; retransmission and segmentation may repeat bytes",
        "cross_mode_equality_required": False,
        "runs": {},
    }
    build = args.turtle.resolve().parent
    check((build / "adapters").resolve() == args.adapters.resolve(),
          "netem runner build/adapters path disagrees with --adapters")
    for framework_io, io_name in ((True, "callback"), (False, "native")):
        profile = inputs / f"{io_name}.json"
        written = write_profile(profile, args.pki, framework_io, False, SAMPLES)
        check(written["lookup"] == {"enabled": False}, "external profile enabled lookup")
        output = runs / io_name
        record = command_record([
            sys.executable, args.netem, "run", "--build", build,
            "--profile", profile, "--net-profile", net_profile,
            "--samples", str(SAMPLES), "--output", output,
        ], timeout=80)
        manifest["commands"].append(record)
        if record["exit_code"] == 2:
            provenance_path = output / "network-provenance.json"
            provenance = (json.loads(provenance_path.read_text())
                          if provenance_path.is_file() else {})
            if provenance.get("status") == "unsupported" and provenance.get("reason"):
                manifest.update(status="unsupported", reason=(
                    "existing netem runner reported setup unsupported; this skip is not M6 "
                    f"success: {provenance['reason']}"
                ))
                return 77
            if unshare_capability_failure(record):
                manifest.update(status="unsupported", reason=(
                    "existing netem runner was explicitly denied rootless namespace setup; "
                    "this skip is not M6 success"
                ))
                return 77
        require_success(record)
        validate_ledger(output)
        network = validate_network(output)
        samples = sorted(output.glob("sample-*"))
        check(len(samples) == SAMPLES, f"{output}: sample denominator changed")
        for sample in samples:
            validate_sample(sample, framework_io, False, args.interpret)
        comparison["runs"][io_name] = network

    report_summary = run_report(args.report, runs, root / "report", manifest["commands"])
    check(len(report_summary.get("samples", [])) == 2 * SAMPLES * 2,
          "external report omitted an I/O path, attempt, or endpoint role")
    validate_report_availability(report_summary, SAMPLES)
    check(all(sample.get("network_integrity", {}).get("status") == "complete" and
              sample.get("network_integrity", {}).get("eligible") is True and
              sample.get("network_integrity", {}).get("reasons") == []
              for sample in report_summary.get("samples", [])),
          "report common network reader rejected complete pure TLS evidence")
    comparison["frozen_network_profile"] = frozen_net
    (root / "external-observation.json").write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n"
    )
    manifest.update(status="complete", scope={
        "actual_tls": True,
        "external_observation": "router AF_PACKET skb metadata",
        "full_pcap_or_syscall_or_physical_wire_capture": False,
    })
    return 0


def main() -> int:
    args = parse_args()
    for name in ("turtle", "report", "interpret", "netem"):
        check(getattr(args, name).is_file(), f"--{name} path is not a file")
    check((args.adapters / "openssl.so").is_file(), "OpenSSL adapter is unavailable")
    check(args.pki.is_dir(), "PKI directory is unavailable")
    root = unique_run_directory(args.output, args.mode)
    manifest: dict[str, object] = {
        "type": "turtle-io-path-test-run",
        "schema": 1,
        "mode": args.mode,
        "status": "running",
        "commands": [],
    }
    manifest_path = root / "run-manifest.json"
    try:
        if args.mode == "normal":
            normal(args, root, manifest)
            result = 0
        else:
            result = external(args, root, manifest)
        return result
    except Exception as error:
        manifest.update(status="failed", reason=str(error))
        raise
    finally:
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"I/O path artifacts retained: {root}", file=sys.stderr)
        if manifest.get("status") == "complete":
            print(f"PASS io_path {args.mode}: real callback/native TLS evidence")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL io_path: {error}", file=sys.stderr)
        raise
