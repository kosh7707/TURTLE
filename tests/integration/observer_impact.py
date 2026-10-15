#!/usr/bin/env python3
"""Exercise the real callback path with the channel observer alternately on and off."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import statistics
import subprocess
import time


SAMPLES = 2
BATCH_ORDER = ((True, False), (False, True), (True, False), (False, True))
COMMON = "handshake_call_begin_to_application_complete"
OFF_REASON = "channel_observer_disabled"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--turtle", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--interpret", type=Path, required=True)
    parser.add_argument("--adapters", type=Path, required=True)
    parser.add_argument("--pki", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def unique_directory(parent: Path) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    stem = f"normal-{time.time_ns()}-{os.getpid()}"
    for suffix in range(100):
        candidate = parent / (stem if suffix == 0 else f"{stem}-{suffix}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            pass
    raise RuntimeError("could not allocate a unique retained observer-impact directory")


def run(argv: list[object], timeout: int) -> dict[str, object]:
    command = [str(item) for item in argv]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    record: dict[str, object] = {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return record


def profile_document(pki: Path, observer: bool) -> dict[str, object]:
    return {
        "name": "openssl-channel-observer-impact",
        "pki": str(pki.resolve()),
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
        "lookup": {"enabled": False},
        "measurement": {
            "samples": SAMPLES,
            "warmups": 0,
            "connections": 1,
            "mode": "timing",
            "timeout_ms": 10000,
            "failure_policy": "fixed-attempts",
            "flush_grace_ms": 500,
            "pin_cores": False,
            "perf": False,
            "kernel_timestamps": True,
            "isolate": True,
            "event_capacity": 32768,
            "stream_capacity": 1048576,
            "keylog_capacity": 262144,
            "calibration_samples": 64,
            "channel_observer": observer,
        },
        "technique": {"name": "unmodified-baseline"},
    }


def normalized_profile(profile: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(profile)
    del value["measurement"]["channel_observer"]  # type: ignore[index]
    return value


def read_jsonl(path: Path) -> list[dict[str, object]]:
    check(path.is_file(), f"missing retained raw file: {path}")
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    check(bool(rows), f"empty retained raw file: {path}")
    return rows


def availability(header: dict[str, object], name: str) -> dict[str, object]:
    item = header.get("availability", {}).get(name)  # type: ignore[union-attr]
    check(isinstance(item, dict) and set(item) == {"available", "reason"},
          f"availability.{name} is absent or malformed")
    return item


def recompute_common(rows: list[dict[str, object]], role: str) -> dict[str, int]:
    events = [row for row in rows if row.get("type") == "event" and
              row.get("connection") == 0]
    starts = [row for row in events if row.get("kind") == "CALL_BEGIN" and
              row.get("call") == "handshake"]
    target = "app_recv" if role == "client" else "app_send"
    expected = int(rows[0]["config"]["tls"]["application_bytes"])
    transferred = 0
    end = None
    active = False
    for event in events:
        if event.get("call") != target:
            continue
        if event.get("kind") == "CALL_BEGIN":
            check(not active, f"{role}: overlapping {target} calls")
            active = True
        elif event.get("kind") == "CALL_END":
            check(active and isinstance(event.get("transferred"), int),
                  f"{role}: malformed {target} completion")
            active = False
            transferred += event["transferred"]
            check(transferred <= expected, f"{role}: application progress exceeds request")
            if transferred == expected:
                check(event.get("result") == 2 and event["transferred"] > 0,
                      f"{role}: full application progress did not complete successfully")
                end = event
    check(bool(starts) and end is not None and transferred == expected and not active,
          f"{role}: raw events lack handshake begin or completed {target}")
    start = min(starts, key=lambda row: row["sequence"])
    check(start["sequence"] < end["sequence"], f"{role}: common window is reversed")
    elapsed = end["monotonic_ns"] - start["monotonic_ns"]
    cpu = end["thread_cpu_ns"] - start["thread_cpu_ns"]
    check(elapsed > 0 and cpu >= 0, f"{role}: invalid raw common-window difference")
    return {
        "start_event_sequence": start["sequence"],
        "end_event_sequence": end["sequence"],
        "elapsed_ns": elapsed,
        "thread_cpu_ns": cpu,
    }


def validate_decoded(decoded: dict[str, object], observer: bool, raw: Path) -> None:
    connections = decoded.get("connections", [])
    check(isinstance(connections, list) and len(connections) == 1,
          f"{raw}: decoded connection missing")
    connection = connections[0]
    expected = ({"available": True, "reason": None} if observer else
                {"available": False, "reason": OFF_REASON})
    check(connection.get("availability", {}).get("tls_stream") == expected,
          f"{raw}: decoder changed observer stream availability")
    if observer:
        check(connection.get("decryption_complete") is True,
              f"{raw}: observed TLS stream did not decode completely")
        for direction in ("client_sent", "server_sent"):
            messages = connection.get(direction, {}).get("messages", [])
            names = [message.get("name") for message in messages]
            check("Finished" in names and "ApplicationData" in names,
                  f"{raw}: observed {direction} lacks handshake/application records")
    else:
        check(connection.get("decryption_complete") is False,
              f"{raw}: disabled observer was decoded as a complete empty stream")
        for direction in ("client_sent", "server_sent"):
            item = connection.get(direction, {})
            check(item.get("availability") == expected and item.get("messages") == [] and
                  item.get("records") == [] and item.get("decryption_complete") is False,
                  f"{raw}: disabled {direction} was represented as observed data")


def validate_role(raw: Path, role: str, observer: bool, batch: int, interpret: Path,
                  commands: list[dict[str, object]]) -> dict[str, object]:
    rows = read_jsonl(raw)
    header = rows[0]
    check(header.get("type") == "sample" and header.get("valid") is True,
          f"{raw}: invalid real TLS sample")
    declaration = header.get("declaration", {})
    check(declaration.get("is_mock") is False and declaration.get("library") == "OpenSSL" and
          declaration.get("callback_io") is True,
          f"{raw}: run did not use production OpenSSL callback I/O")
    check(declaration.get("key_log") is True and declaration.get("plaintext_hook") is True,
          f"{raw}: fixed keylog/plaintext adapter capabilities changed")
    config = header.get("config", {})
    check(header.get("batch") == batch and config.get("batch") == batch,
          f"{raw}: raw sample did not retain the requested batch identifier")
    check(config.get("channel_observer") is observer and config.get("mode") == "timing" and
          config.get("perf") is False and config.get("pin_cores") is False and
          config.get("warmups") == 0 and config.get("connections") == 1 and
          config.get("stream_capacity", 0) > 0 and config.get("keylog_capacity", 0) > 0,
          f"{raw}: observer or fixed measurement controls changed")
    tls = config.get("tls", {})
    check(tls.get("framework_io") is True and tls.get("mutual_auth") is False and
          tls.get("cipher") == "TLS_AES_128_GCM_SHA256" and
          tls.get("tickets") == 0 and tls.get("application_bytes") == 32,
          f"{raw}: frozen TLS condition changed")
    connections = header.get("connections", [])
    check(len(connections) == 1 and connections[0].get("application_verified") is True and
          connections[0].get("verification") ==
          ("passed" if role == "client" else "not_applicable"),
          f"{raw}: authenticated encrypted application exchange failed")
    negotiated = connections[0].get("negotiated", {})
    check(negotiated.get("version") == "TLS1.3" and
          negotiated.get("cipher") == "TLS_AES_128_GCM_SHA256" and
          negotiated.get("resumed") is False,
          f"{raw}: connection was not a fresh TLS 1.3 AES-128 exchange")
    primary = connections[0].get("primary_window")
    if role == "server" and not observer:
        check(connections[0].get("start_sequence") is None and primary == {
                  "available": False, "reason": "server_first_receive_not_observed",
              }, f"{raw}: observer-off server fabricated its first-receive primary boundary")
    else:
        check(primary == {"available": True, "reason": None},
              f"{raw}: available primary boundary was lost")
    capabilities = header.get("capabilities", {})
    socket = connections[0].get("socket", {})
    check(capabilities.get("kernel_timestamp_configured") is True and
          socket.get("kernel_timestamps") is True and
          isinstance(socket.get("send_buffer"), int) and socket.get("send_buffer") > 0 and
          isinstance(socket.get("receive_buffer"), int) and socket.get("receive_buffer") > 0,
          f"{raw}: configured timestamp or actual socket readback changed")

    expected_availability = ({"available": True, "reason": None} if observer else
                             {"available": False, "reason": OFF_REASON})
    for name in ("tls_stream", "io_events", "kernel_receive_events"):
        check(availability(header, name) == expected_availability,
              f"{raw}: {name} availability disagrees with observer flag")
    kinds = [row.get("kind") for row in rows if row.get("type") == "event"]
    check("CALL_BEGIN" in kinds and "CALL_END" in kinds and
          "WAIT_BEGIN" in kinds and "WAIT_END" in kinds,
          f"{raw}: call/wait boundary capture was not preserved")
    io_kinds = {"IO_SEND_ENTER", "IO_SEND_RETURN", "IO_RECV_ENTER", "IO_RECV_RETURN",
                "KERNEL_RX"}
    check(any(kind in io_kinds for kind in kinds) is observer,
          f"{raw}: transport observation events disagree with observer flag")
    if role == "server" and observer:
        successful_receives = [row for row in rows if row.get("type") == "event" and
                               row.get("connection") == 0 and
                               row.get("kind") == "IO_RECV_RETURN" and
                               row.get("result") == 0 and row.get("transferred", 0) > 0]
        check(bool(successful_receives) and connections[0].get("start_sequence") ==
              min(row["sequence"] for row in successful_receives),
              f"{raw}: server primary did not start at first successful receive")
    for suffix in ("keys.log", "plaintext.bin", "plaintext.jsonl"):
        check((raw.parent / f"{role}.{suffix}").is_file(),
              f"{raw}: fixed {suffix} artifact was not retained")
    check((raw.parent / f"{role}.keys.log").stat().st_size > 0,
          f"{raw}: configured key log was unexpectedly empty")
    sent = raw.parent / f"{role}.conn-0.sent.bin"
    received = raw.parent / f"{role}.conn-0.received.bin"
    check(sent.is_file() and received.is_file(), f"{raw}: stream artifacts missing")
    check((bool(sent.read_bytes()) and bool(received.read_bytes())) if observer else
          (sent.read_bytes() == b"" and received.read_bytes() == b""),
          f"{raw}: stream bytes disagree with observer availability")

    raw_common = recompute_common(rows, role)
    decoded_path = raw.with_suffix(".decoded.json")
    commands.append(run([interpret, raw, decoded_path], timeout=10))
    validate_decoded(json.loads(decoded_path.read_text()), observer, raw)
    return {
        "raw": str(raw),
        "framework_version": header.get("framework_version"),
        "library_version": declaration.get("version"),
        "profile_hash": header.get("profile_hash"),
        "socket_readback": socket,
        **raw_common,
    }


def validate_ledger(output: Path) -> None:
    rows = read_jsonl(output / "attempts.jsonl")
    config = [row for row in rows if row.get("record_kind") == "run_config"]
    started = [row for row in rows if row.get("record_kind") == "attempt_started"]
    final = [row for row in rows if row.get("record_kind") == "attempt_final"]
    summary = [row for row in rows if row.get("record_kind") == "run_summary"]
    check(len(config) == 1 and config[0].get("requested_count") == SAMPLES,
          f"{output}: per-run requested denominator is missing")
    check([row.get("attempt_id") for row in started] == [1, 2] and
          [row.get("attempt_id") for row in final] == [1, 2] and
          all(row.get("final_status") == "success" and row.get("artifacts") == {
              "client.jsonl": "complete", "server.jsonl": "complete",
          } for row in final), f"{output}: attempt ledger is incomplete")
    check(len(summary) == 1 and all(summary[0].get(key) == value for key, value in {
        "requested": 2, "started": 2, "success": 2, "timeout": 0,
        "error": 0, "not_attempted": 0,
    }.items()), f"{output}: run denominator changed")
    check(all("batch" not in row for row in rows),
          f"{output}: attempt ledger unexpectedly expanded its per-run schema with batch")


def distribution(values: list[int]) -> dict[str, object]:
    check(bool(values), "cannot summarize an empty diagnostic distribution")
    return {"count": len(values), "values": values, "minimum": min(values),
            "maximum": max(values), "mean": statistics.fmean(values)}


def report_common(summary: dict[str, object], raw_values: dict[tuple[str, bool], list[dict[str, object]]]) -> None:
    check(summary.get("invalid_samples") == 0 and len(summary.get("samples", [])) == 32,
          "report omitted or invalidated one of 32 retained endpoint-role samples")
    for sample in summary["samples"]:
        check(sample.get("valid") is True and len(sample.get("connections", [])) == 1,
              "report lost a valid measured connection")
        common = sample["connections"][0].get(COMMON)
        check(isinstance(common, dict) and common.get("definition") == COMMON and
              common.get("available") is True and common.get("reason") is None and
              common.get("thread_cpu_reason") is None,
              "report common-window availability/schema changed")
        path = Path(sample["path"])
        observer = "observer-on" in path.parts
        role = sample["role"]
        candidates = raw_values[(role, observer)]
        match = next((item for item in candidates
                      if Path(item["raw"]).resolve() == path.resolve()), None)
        check(match is not None, f"{path}: report sample cannot be matched to retained raw data")
        for key in ("start_event_sequence", "end_event_sequence", "elapsed_ns", "thread_cpu_ns"):
            check(common.get(key) == match[key], f"{path}: report {COMMON}.{key} was not raw-recomputed")
        connection = sample["connections"][0]
        if observer:
            check(connection.get("io_breakdown") == {"available": True, "reason": None},
                  f"{path}: observer-on report lost its I/O breakdown")
            if role == "server":
                check(connection.get("primary_window") == {"available": True, "reason": None},
                      f"{path}: observer-on server lost its first-receive primary window")
        else:
            check(connection.get("io_breakdown") == {
                      "available": False, "reason": "io_events_not_observed",
                  } and all(connection.get(field) is None for field in
                            ("computation_ns", "io_ns", "wait_ns", "gap_ns")),
                  f"{path}: observer-off I/O decomposition was fabricated")
            if role == "server":
                check(connection.get("primary_window") == {
                          "available": False,
                          "reason": "server_first_receive_not_observed",
                      } and connection.get("elapsed_ns") is None and
                      connection.get("thread_cpu_ns") is None,
                      f"{path}: observer-off server primary values were fabricated")

    groups = summary.get("groups", [])
    selected: dict[tuple[str, bool], dict[str, object]] = {}
    for group in groups:
        dimensions = group.get("dimensions", {})
        controls = dimensions.get("run_controls", {})
        observer = controls.get("channel_observer")
        role = dimensions.get("role")
        if isinstance(observer, bool) and role in ("client", "server"):
            selected[(role, observer)] = group
    check(set(selected) == set(raw_values),
          "report did not keep role and channel_observer as distinct group identity")
    for key, group in selected.items():
        metadata = group.get(COMMON, {})
        check(metadata.get("definition") == COMMON,
              f"{key}: group lacks named common-window metadata")
        if key[1] is False:
            check(group.get("automatic_comparison_eligible") is False,
                  f"{key}: observer-off group entered primary automatic comparisons")
        metrics = group.get("metrics", {})
        for field in ("elapsed_ns", "thread_cpu_ns"):
            metric = metrics.get(f"{COMMON}_{field}", {})
            expected = sorted(item[field] for item in raw_values[key])
            check(metric.get("count") == 8 and sorted(metric.get("values", [])) == expected,
                  f"{key}: grouped {field} distribution differs from raw recomputation")
        if key == ("server", False):
            check("elapsed_ns" not in metrics and "thread_cpu_ns" not in metrics and
                  group.get("automatic_comparison_eligible") is False,
                  "observer-off server common window fabricated a primary window")


def main() -> int:
    args = parse_args()
    for name in ("turtle", "report", "interpret"):
        check(getattr(args, name).is_file(), f"--{name} path is not a file")
    check((args.adapters / "openssl.so").is_file(), "OpenSSL adapter is unavailable")
    check(args.pki.is_dir(), "PKI directory is unavailable")
    root = unique_directory(args.output)
    inputs, runs = root / "inputs", root / "runs"
    inputs.mkdir()
    runs.mkdir()
    manifest: dict[str, object] = {
        "type": "turtle-observer-impact-test-run", "schema": 1,
        "status": "running", "batch_order": [], "commands": [], "profiles": [],
        "scope": {
            "actual_tls": True,
            "interpretation": "callback channel-observer toggle impact diagnostic",
            "uninstrumented_run": False,
            "complete_overhead_correction": False,
            "performance_sign_or_magnitude_or_significance_acceptance": False,
            "wsl_performance_conclusion": False,
            "network": "local TCP; no netem or MTU change is performed",
        },
    }
    manifest_path = root / "run-manifest.json"
    raw_values = {(role, observer): [] for role in ("client", "server")
                  for observer in (True, False)}
    profiles: list[dict[str, object]] = []
    run_argvs: list[list[str]] = []
    try:
        manifest["commands"].append(run([args.turtle, "capabilities"], timeout=10))
        ordinal = 0
        for batch, pair in enumerate(BATCH_ORDER, start=1):
            batch_entry = {"batch": batch, "order": ["on" if item else "off" for item in pair]}
            manifest["batch_order"].append(batch_entry)
            for position, observer in enumerate(pair, start=1):
                ordinal += 1
                mode_name = "observer-on" if observer else "observer-off"
                name = f"batch-{batch:02d}-position-{position}-{mode_name}"
                profile = profile_document(args.pki, observer)
                profiles.append(profile)
                profile_path = inputs / f"{name}.json"
                profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
                output = runs / f"batch-{batch:02d}" / mode_name
                command = [
                    args.turtle, "run", "--profile", profile_path,
                    "--client", "openssl", "--server", "openssl",
                    "--adapter-dir", args.adapters, "--batch", str(batch),
                    "--output", output,
                ]
                run_argvs.append([str(item) for item in command])
                profile_record = {
                    "ordinal": ordinal, "batch": batch, "position": position,
                    "channel_observer": observer, "path": str(profile_path),
                    "document": profile,
                }
                manifest["profiles"].append(profile_record)
                manifest["commands"].append(run(command, timeout=30))
                retained_argv = manifest["commands"][-1]["argv"]
                batch_index = retained_argv.index("--batch")
                check(retained_argv[batch_index + 1] == str(profile_record["batch"]),
                      f"{output}: run manifest argv and batch ordering metadata disagree")
                validate_ledger(output)
                samples = sorted(output.glob("sample-*"))
                check(len(samples) == SAMPLES, f"{output}: expected two retained samples")
                for sample in samples:
                    check((sample / "director.txt").read_text().strip() == "valid",
                          f"{sample}: child-pair outcome is invalid")
                    for role in ("client", "server"):
                        raw_values[(role, observer)].append(validate_role(
                            sample / f"{role}.jsonl", role, observer, batch, args.interpret,
                            manifest["commands"],
                        ))

        baseline = normalized_profile(profiles[0])
        check(all(normalized_profile(profile) == baseline for profile in profiles),
              "normalized input profiles differ by more than measurement.channel_observer")
        def normalized_argv(argv: list[str]) -> list[str]:
            normalized = list(argv)
            for option in ("--profile", "--batch", "--output"):
                index = normalized.index(option)
                normalized[index + 1] = f"<{option[2:]}>"
            return normalized
        check(all(normalized_argv(argv) == normalized_argv(run_argvs[0])
                  for argv in run_argvs),
              "run argv differs by more than input/execution identifiers")
        socket_readbacks = {
            json.dumps(item["socket_readback"], sort_keys=True)
            for records in raw_values.values() for item in records
        }
        check(len(socket_readbacks) == 1,
              "actual socket/timestamp readback differs across observer conditions")
        framework_versions = {
            item["framework_version"] for records in raw_values.values() for item in records
        }
        library_versions = {
            item["library_version"] for records in raw_values.values() for item in records
        }
        check(len(framework_versions) == 1 and
              all(isinstance(value, str) and value for value in framework_versions),
              "framework version is missing or differs across observer conditions")
        check(len(library_versions) == 1 and
              all(isinstance(value, str) and value for value in library_versions),
              "OpenSSL version is missing or differs across observer conditions")
        manifest["versions"] = {
            "source": "actual endpoint-role raw sample headers",
            "validated_across_endpoint_role_raw_files": 32,
            "framework": next(iter(framework_versions)),
            "libraries": [{
                "name": "OpenSSL",
                "version": next(iter(library_versions)),
            }],
        }
        manifest["normalized_input_equality"] = {
            "equal": True,
            "excluded_profile_field": "measurement.channel_observer",
            "execution_identifiers": ["profile path", "batch", "output path"],
            "normalized_profile": baseline,
            "normalized_argv": normalized_argv(run_argvs[0]),
        }
        report_dir = root / "report"
        manifest["commands"].append(run([args.report, runs, report_dir], timeout=30))
        summary = json.loads((report_dir / "summary.json").read_text())
        report_common(summary, raw_values)

        diagnostic: dict[str, object] = {
            "type": "turtle-channel-observer-impact-diagnostic", "schema": 1,
            "boundary": COMMON,
            "acceptance_uses_sign_magnitude_or_significance": False,
            "modes": {}, "arithmetic_on_minus_off": {},
            "limitations": [
                "This is not an uninstrumented run.",
                "This is not a complete observer-overhead correction.",
                "The sample count is a functional diagnostic, not an inferential study.",
                "No WSL or platform performance ranking is supported.",
            ],
        }
        for role in ("client", "server"):
            diagnostic["modes"][role] = {}
            diagnostic["arithmetic_on_minus_off"][role] = {}
            for observer in (True, False):
                label = "on" if observer else "off"
                records = raw_values[(role, observer)]
                diagnostic["modes"][role][label] = {
                    "raw": records,
                    "elapsed_ns": distribution([item["elapsed_ns"] for item in records]),
                    "thread_cpu_ns": distribution([item["thread_cpu_ns"] for item in records]),
                }
            for field in ("elapsed_ns", "thread_cpu_ns"):
                on_values = [item[field] for item in raw_values[(role, True)]]
                off_values = [item[field] for item in raw_values[(role, False)]]
                diagnostic["arithmetic_on_minus_off"][role][field] = (
                    statistics.fmean(on_values) - statistics.fmean(off_values)
                )
        (root / "diagnostic-summary.json").write_text(
            json.dumps(diagnostic, indent=2, sort_keys=True) + "\n"
        )
        manifest["status"] = "complete"
        manifest["counts"] = {"attempts": 16, "endpoint_role_raw_files": 32,
                              "batches": 4, "samples_per_mode_run": 2}
        print("PASS observer_impact: 16 actual TLS attempts, 32 endpoint-role samples")
        return 0
    except Exception as error:
        manifest.update(status="failed", reason=str(error))
        raise
    finally:
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"observer-impact artifacts retained: {root}", file=os.sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL observer_impact: {error}", file=os.sys.stderr)
        raise
