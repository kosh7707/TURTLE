#!/usr/bin/env python3
"""Black-box contracts for turtle-report --repeated-context.

The JSONL files below are deterministic measurement-record fixtures.  They are
not evidence of a live TLS handshake and this test never opens a socket.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable

Json = dict[str, Any]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[Any], trailing: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True) + "\n")
        out.write(trailing)


def run_config(requested: int) -> Json:
    return {"type": "turtle-attempt-ledger", "schema": 1,
            "record_kind": "run_config", "requested_count": requested,
            "failure_policy": "fixed-attempts"}


def attempt_final(attempt: int, status: str = "success") -> Json:
    return {"type": "turtle-attempt-ledger", "schema": 1,
            "record_kind": "attempt_final", "attempt_id": attempt,
            "final_status": status, "network_observation_ids": []}


def attempt_started(attempt: int) -> Json:
    return {"type": "turtle-attempt-ledger", "schema": 1,
            "record_kind": "attempt_started", "attempt_id": attempt}


def run_summary(requested: int, statuses: list[str], missing_artifacts: int = 0) -> Json:
    counts = {name: statuses.count(name) for name in
              ("success", "timeout", "error", "incomplete")}
    started = len(statuses)
    return {"type": "turtle-attempt-ledger", "schema": 1,
            "record_kind": "run_summary", "requested": requested,
            "started": started, **counts, "not_attempted": requested - started,
            "missing_artifacts": missing_artifacts, "missing_artifact_rows": []}


def write_ledger(run: Path, requested: int, statuses: list[str] | None = None) -> None:
    statuses = statuses if statuses is not None else ["success"] * requested
    rows = [run_config(requested)]
    rows += [attempt_final(i + 1, status) for i, status in enumerate(statuses)]
    rows.append(run_summary(requested, statuses))
    write_jsonl(run / "attempts.jsonl", rows)


def connection(index: int, warmup: bool = False) -> Json:
    return {"index": index, "warmup": warmup, "application_verified": True,
            "socket": {"nonblocking": True, "tcp_nodelay": True,
                       "send_buffer": 4096, "receive_buffer": 4096,
                       "kernel_timestamps": False},
            "tcp_start": {"snd_mss": 1448, "rcv_mss": 1448}}


def header(sample: int, role: str, client_adapter: str, server_adapter: str,
           *, batch: int = 1, measured: int = 2, warmups: int = 0,
           mode: str = "timing", observer: bool = True,
           revision: int | None = 2, lookup: bool = False,
           indices: list[int] | None = None) -> Json:
    own = client_adapter if role == "client" else server_adapter
    indices = indices if indices is not None else list(range(warmups + measured))
    h: Json = {
        "type": "sample", "schema": 1, "sample": sample, "batch": batch,
        "role": role, "valid": True, "profile_hash": "fixed-profile",
        "environment_hash": "fixed-environment", "mode": mode,
        "pinned_cpu": 2 if role == "client" else 3,
        "loaded_context_size": 0, "loaded_context_hash": "",
        "perf_complete": False,
        "config": {
            "scenario_name": "standard-tls" if not lookup else
                             "synthetic-lookup-plus-standard-tls",
            "lookup": {"enabled": lookup, "cache_mode": "empty"},
            "client_adapter": client_adapter, "server_adapter": server_adapter,
            "perf": False, "perf_scope": "user", "channel_observer": observer,
            "isolate": True, "pin_cores": True, "kernel_timestamps": False,
            "timeout_ms": 10000, "flush_grace_ms": 500,
            "failure_policy": "fixed-attempts", "warmups": warmups,
            "connections": measured, "tcp_nodelay": True,
            "socket_send_buffer": 4096, "socket_receive_buffer": 4096,
            "application_bytes": 4,
        },
        "declaration": {"library": own, "version": "fixture-1",
                        "build_options": "fixture-release", "is_mock": False},
        "capabilities": {
            "monotonic_clock": True, "thread_cpu_clock": True,
            "perf": False, "perf_requested_scope": "user",
            "perf_status": "disabled", "perf_effective_scope": None,
            "perf_failure_stage": None, "perf_error_number": None,
            "perf_note": "disabled by fixture", "heap_tracking": True,
            "affinity": True, "kernel_timestamp_configured": False,
        },
        "observation_level": "L0",
        "connections": [connection(i, i < warmups) for i in indices],
    }
    if revision is not None:
        h["measurement_contract_revision"] = revision
    if not observer:
        h["availability"] = {
            "io_events": {"available": False, "reason": "channel_observer_disabled"},
            "tls_stream": {"available": False, "reason": "channel_observer_disabled"},
        }
    return h


def events(role: str, values: list[int], cpu_values: list[int | None],
           *, indices: list[int] | None = None) -> list[Json]:
    indices = indices if indices is not None else list(range(len(values)))
    rows: list[Json] = []
    sequence = 1
    for index, elapsed, cpu_elapsed in zip(indices, values, cpu_values):
        base = 1_000_000 + index * 100_000
        cpu_base = 10_000 + index * 1_000
        if role == "client":
            rows.append({"connection": index, "location": "implementation_boundary",
                         "kind": "CALL_BEGIN", "call": "handshake",
                         "sequence": sequence, "monotonic_ns": base,
                         "thread_cpu_ns": cpu_base, "result": 0, "transferred": 0})
            sequence += 1
        else:
            # The primary server window begins at the first successful receive return.
            # Pair the zero-duration receive and then nest app_send so the existing
            # interval-conservation checker has a valid, hand-calculable timeline.
            rows.append({"connection": index, "location": "implementation_boundary",
                         "kind": "IO_RECV_ENTER", "call": "handshake",
                         "sequence": sequence, "monotonic_ns": base,
                         "thread_cpu_ns": cpu_base, "result": 0, "transferred": 0})
            sequence += 1
            rows.append({"connection": index, "location": "implementation_boundary",
                         "kind": "IO_RECV_RETURN", "call": "handshake",
                         "sequence": sequence, "monotonic_ns": base,
                         "thread_cpu_ns": cpu_base, "result": 0, "transferred": 1})
            sequence += 1
            rows.append({"connection": index, "location": "implementation_boundary",
                         "kind": "CALL_BEGIN", "call": "app_send",
                         "sequence": sequence, "monotonic_ns": base,
                         "thread_cpu_ns": cpu_base, "result": 0, "transferred": 0})
            sequence += 1
        end_cpu = None if cpu_elapsed is None else cpu_base + cpu_elapsed
        rows.append({"connection": index, "location": "implementation_boundary",
                     "kind": "CALL_END", "call": "app_recv" if role == "client" else "app_send",
                     "sequence": sequence, "monotonic_ns": base + elapsed,
                     "thread_cpu_ns": end_cpu, "result": 2, "transferred": 4})
        sequence += 1
    return rows


def write_sample(run: Path, directory_name: str, sample: int,
                 client_adapter: str, server_adapter: str,
                 client_values: list[int], server_values: list[int],
                 *, measured: int = 2, warmups: int = 0, batch: int = 1,
                 client_cpu: list[int | None] | None = None,
                 server_cpu: list[int | None] | None = None,
                 mutate_header: Callable[[Json, str], None] | None = None,
                 client_indices: list[int] | None = None,
                 server_indices: list[int] | None = None) -> None:
    directory = run / directory_name
    client_cpu = client_cpu if client_cpu is not None else client_values
    server_cpu = server_cpu if server_cpu is not None else server_values
    for role, vals, cpus, indices in (
        ("client", client_values, client_cpu, client_indices),
        ("server", server_values, server_cpu, server_indices),
    ):
        h = header(sample, role, client_adapter, server_adapter, batch=batch,
                   measured=measured, warmups=warmups, indices=indices)
        if mutate_header:
            mutate_header(h, role)
        rows = [h] + events(role, vals, cpus, indices=indices)
        write_jsonl(directory / f"{role}.jsonl", rows)


def build_study(root: Path, *, batch_mismatch: bool = False) -> dict[str, Path]:
    adapters = {"A": "fixture-adapter-A", "B": "fixture-adapter-B"}
    runs: dict[str, Path] = {}
    manifest_runs = []
    for client_name, server_name in (("A", "A"), ("A", "B"), ("B", "A"), ("B", "B")):
        name = (client_name + server_name).lower()
        run = root / f"run-{name}"
        runs[name] = run
        write_ledger(run, 2)
        for sample in (1, 2):
            client_base = 1 if client_name == "A" else 21
            server_base = 2 if server_name == "A" else 22
            delta = 10 * (sample - 1)
            write_sample(run, f"sample-{sample:06d}", sample,
                         adapters[client_name], adapters[server_name],
                         [client_base + delta] * 2, [server_base + delta] * 2)
        if batch_mismatch and name == "bb":
            for raw in (run / "sample-000001").glob("*.jsonl"):
                rows = [json.loads(x) for x in raw.read_text().splitlines()]
                rows[0]["batch"] = 2
                write_jsonl(raw, rows)
        manifest_runs.append({"status": "complete", "returncode": 0, "batch": 1,
                              "command": ["fixture-runner", "--output", str(run.resolve()),
                                          "--batch", "1"]})
    write_json(root / "study.json", {"type": "turtle-study", "schema": 1,
                                      "runs": manifest_runs})
    return runs


def invoke(reporter: Path, input_path: Path, output: Path,
           repeated: bool, expect_success: bool = True,
           cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    args = [str(reporter), str(input_path), str(output)]
    if repeated:
        args.append("--repeated-context")
    cp = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        cwd=cwd)
    if expect_success and cp.returncode != 0:
        raise AssertionError(f"reporter failed ({cp.returncode}): {' '.join(args)}\n{cp.stdout}")
    if not expect_success and cp.returncode == 0:
        raise AssertionError(f"reporter unexpectedly accepted invalid fixture: {' '.join(args)}")
    return cp


def file_map(root: Path, omit_repeated: bool = False) -> dict[str, bytes]:
    result = {}
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = p.relative_to(root).as_posix()
        if omit_repeated and rel == "repeated-context-summary.json":
            continue
        result[rel] = p.read_bytes()
    return result


def run_default_and_repeated(reporter: Path, input_path: Path, base: Path,
                             cwd: Path | None = None) -> Json:
    default = base / "default"
    repeated = base / "repeated"
    invoke(reporter, input_path, default, False, cwd=cwd)
    invoke(reporter, input_path, repeated, True, cwd=cwd)
    require(file_map(default) == file_map(repeated, omit_repeated=True),
            "opt-in changed a legacy output byte or file")
    path = repeated / "repeated-context-summary.json"
    require(path.is_file(), "opt-in did not add repeated-context-summary.json")
    return json.loads(path.read_text(encoding="utf-8"))


def find_group(view: Json, role: str, client: str, server: str) -> Json:
    matches = [g for g in view["groups"]
               if g["dimensions"]["role"] == role
               and g["dimensions"]["client_adapter"] == client
               and g["dimensions"]["server_adapter"] == server]
    require(len(matches) == 1, f"expected one {role} {client}/{server} group, got {len(matches)}")
    return matches[0]


def assert_canonical(view: Json) -> None:
    required_top = {"type", "schema", "aggregation_policy", "estimand",
                    "selection_scope", "studies", "runs", "contexts", "groups",
                    "batch_diagnostics", "comparisons"}
    require(required_top <= view.keys(), "canonical top-level keys missing")
    require(view["type"] == "turtle-repeated-context-summary", "wrong repeated type")
    require(view["schema"] == 1, "wrong repeated schema")
    require(view["aggregation_policy"] == "context-stq2-v1", "wrong policy")
    require(view["estimand"] == "stq2_of_context_stq2", "wrong estimand")
    for context in view["contexts"]:
        require({"id", "source", "batch_namespace", "batch", "measured_connections",
                 "warmups", "status", "execution_complete", "reasons", "metrics"} <= context.keys(),
                "context canonical keys missing")
        for metric in ("elapsed_ns", "thread_cpu_ns"):
            require({"complete", "expected_count", "available_count", "missing_count",
                     "invalid_count", "reasons", "values", "inner_statistics"} <=
                    context["metrics"][metric].keys(), "metric canonical keys missing")
    for run in view["runs"]:
        require({"root", "ledger", "ledger_status", "namespace_status",
                 "batch_namespace", "batch", "denominators", "coverage_complete",
                 "reasons", "role_coverage"} <= run.keys(), "run canonical keys missing")
        require({"requested", "started", "success", "timeout", "error", "incomplete",
                 "not_attempted", "missing_artifacts"} <= run["denominators"].keys(),
                "denominator keys missing")


def positive_contract(reporter: Path, root: Path) -> None:
    study = root / "positive-study"
    build_study(study)
    view = run_default_and_repeated(reporter, study, root / "positive-output")
    assert_canonical(view)
    require(view["selection_scope"] == "study_root", "study root selection not recognized")
    require(len(view["studies"]) == 1 and view["studies"][0]["namespace_status"] == "verified",
            "single study namespace not verified")
    require(view["studies"][0]["coverage_complete"] is True, "complete study coverage rejected")
    require(len(view["runs"]) == 4 and all(r["coverage_complete"] for r in view["runs"]),
            "complete 4-run study coverage rejected")
    require(len(view["contexts"]) == 16, "4 runs x 2 samples x 2 roles not preserved")
    require(all(c["execution_complete"] and c["status"] == "complete"
                for c in view["contexts"]), "positive context unexpectedly excluded")
    require(all(c["measured_connections"] == 2 and c["warmups"] == 0
                for c in view["contexts"]), "K/W changed")
    for context in view["contexts"]:
        for metric in ("elapsed_ns", "thread_cpu_ns"):
            m = context["metrics"][metric]
            require(m["expected_count"] == 2 and m["available_count"] == 2 and
                    m["missing_count"] == 0 and m["invalid_count"] == 0,
                    "complete metric counts wrong")
            require([x["connection"] for x in m["values"]] == [0, 1],
                    "first connection/index order was not preserved")
    group = find_group(view, "client", "fixture-adapter-A", "fixture-adapter-A")
    elapsed = group["metrics"]["elapsed_ns"]
    require(elapsed["context_values"] == [1, 11], "hand-calculated context representatives changed")
    require(elapsed["outer_statistics"] == {"count": 2, "minimum": 1, "maximum": 11,
                                             "stq1": 1, "stq2": 6, "stq3": 11},
            "hand-calculated outer StQ is wrong")
    require(elapsed["candidate_contexts"] == 2 and elapsed["eligible_contexts"] == 2,
            "connection count was confused with context count")
    require(view["comparisons"], "complete fixed-peer study produced no comparison")
    wanted_client = []
    wanted_server = []
    for comparison in view["comparisons"]:
        ga, gb = view["groups"][comparison["group_a"]], view["groups"][comparison["group_b"]]
        if comparison["metric"] == "elapsed_ns":
            roles = {ga["dimensions"]["role"], gb["dimensions"]["role"]}
            if roles == {"client"} and ga["dimensions"]["server_adapter"] == gb["dimensions"]["server_adapter"]:
                wanted_client.append(comparison)
            if roles == {"server"} and ga["dimensions"]["client_adapter"] == gb["dimensions"]["client_adapter"]:
                wanted_server.append(comparison)
        require(comparison["resampling_unit"] == "context" and comparison["seed"] == 1 and
                comparison["replicates"] == 2000 and comparison["context_count_a"] == 2 and
                comparison["context_count_b"] == 2, "comparison did not resample contexts")
        require(comparison["method"] == "independent_context_percentile_bootstrap" and
                comparison["estimand"] == "stq2_of_context_stq2" and
                comparison["assumption"] == "independent_contexts_within_observed_batch" and
                comparison["interpretation"] ==
                "exploratory_complete_execution_conditional_not_equivalence",
                "comparison interpretation contract changed")
    require(wanted_client and wanted_server, "both roles need a real fixed-peer comparison")
    require(all(abs(c["difference_b_minus_a_ns"]) == 20 for c in wanted_client + wanted_server),
            "fixed constant vectors did not produce the expected 20ns effect")
    require(all("lower_95_ns" in c and "upper_95_ns" in c and
                c["lower_95_ns"] <= c["upper_95_ns"] for c in view["comparisons"]),
            "comparison CI fields missing")
    require(view["batch_diagnostics"] and all("confidence_interval" not in d
                                               for d in view["batch_diagnostics"]),
            "batch diagnostics must not invent a pooled CI")


def two_batch_contract(reporter: Path, root: Path) -> None:
    study = root / "two-batch-study"
    manifest_runs = []
    for batch in (1, 2):
        offset = 100 * (batch - 1)
        for client_name, server_name in (("A", "A"), ("A", "B"),
                                         ("B", "A"), ("B", "B")):
            run = study / f"batch-{batch}-run-{client_name.lower()}{server_name.lower()}"
            write_ledger(run, 2)
            client_adapter = f"fixture-adapter-{client_name}"
            server_adapter = f"fixture-adapter-{server_name}"
            for sample in (1, 2):
                delta = 10 * (sample - 1)
                client_value = offset + (1 if client_name == "A" else 21) + delta
                server_value = offset + (2 if server_name == "A" else 22) + delta
                write_sample(run, f"sample-{sample:06d}", sample, client_adapter,
                             server_adapter, [client_value] * 2, [server_value] * 2,
                             batch=batch)
            manifest_runs.append({
                "status": "complete", "returncode": 0, "batch": batch,
                "command": ["fixture-runner", "--output", str(run.resolve()),
                            "--batch", str(batch)],
            })
    write_json(study / "study.json", {"type": "turtle-study", "schema": 1,
                                      "runs": manifest_runs})
    view = run_default_and_repeated(reporter, study, root / "two-batch-output")
    require(view["studies"][0]["coverage_complete"] is True and
            all(r["coverage_complete"] for r in view["runs"]),
            "complete two-batch study coverage rejected")
    require({c["batch"] for c in view["comparisons"]} == {1, 2},
            "comparisons were not produced separately for both batches")
    for comparison in view["comparisons"]:
        ga = view["groups"][comparison["group_a"]]
        gb = view["groups"][comparison["group_b"]]
        require(ga["batch"] == gb["batch"] == comparison["batch"],
                "comparison pooled contexts across batches")
        require(comparison["context_count_a"] == 2 and
                comparison["context_count_b"] == 2,
                "two batches were pooled into a four-context CI")
    two_entry = [d for d in view["batch_diagnostics"] if len(d["batches"]) == 2]
    require(two_entry, "no cross-batch descriptive diagnostic was emitted")
    require(all([b["batch"] for b in d["batches"]] == [1, 2] for d in two_entry),
            "batch diagnostics lost stable batch order")
    require(all(d["batch_stq2_range"] == 100 for d in two_entry),
            "hand-calculated batch StQ2 range is wrong")
    require(all("confidence_interval" not in d and "lower_95_ns" not in d and
                "upper_95_ns" not in d for d in view["batch_diagnostics"]),
            "batch diagnostics invented a pooled confidence interval")


def unlisted_raw_child_contract(reporter: Path, root: Path) -> None:
    study = root / "study"
    build_study(study)
    extra = study / "extra-raw-run"
    write_sample(extra, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [41, 41], [42, 42])
    view = run_default_and_repeated(reporter, study, root / "output")
    extra_root = str(extra.resolve())
    matching_runs = [r for r in view["runs"] if r["root"] == extra_root]
    require(len(matching_runs) == 1 and matching_runs[0]["ledger_status"] == "absent",
            "unlisted raw-only child was merged into INPUT or lost")
    extra_contexts = [c for c in view["contexts"]
                      if c["id"]["run_root"] == extra_root]
    require(len(extra_contexts) == 2,
            "raw-only child context identity did not retain its actual run root")
    require(extra_root in view["studies"][0]["discovered_run_roots"],
            "unlisted raw-only run was omitted from study discovery")
    require(view["studies"][0]["coverage_complete"] is False and
            view["studies"][0]["reasons"],
            "manifest-unlisted raw run did not invalidate study coverage")
    require(view["comparisons"] == [],
            "manifest-unlisted raw run left study automatic comparisons enabled")


def ancestor_study_partial_batch_contract(reporter: Path, root: Path) -> None:
    study = root / "study"
    selected = study / "batch-001"
    manifest_runs = []
    for client_name, server_name in (("A", "A"), ("A", "B"),
                                     ("B", "A"), ("B", "B")):
        run = selected / f"run-{client_name.lower()}{server_name.lower()}"
        write_ledger(run, 2)
        for sample in (1, 2):
            delta = 10 * (sample - 1)
            client_value = (1 if client_name == "A" else 21) + delta
            server_value = (2 if server_name == "A" else 22) + delta
            write_sample(run, f"sample-{sample:06d}", sample,
                         f"fixture-adapter-{client_name}",
                         f"fixture-adapter-{server_name}",
                         [client_value] * 2, [server_value] * 2)
        manifest_runs.append({"status": "complete", "returncode": 0, "batch": 1,
                              "command": ["fixture-runner", "--output",
                                          str(run.resolve()), "--batch", "1"]})
    write_json(study / "study.json", {"type": "turtle-study", "schema": 1,
                                      "runs": manifest_runs})
    view = run_default_and_repeated(reporter, selected, root / "output")
    require(view["selection_scope"] in {"partial", "mixed"},
            "study descendant selection was mislabeled as a full study root")
    require(view["comparisons"] == [],
            "study descendant selection produced automatic comparison")
    require(view["contexts"] and all("selection_scope_partial" in c["reasons"]
                                      for c in view["contexts"]),
            "partial selection reason was lost before context serialization")
    require(all(not metric["automatic_comparison_eligible"] and
                "selection_scope_partial" in metric["comparison_exclusion_reasons"]
                for group in view["groups"] for metric in group["metrics"].values()),
            "partial selection did not propagate into group comparison eligibility")


def relative_partial_identity_contract(reporter: Path, root: Path) -> None:
    run = root / "run"
    write_ledger(run, 2, ["timeout", "success"])
    write_sample(run, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [1, 1], [2, 2])
    raw = run / "sample-000001" / "client.jsonl"
    absolute = run_default_and_repeated(reporter, raw, root / "absolute-output")
    relative_run = run_default_and_repeated(
        reporter, Path("sample-000001/client.jsonl"), root / "relative-run-output", cwd=run)
    relative_sample = run_default_and_repeated(
        reporter, Path("client.jsonl"), root / "relative-sample-output", cwd=raw.parent)
    expected_root = str(run.resolve())
    for label, view in (("absolute", absolute), ("run-relative", relative_run),
                        ("sample-relative", relative_sample)):
        require(view["selection_scope"] == "partial", f"{label} selection not partial")
        require(len(view["runs"]) == 1 and view["runs"][0]["root"] == expected_root,
                f"{label} did not retain canonical nearest run identity")
        require(view["runs"][0]["denominators"]["requested"] == 2 and
                view["runs"][0]["denominators"]["timeout"] == 1,
                f"{label} lost nearest ancestor ledger denominator")
        require(len(view["contexts"]) == 1 and
                view["contexts"][0]["id"]["run_root"] == expected_root and
                "parent_attempt_unsuccessful" in view["contexts"][0]["reasons"],
                f"{label} canonical context/parent identity differs")
        require(view["comparisons"] == [], f"{label} partial input compared")

    # With no ledger, relative file spelling must still resolve to the raw run,
    # not the cwd/sample directory or a non-absolute identity.
    raw_only = root / "raw-only-run"
    write_sample(raw_only, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [3, 3], [4, 4])
    no_ledger = run_default_and_repeated(
        reporter, Path("sample-000001/client.jsonl"), root / "raw-only-output", cwd=raw_only)
    raw_root = str(raw_only.resolve())
    require(len(no_ledger["runs"]) == 1 and no_ledger["runs"][0]["root"] == raw_root and
            no_ledger["contexts"][0]["id"]["run_root"] == raw_root,
            "relative no-ledger raw identity was not absolute nearest run-root")


def partial_and_failed_parent(reporter: Path, root: Path) -> None:
    run = root / "partial-run"
    write_ledger(run, 2, ["timeout", "success"])
    write_sample(run, "sample-000001", 1, "fixture-adapter-A", "fixture-adapter-A",
                 [1, 1], [2, 2])
    raw = run / "sample-000001" / "client.jsonl"
    view = run_default_and_repeated(reporter, raw, root / "partial-output")
    require(view["selection_scope"] == "partial", "single raw selection not partial")
    require(len(view["contexts"]) == 1, "partial input silently added unselected peer/raw")
    require(len(view["runs"]) == 1, "ancestor ledger was not associated once")
    den = view["runs"][0]["denominators"]
    require(den["requested"] == 2 and den["started"] == 2 and den["timeout"] == 1,
            "partial selection shrank or rewrote ledger denominator")
    require("parent_attempt_unsuccessful" in view["contexts"][0]["reasons"],
            "ancestor parent failure not applied to repeated view")
    require(view["comparisons"] == [], "partial/failed parent produced comparison")


def coverage_and_metric_contract(reporter: Path, root: Path) -> None:
    # All-success ledger is not enough: sample 2 has no raw at all.
    run = root / "missing-raw-run"
    write_ledger(run, 3)
    write_sample(run, "sample-000001", 1, "fixture-adapter-A", "fixture-adapter-A",
                 [1, 1], [2, 2], client_cpu=[0, 0], server_cpu=[0, 0])
    view = run_default_and_repeated(reporter, run, root / "missing-raw-output")
    rr = view["runs"][0]
    require(rr["denominators"]["requested"] == 3, "requested denominator inferred from raw")
    require(rr["coverage_complete"] is False and "missing_raw" in rr["reasons"],
            "all-success ledger incorrectly overrode missing bilateral raw")
    require(rr["role_coverage"]["client"]["discovered_contexts"] == 1 and
            rr["role_coverage"]["server"]["discovered_contexts"] == 1,
            "raw-free attempts were fabricated as contexts")
    require(len(view["contexts"]) == 2 and all(c["metrics"]["thread_cpu_ns"]["inner_statistics"]["stq2"] == 0
                                                for c in view["contexts"]),
            "actual CPU zero was treated as missing")
    require(view["comparisons"] == [], "incomplete run coverage produced comparison")

    # A single missing role is distinct from an entirely missing attempt.
    run_role = root / "one-role-missing-run"
    write_ledger(run_role, 2)
    write_sample(run_role, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [1, 1], [2, 2])
    write_sample(run_role, "sample-000002", 2, "fixture-adapter-A",
                 "fixture-adapter-A", [3, 3], [4, 4])
    (run_role / "sample-000002" / "server.jsonl").unlink()
    view_role = run_default_and_repeated(reporter, run_role,
                                         root / "one-role-missing-output")
    cov = view_role["runs"][0]["role_coverage"]
    require(cov["client"]["discovered_contexts"] == 2 and
            cov["server"]["discovered_contexts"] == 1,
            "one-role missing coverage was not distinguished")
    require(view_role["runs"][0]["coverage_complete"] is False and
            "missing_raw" in view_role["runs"][0]["reasons"] and
            view_role["comparisons"] == [],
            "one-role missing run became automatically comparable")
    require(any(c["id"]["sample"] == 1 and c["id"]["role"] == "server"
                for c in view_role["contexts"]),
            "remaining complete descriptive context was discarded")

    # One CPU boundary missing: elapsed remains complete, CPU uses no K-1 estimate.
    run2 = root / "missing-cpu-run"
    write_ledger(run2, 1)
    write_sample(run2, "sample-000001", 1, "fixture-adapter-A", "fixture-adapter-A",
                 [5, 5], [6, 6], client_cpu=[0, None], server_cpu=[0, 0])
    view2 = run_default_and_repeated(reporter, run2, root / "missing-cpu-output")
    client = next(c for c in view2["contexts"] if c["id"]["role"] == "client")
    elapsed, cpu = client["metrics"]["elapsed_ns"], client["metrics"]["thread_cpu_ns"]
    require(elapsed["complete"] is True and elapsed["inner_statistics"] is not None,
            "elapsed was discarded with missing CPU")
    require(cpu["complete"] is False and cpu["expected_count"] == 2 and
            cpu["available_count"] == 1 and cpu["missing_count"] == 1 and
            cpu["inner_statistics"] is None and "metric_incomplete" in cpu["reasons"],
            "CPU metric improperly inferred K from available observations")


def manual_run_coverage_contract(reporter: Path, root: Path) -> None:
    # A study manifest is required for cross-run comparison, not for truthful
    # execution coverage of an otherwise complete manual run.
    manual = root / "manual-complete-run"
    write_ledger(manual, 1)
    write_sample(manual, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [1, 1], [2, 2])
    manual_view = run_default_and_repeated(reporter, manual,
                                            root / "manual-complete-output")
    rr = manual_view["runs"][0]
    require(rr["coverage_complete"] is True,
            "complete manual run coverage was coupled to study namespace verification")
    require(rr["namespace_status"] == "unverified" and
            "run_coverage_incomplete" not in rr["reasons"],
            "manual run namespace status was confused with raw execution coverage")
    require(manual_view["comparisons"] == [] and
            all("batch_namespace_unverified" in m["comparison_exclusion_reasons"]
                for g in manual_view["groups"] for m in g["metrics"].values()),
            "manual run without a verified study became automatically comparable")



def incomplete_study_coverage_contract(reporter: Path, root: Path) -> None:
    # A missing manifest member invalidates study comparison coverage but must
    # not rewrite the observed complete run's own execution coverage.
    study = root / "study-with-missing-run"
    present = study / "run-present"
    missing = study / "run-missing"
    write_ledger(present, 1)
    write_sample(present, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [3, 3], [4, 4])
    write_json(study / "study.json", {
        "type": "turtle-study", "schema": 1,
        "runs": [
            {"status": "complete", "returncode": 0, "batch": 1,
             "command": ["fixture-runner", "--output", str(present.resolve()),
                         "--batch", "1"]},
            {"status": "complete", "returncode": 0, "batch": 1,
             "command": ["fixture-runner", "--output", str(missing.resolve()),
                         "--batch", "1"]},
        ],
    })
    study_view = run_default_and_repeated(reporter, study,
                                           root / "missing-member-output")
    require(study_view["studies"][0]["coverage_complete"] is False and
            "study_run_missing" in study_view["studies"][0]["reasons"],
            "missing study member did not invalidate study coverage")
    require(study_view["runs"][0]["coverage_complete"] is True,
            "missing peer run rewrote complete present-run execution coverage")
    require(study_view["comparisons"] == [],
            "incomplete study inventory produced cross-run comparison")



def partition_validity_contract(reporter: Path, root: Path) -> None:
    # A present index is not an execution success when partition.valid is false.
    invalid = root / "application-unverified-run"
    write_ledger(invalid, 1)
    def unverify_application(h: Json, role: str) -> None:
        del role
        h["connections"][1]["application_verified"] = False
    write_sample(invalid, "sample-000001", 1, "fixture-adapter-A",
                 "fixture-adapter-A", [5, 5], [6, 6],
                 mutate_header=unverify_application)
    invalid_view = run_default_and_repeated(reporter, invalid,
                                             root / "application-unverified-output")
    require(all(c["execution_complete"] is False and c["status"] == "excluded" and
                "invalid_context" in c["reasons"] for c in invalid_view["contexts"]),
            "partition.valid=false connection was counted as execution complete")
    require(invalid_view["runs"][0]["coverage_complete"] is False and
            invalid_view["comparisons"] == [],
            "invalid application connection produced complete coverage/comparison")


def malformed_connection_contract(reporter: Path, root: Path) -> None:
    cases = {
        "k-missing": ([0], [1], "incomplete_connections"),
        "duplicate-index": ([0, 0, 1], [1, 2, 3], "duplicate_connection"),
        "extra-index": ([0, 1, 2], [1, 2, 3], "incomplete_connections"),
    }
    for name, (indices, vals, reason) in cases.items():
        run = root / name
        write_ledger(run, 1)
        write_sample(run, "sample-000001", 1, "fixture-adapter-A", "fixture-adapter-A",
                     vals, vals, measured=2, client_indices=indices, server_indices=indices)
        view = run_default_and_repeated(reporter, run, root / f"{name}-output")
        require(all(c["execution_complete"] is False and reason in c["reasons"]
                    for c in view["contexts"]), f"{name} was silently admitted")
        require(view["comparisons"] == [], f"{name} produced comparison")

    # Two directories repeat the same run-root/sample/role identity.  The view must
    # not silently expose duplicate canonical context IDs.
    run = root / "duplicate-context"
    write_ledger(run, 2)
    for directory in ("copy-one", "copy-two"):
        write_sample(run, directory, 1, "fixture-adapter-A", "fixture-adapter-A",
                     [1, 1], [2, 2])
    view = run_default_and_repeated(reporter, run, root / "duplicate-context-output")
    ids = [(c["id"]["run_root"], c["id"]["sample"], c["id"]["role"])
           for c in view["contexts"]]
    duplicate_ids = {identity for identity in ids if ids.count(identity) > 1}
    require(duplicate_ids, "duplicate-context fixture did not create duplicate IDs")
    affected = [c for c, identity in zip(view["contexts"], ids) if identity in duplicate_ids]
    require(len(affected) == 4, "duplicate descriptive records were silently discarded")
    require(all(c["execution_complete"] is False and c["status"] == "excluded" and
                "invalid_context" in c["reasons"] for c in affected),
            "duplicate context ID was silently admitted")
    require(view["runs"][0]["coverage_complete"] is False and view["comparisons"] == [],
            "duplicate context identity did not block run comparison")


def existing_eligibility_contract(reporter: Path, root: Path) -> None:
    mutations: dict[str, Callable[[Json, str], None]] = {
        "memory": lambda h, role: h.update(mode="memory"),
        "missing-revision": lambda h, role: h.pop("measurement_contract_revision", None),
        "missing-perf-identity": lambda h, role: h["capabilities"].pop(
            "perf_effective_scope", None),
        "observer-disabled": lambda h, role: (
            h["config"].update(channel_observer=False),
            h.update(observation_level="observer-disabled",
                     availability={"io_events": {"available": False,
                                                  "reason": "channel_observer_disabled"}})),
        "native-no-io": lambda h, role: (
            h["config"].update(framework_io=False),
            h.update(observation_level="library-only",
                     availability={"io_events": {"available": False,
                                                  "reason": "native_socket_io_not_observed"},
                                   "tls_stream": {"available": False,
                                                  "reason": "native_socket_io_not_observed"}})),
        "network-unverified": lambda h, role: h["config"].update(
            network_handoff={"net_profile": {"name": "fixture-netem"}}),
    }
    for name, mutate in mutations.items():
        run = root / name
        write_ledger(run, 2)
        for sample in (1, 2):
            write_sample(run, f"sample-{sample:06d}", sample,
                         "fixture-adapter-A", "fixture-adapter-A", [5, 5], [6, 6],
                         mutate_header=mutate)
        view = run_default_and_repeated(reporter, run, root / f"{name}-output")
        require(view["comparisons"] == [], f"{name} relaxed into a comparison")
        require(all(not m["automatic_comparison_eligible"]
                    for g in view["groups"] for m in g["metrics"].values()),
                f"{name} group marked automatically comparable")


def namespace_and_manifest_contract(reporter: Path, root: Path) -> None:
    mismatch = root / "batch-mismatch-study"
    build_study(mismatch, batch_mismatch=True)
    view = run_default_and_repeated(reporter, mismatch, root / "batch-mismatch-output")
    require(any("study_manifest_mismatch" in r["reasons"] for r in view["runs"]),
            "manifest/raw batch mismatch not recorded")
    require(view["comparisons"] == [], "manifest/raw batch mismatch produced comparison")

    common = root / "two-studies"
    build_study(common / "study-one")
    build_study(common / "study-two")
    view2 = run_default_and_repeated(reporter, common, root / "two-studies-output")
    require(len(view2["studies"]) == 2 and all(s["namespace_status"] == "multiple"
                                               for s in view2["studies"]),
            "two batch-1 studies were not kept as multiple namespaces")
    require(view2["comparisons"] == [], "same numeric batch across studies was pooled")


def ledger_boundaries(reporter: Path, root: Path) -> None:
    ledger_only = root / "ledger-only"
    write_ledger(ledger_only, 3, ["success", "timeout"])
    view = run_default_and_repeated(reporter, ledger_only, root / "ledger-only-output")
    require(view["contexts"] == [] and len(view["runs"]) == 1,
            "ledger-only run disappeared or fabricated contexts")
    den = view["runs"][0]["denominators"]
    require(den["requested"] == 3 and den["started"] == 2 and den["not_attempted"] == 1,
            "ledger-only denominators changed")

    absent = root / "ledger-absent"
    write_sample(absent, "sample-000001", 1, "fixture-adapter-A", "fixture-adapter-A",
                 [1, 1], [2, 2])
    view2 = run_default_and_repeated(reporter, absent, root / "ledger-absent-output")
    rr = view2["runs"][0]
    require(rr["ledger_status"] == "absent" and rr["ledger"] is None and
            all(v is None for v in rr["denominators"].values()),
            "absent ledger denominators were inferred from raw")
    require(all("parent_status_unverified" in c["reasons"] for c in view2["contexts"]),
            "absent parent status was treated as success")

    no_summary = root / "normal-eof-no-summary"
    write_jsonl(no_summary / "attempts.jsonl", [run_config(1), attempt_started(1)])
    cp = invoke(reporter, no_summary, root / "normal-eof-output", True, expect_success=False)
    require("missing run_summary" in cp.stdout, "normal EOF missing summary was not rejected distinctly")

    partial = root / "truncated-partial"
    write_jsonl(partial / "attempts.jsonl", [run_config(2), attempt_started(1)], trailing="{")
    view3 = run_default_and_repeated(reporter, partial, root / "truncated-output")
    rr3 = view3["runs"][0]
    require(rr3["ledger_status"] == "partial" and rr3["denominators"]["requested"] == 2,
            "truncated outstanding attempt was not preserved as partial")
    for key in ("started", "success", "timeout", "error", "incomplete",
                "not_attempted", "missing_artifacts"):
        require(rr3["denominators"][key] is None,
                f"partial ledger inferred final denominator {key}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} REPORTER", file=sys.stderr)
        return 2
    reporter = Path(sys.argv[1]).resolve()
    if not reporter.is_file():
        print(f"reporter is not a file: {reporter}", file=sys.stderr)
        return 2
    tests = [positive_contract, two_batch_contract, unlisted_raw_child_contract,
             ancestor_study_partial_batch_contract, relative_partial_identity_contract,
             partial_and_failed_parent,
             coverage_and_metric_contract, manual_run_coverage_contract,
             incomplete_study_coverage_contract, partition_validity_contract,
             malformed_connection_contract, existing_eligibility_contract,
             namespace_and_manifest_contract, ledger_boundaries]
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="turtle-repeated-context-") as temporary:
        base = Path(temporary)
        for test in tests:
            case = base / test.__name__
            case.mkdir()
            try:
                test(reporter, case)
                print(f"PASS {test.__name__}")
            except Exception as error:  # report all independent contract gaps in one run
                failures.append(f"{test.__name__}: {error}")
                print(f"FAIL {test.__name__}: {error}", file=sys.stderr)
    if failures:
        print("repeated-context contract failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("PASS repeated-context black-box contracts (synthetic records; not live TLS evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
