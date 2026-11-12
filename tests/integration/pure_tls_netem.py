#!/usr/bin/env python3
"""Actual stock OpenSSL TLS over the lookup-free owned netem topology."""

from profiles import experiment_profile, flatten_experiment
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SAMPLES = 2
PHASES = (
    ("setup", "begin"),
    ("setup", "end"),
    ("scenario", "begin"),
    ("scenario", "end"),
    ("cleanup", "begin"),
    ("cleanup", "end"),
)
TLS_PATHS = {"tls_c2s", "tls_s2c"}


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


def read_jsonl(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    check(rows, f"empty JSONL artifact: {path}")
    return rows


def write_profile(path, pki):
    # This is deliberately one shared TLS profile for both network conditions.
    # In particular, it contains neither a lookup object nor a snapshot path.
    profile = {
        "name": "standard-tls-netem",
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
        },
        "technique": {"name": "standard-tls"},
    }
    path.write_text(json.dumps(experiment_profile(**profile), sort_keys=True, indent=2) + "\n")


def write_net_profile(path, delay_ms):
    policy = {"delay_ms": delay_ms, "loss_percent": 0.0, "limit_packets": 10000, "rate_bps": None}
    profile = {
        "type": "turtle-netem-profile",
        "schema": 3,
        "qdisc": "netem",
        "mtu": 1500,
        "offload": {"tso": False, "gso": False, "gro": False},
        "trace": True,
        "loss_seed": None,
        "initial_cwnd": {"client": None, "server": None},
        "kernel_events": False, "targeted_drop": {name: None for name in TLS_PATHS},
        "paths": {name: dict(policy) for name in sorted(TLS_PATHS)},
    }
    path.write_text(json.dumps(profile, sort_keys=True, indent=2) + "\n")


def validate_ledger(output):
    rows = read_jsonl(output / "attempts.jsonl")
    check(rows[0].get("record_kind") == "run_config" and
          rows[0].get("requested_count") == SAMPLES,
          f"{output}: attempt ledger lost its declared denominator")
    started = [row for row in rows if row.get("record_kind") == "attempt_started"]
    final = [row for row in rows if row.get("record_kind") == "attempt_final"]
    summary = [row for row in rows if row.get("record_kind") == "run_summary"]
    check(len(started) == SAMPLES and len(final) == SAMPLES and len(summary) == 1,
          f"{output}: attempt ledger is incomplete")
    check([row["attempt_id"] for row in started] == [1, 2] and
          [row["attempt_id"] for row in final] == [1, 2],
          f"{output}: attempt identities changed")
    check(all(row.get("final_status") == "success" for row in final),
          f"{output}: an actual TLS attempt failed")
    check(all(row.get("participants") == ["tls-server", "tls-client"] for row in final),
          f"{output}: pure TLS ledger contains a CA participant")
    expected_artifacts = {"client.jsonl": "complete", "server.jsonl": "complete"}
    check(all(row.get("artifacts") == expected_artifacts and
              row.get("artifact_status") == ["complete", "complete"] for row in final),
          f"{output}: pure TLS ledger synthesized CA/lookup artifacts or lost role artifacts")
    check(all(row.get("network_observation_ids") ==
              [f"{row['attempt_id']}:{phase}:{edge}" for phase, edge in PHASES]
              for row in final), f"{output}: ledger lost a phase observation reference")
    expected = {"requested": 2, "started": 2, "success": 2,
                "timeout": 0, "error": 0, "not_attempted": 0}
    check(all(summary[0].get(key) == value for key, value in expected.items()),
          f"{output}: run summary does not prove two successful attempts")


def validate_network(output, delay_ms):
    manifest = json.loads((output / "network-manifest.json").read_text())
    provenance = json.loads((output / "network-provenance.json").read_text())
    check(set(manifest["namespace_fds"]) == {"client", "server"},
          f"{output}: CA or router fd was passed to the TLS runner")
    check(set(manifest["addresses"]) == {"client_tls", "server"},
          f"{output}: inactive CA addresses remain in the manifest")
    check(set(manifest["interfaces"]) == {
        "client_tls", "server", "router_client_tls", "router_server"},
        f"{output}: inactive CA interfaces remain in the manifest")
    check(set(manifest["net_profile"]["paths"]) == TLS_PATHS,
          f"{output}: manifest contains non-TLS paths")

    identity = provenance["condition_identity"]
    check(provenance.get("status") == "complete" and
          provenance.get("runner", {}).get("returncode") == 0,
          f"{output}: coordinator did not finish successfully")
    check(identity["topology"]["kind"] == "three-netns-receiver-facing-router-egress",
          f"{output}: wrong fixed topology")
    helpers = provenance["lifecycle"]["helpers"]
    check(set(helpers) == {"client", "server", "router"} and
          all(helper.get("owned") is True for helper in helpers.values()),
          f"{output}: helper ownership is not the pure TLS topology")
    check(set(identity["requested"]["paths"]) == TLS_PATHS and
          set(identity["actual"]["paths"]) == TLS_PATHS and
          set(provenance["applied_qdisc_readback"]) == TLS_PATHS,
          f"{output}: exactly two TLS qdiscs were not observed")
    for logical_path in TLS_PATHS:
        requested = identity["requested"]["paths"][logical_path]
        actual = identity["actual"]["paths"][logical_path]
        check(requested == {"delay_ms": delay_ms, "loss_percent": 0.0,
                            "limit_packets": 10000, "rate_bps": None},
              f"{output}: requested {logical_path} policy changed")
        check(abs(actual["delay_ms"] - delay_ms) <= .001 and
              actual["loss_percent"] == 0 and actual["limit_packets"] == 10000 and
              actual["kind"] == "netem",
              f"{output}: {logical_path} qdisc readback differs")
    link_adds = [row for row in provenance["commands"]
                 if row.get("argv", [])[:3] == ["ip", "link", "add"]]
    check(len(link_adds) == 2 and
          {row["argv"][3] for row in link_adds} == {"ctls", "stls"},
          f"{output}: pure TLS did not create exactly two endpoint links")

    observations = read_jsonl(output / "network-observations.jsonl")
    check(len(observations) == SAMPLES * len(PHASES),
          f"{output}: incomplete network phase evidence")
    expected_ids = [f"{attempt}:{phase}:{edge}" for attempt in (1, 2)
                    for phase, edge in PHASES]
    check([row.get("observation_id") for row in observations] == expected_ids and
          all(set(row.get("qdiscs", {})) == TLS_PATHS for row in observations),
          f"{output}: phase order or two-qdisc snapshots changed")
    packets = read_jsonl(output / "packets.jsonl")
    packet_rows = [row for row in packets if row.get("record_kind") == "packet"]
    check(set(packets[0].get("interfaces", [])) == {"rctls", "rstls"} and
          all(row.get("logical_path") in (*TLS_PATHS, "control_tls_c2s", "control_tls_s2c") for row in packet_rows),
          f"{output}: trace observed an inactive CA interface or path")
    host = provenance.get("host_network_identity", {})
    check(host.get("unchanged") is True,
          f"{output}: host network identity was not proved unchanged")
    lifecycle = provenance["lifecycle"]
    check(lifecycle.get("namespace_fds_closed") is True and
          lifecycle.get("owned_pipe_fds_closed") is True,
          f"{output}: owned descriptors were not proved closed")
    helper_cleanup = {row.get("helper"): row.get("result")
                      for row in provenance.get("cleanup", []) if "helper" in row}
    check(helper_cleanup == {"client": "reaped", "server": "reaped", "router": "reaped"},
          f"{output}: owned helpers were not all reaped")


def validate_role(raw, role, interpret):
    rows = read_jsonl(raw)
    header = rows[0]
    check(header.get("type") == "sample" and header.get("schema") == 3 and header.get("valid"),
          f"{raw}: invalid sample: {header.get('invalid_reason')}")
    check(header["role"] == role and not header["declaration"]["is_mock"],
          f"{raw}: role or actual-TLS declaration changed")
    config = header["config"]
    check("samples" not in config and config["warmups"] == 0 and
          config["connections"] == 1 and config["pin_cores"] is False and
          config["perf"] is False,
          f"{raw}: explicit WSL-safe execution controls changed")
    lookup = config.get("lookup")
    check(lookup is None or lookup.get("enabled") is False,
          f"{raw}: lookup was enabled")
    check(len(header["connections"]) == 1, f"{raw}: connection count changed")
    connection = header["connections"][0]
    negotiated = connection["negotiated"]
    check(negotiated["version"] == "TLS1.3" and
          negotiated["cipher"] == "TLS_AES_128_GCM_SHA256",
          f"{raw}: required TLS 1.3 cipher was not negotiated")
    check(negotiated["resumed"] is False and connection["application_verified"] is True,
          f"{raw}: resumed handshake or unverified encrypted ping-pong")
    expected_verification = "passed" if role == "client" else "not_applicable"
    check(connection["verification"] == expected_verification,
          f"{raw}: peer verification result changed")

    decoded_path = raw.with_suffix(".decoded.json")
    run(interpret, raw, decoded_path)
    decoded = json.loads(decoded_path.read_text())
    check(len(decoded["connections"]) == 1 and
          decoded["connections"][0]["decryption_complete"],
          f"{raw}: TLS stream was not fully decoded")
    decoded_connection = decoded["connections"][0]
    server_names = [message["name"] for message in decoded_connection["server_sent"]["messages"]]
    client_names = [message["name"] for message in decoded_connection["client_sent"]["messages"]]
    check("Certificate" in server_names and "CompressedCertificate" not in server_names,
          f"{raw}: stock Certificate message is missing or compressed")
    check("Finished" in server_names and "Finished" in client_names and
          "ApplicationData" in server_names and "ApplicationData" in client_names,
          f"{raw}: full handshake or encrypted ping-pong records are missing")


def validate_artifacts(output, interpret):
    forbidden = {"ca.jsonl", "lookup.jsonl", "lookup-summary.json", "snapshot.json"}
    check(not any(path.name in forbidden or "object" in path.name.lower()
                  for path in output.rglob("*") if path.is_file()),
          f"{output}: CA, lookup, object, or snapshot artifact was synthesized")
    samples = sorted(output.glob("sample-*"))
    check(len(samples) == SAMPLES, f"{output}: sample denominator changed")
    for sample in samples:
        validate_role(sample / "client.jsonl", "client", interpret)
        validate_role(sample / "server.jsonl", "server", interpret)
        client_sent = (sample / "client.conn-0.sent.bin").read_bytes()
        client_received = (sample / "client.conn-0.received.bin").read_bytes()
        server_sent = (sample / "server.conn-0.sent.bin").read_bytes()
        server_received = (sample / "server.conn-0.received.bin").read_bytes()
        check(client_sent and server_sent and client_sent == server_received and
              server_sent == client_received,
              f"{sample}: captured TLS stream bytes do not correspond by direction")


def validate_combined_report(report_dir):
    summary = json.loads((report_dir / "summary.json").read_text())
    check(summary.get("invalid_samples") == 0, "combined report rejected a valid TLS sample")
    check("lookup_summary" not in summary and not (report_dir / "lookup-summary.json").exists(),
          "pure TLS attempts incorrectly produced a synthetic lookup summary")
    samples = summary.get("samples", [])
    check(len(samples) == 2 * SAMPLES * 2,
          "combined report omitted a condition, attempt, or endpoint role")
    check(all(sample.get("network_integrity", {}).get("status") == "complete" and
              sample["network_integrity"].get("eligible") is True and
              sample["network_integrity"].get("reasons") == []
              for sample in samples),
          "a reported pure TLS sample lacks complete network integrity evidence")
    groups = summary.get("groups", [])
    check(len(groups) == 4, "network conditions or endpoint roles were pooled")
    found = set()
    for group in groups:
        dimensions = group["dimensions"]
        requested = dimensions.get("network_requested_identity")
        actual = dimensions.get("network_actual_identity")
        check("network_integrity" not in dimensions,
              "runtime integrity was incorrectly included in the stable condition identity")
        check(isinstance(requested, dict) and set(requested["paths"]) == TLS_PATHS,
              "report omitted the requested pure TLS network identity")
        check(isinstance(actual, dict) and
              actual["topology"]["kind"] == "three-netns-receiver-facing-router-egress" and
              set(actual["actual"]["paths"]) == TLS_PATHS,
              "report omitted the actual pure TLS network identity")
        check(group.get("automatic_comparison_eligible") is True and
              dimensions.get("automatic_comparison_identity_complete") is True,
              "complete network evidence was not eligible for grouping")
        delays = {policy["delay_ms"] for policy in requested["paths"].values()}
        check(len(delays) == 1, "asymmetric delay unexpectedly entered the test")
        delay = delays.pop()
        role = dimensions["role"]
        check(delay in (0, 20) and role in ("client", "server"),
              "unexpected report group identity")
        elapsed = group["metrics"].get("elapsed_ns", {})
        cpu = group["metrics"].get("thread_cpu_ns", {})
        check(elapsed.get("count") == SAMPLES and len(elapsed.get("values", [])) == SAMPLES and
              cpu.get("count") == SAMPLES and len(cpu.get("values", [])) == SAMPLES,
              "role-specific elapsed or thread CPU samples were pooled or omitted")
        found.add((delay, role))
    check(found == {(0, "client"), (0, "server"), (20, "client"), (20, "server")},
          "0 ms and 20 ms client/server groups are not distinct")


def main():
    check(len(sys.argv) == 7,
          "usage: pure_tls_netem.py NETEM TURTLE REPORT INTERPRET ADAPTERS PKI")
    netem, turtle, report, interpret, adapters, pki = map(Path, sys.argv[1:])
    check((adapters / "openssl.so").exists(),
          "OpenSSL adapter is not present in the supplied adapter directory")
    build = turtle.resolve().parent
    check(build / "adapters" == adapters.resolve(),
          "netem runner and test disagree about the adapter directory")
    root = Path(tempfile.mkdtemp(prefix="turtle-pure-tls-netem-"))
    try:
        inputs = root / "inputs"
        runs = root / "runs"
        inputs.mkdir()
        runs.mkdir()
        profile = inputs / "standard-tls.json"
        write_profile(profile, pki.resolve())
        for delay_ms in (0, 20):
            net_profile = inputs / f"tls-{delay_ms}ms.json"
            output = runs / f"tls-{delay_ms}ms"
            write_net_profile(net_profile, delay_ms)
            run(sys.executable, netem, "run", "--build", build,
                "--profile", profile, "--net-profile", net_profile,
                "--samples", str(SAMPLES), "--output", output)
            validate_ledger(output)
            validate_network(output, delay_ms)
            validate_artifacts(output, interpret)
            for raw in sorted(output.glob('sample-*/*.jsonl')):
                if raw.stem not in ('client', 'server'):
                    continue
                correlated = raw.with_suffix('.tcp.json')
                run(sys.executable, netem.parent / 'tcp-correlate.py',
                    output / 'packets.jsonl', raw, correlated)
                evidence = json.loads(correlated.read_text())
                check(evidence['status'] == 'available' and evidence['capture_complete'],
                      'raw packet/TLS byte mapping unavailable')
                for conn in evidence['connections']:
                    check(conn['status'] == 'available' and conn['stream_bytes_verified'] > 0,
                          'TCP byte reconstruction incomplete')
                    finished = next(m for m in conn['messages'] if m['name'] == 'Finished')
                    check(finished['packet_indices'] and finished['socket_submission_events'] and
                          finished['cumulative_ack_status'] == 'observed',
                          'Finished record/submission/packet/ACK mapping incomplete')
        combined_report = root / "combined-report"
        run(report, runs, combined_report)
        validate_combined_report(combined_report)
        # Requested kernel evidence that was not collected must remain missing,
        # while the already completed real TLS exchange remains in the report.
        output = runs / "tls-0ms"
        provenance_path = output / "network-provenance.json"
        original = provenance_path.read_text()
        provenance = json.loads(original)
        provenance["condition_identity"]["requested"]["kernel_events"] = True
        provenance_path.write_text(json.dumps(provenance))
        missing_report = root / "missing-kernel-report"
        run(report, output, missing_report)
        missing = json.loads((missing_report / "summary.json").read_text())
        check(all("requested_kernel_collection_or_targeted_loss_incomplete" in
                  sample["network_integrity"]["reasons"] and
                  not sample["network_integrity"]["eligible"] for sample in missing["samples"]),
              "missing requested kernel observations were accepted")
        provenance_path.write_text(original)
        shutil.rmtree(root)
        print("PASS pure TLS netem: 0/20ms, four attempts, TLS decode, cleanup, grouped report")
    except Exception:
        print(f"Artifacts retained: {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
