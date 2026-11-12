#!/usr/bin/env python3
"""Normal-path integration only: real TLS -> raw artifacts -> decode -> replay."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from tls_transcript import tls_records, validate_wire_hellos
from report_attribution import (
    SERVER_WINDOW,
    SERVER_WINDOW_DEFINITION,
    validate_available_attribution,
    validate_no_attribution_metrics,
    validate_server_window,
)


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, capture_output=True, text=True)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_tcp_read_policy(stream, events, connection, context):
    records = tls_records(stream, f"{context} received")
    receives = [
        event for event in events
        if event.get("connection") == connection and
        event.get("kind") == "IO_RECV_RETURN" and
        event.get("result") == 0 and event.get("transferred", 0) > 0
    ]
    check(records and receives, f"{context}: missing TLS records or successful receives")
    completed = set()
    for event in receives:
        begin, end = event["stream_begin"], event["stream_end"]
        matches = [record for record in records if record["begin"] <= begin < record["end"]]
        check(len(matches) == 1, f"{context}: receive begins outside one TLS record")
        record = matches[0]
        boundary = record["header_end"] if begin < record["header_end"] else record["end"]
        check(event["requested"] == boundary - begin,
              f"{context}: receive did not request the exact header/body remainder")
        check(end - begin == event["transferred"] and end <= boundary,
              f"{context}: receive crossed a header, body, or next-record boundary")
        if end == record["end"]:
            completed.add(record["begin"])
    check(len(completed) == len(records),
          f"{context}: not every TLS record body has a successful completion return")


def validate_role(raw, mode, interpret):
    rows = [json.loads(line) for line in raw.read_text().splitlines()]
    header, events = rows[0], rows[1:]
    check(header["valid"], header["invalid_reason"])
    check(not header["declaration"]["is_mock"], "mock used for real TLS test")
    check(header["declaration"].get("read_ahead") is False and
          bool(header["declaration"].get("read_ahead_note")),
          "real adapter read-ahead policy is absent or unsupported")
    check(header["config"]["isolate"], "isolation was silently disabled")
    for conn in header["connections"]:
        socket = conn["socket"]
        check(socket is not None, "configured socket settings were not observed")
        check(set(socket) == {
            "nonblocking", "tcp_nodelay", "send_buffer", "receive_buffer",
            "kernel_timestamps",
            "kernel_tx_timestamps", "kernel_tx_timestamp_error", "kernel_tx_drain_error",
        }, "socket settings schema changed")
        check(socket["nonblocking"] is True, "socket is not nonblocking")
        check(socket["tcp_nodelay"] == header["config"]["tcp_nodelay"],
              "TCP_NODELAY differs from requested configuration")
        check(socket["send_buffer"] > 0, "invalid effective send buffer")
        check(socket["receive_buffer"] > 0, "invalid effective receive buffer")
        check(isinstance(socket["kernel_timestamps"], bool),
              "kernel timestamp state was not recorded")
        check(socket['kernel_tx_timestamps'] is False and socket['kernel_tx_timestamp_error'] == 0,
              'ordinary runs unexpectedly enabled TX tracing')
        check(conn["negotiated"]["version"] == "TLS1.3", "wrong TLS version")
        check(conn["negotiated"]["cipher"] == "TLS_AES_128_GCM_SHA256",
              "wrong TLS cipher suite")
        check(conn["negotiated"]["group"] == "secp256r1", "wrong TLS group")
        check(not conn["negotiated"]["resumed"], "full handshake was resumed")
        check(not conn["negotiated"]["hello_retry_request"],
              "adapter reported HelloRetryRequest")
        check(conn["application_verified"], "encrypted pingpong not verified")
    check(len(events) > 10, "missing measured boundaries")
    check(all(a["sequence"] < b["sequence"] for a, b in zip(events, events[1:])), "event order")
    if mode == "timing" or not header["capabilities"]["heap_tracking"]:
        check(all(e["heap"] is None for e in events), "unsupported heap synthesized")
    else:
        check(any(e["heap"] and e["heap"]["peak"] > 0 for e in events), "allocator hook unused")
    if not header["capabilities"]["perf"]:
        check(all(e["cycles"] is None for e in events), "unavailable cycles synthesized")
    decoded = raw.with_suffix(".decoded.json")
    run(interpret, raw, decoded)
    for connection in json.loads(decoded.read_text())["connections"]:
        check(connection["decryption_complete"], "TLS stream was not fully decoded")
        for direction in ("client_sent", "server_sent"):
            messages = connection[direction]["messages"]
            names = [message["name"] for message in messages]
            check("Finished" in names, "missing Finished")
            check("ApplicationData" in names, "missing application record")
        index = connection["connection"]
        prefix = raw.parent / raw.stem
        sent = (prefix.parent / f"{prefix.name}.conn-{index}.sent.bin").read_bytes()
        received = (prefix.parent / f"{prefix.name}.conn-{index}.received.bin").read_bytes()
        client_stream, server_stream = ((sent, received) if header["role"] == "client"
                                        else (received, sent))
        validate_tcp_read_policy(
            received, events, index, f"{header['role']} capture connection {index}"
        )
        validate_wire_hellos(
            client_stream, server_stream,
            f"{header['role']} capture connection {index}",
        )
    return header["pid"]


def validate_report_evidence(data):
    for sample in data["samples"]:
        raw = Path(sample["path"])
        rows = [json.loads(line) for line in raw.read_text().splitlines()]
        decoded = json.loads(raw.with_suffix(".decoded.json").read_text())
        decoded_by_index = {
            connection["connection"]: connection
            for connection in decoded["connections"]
        }
        for connection in sample["connections"]:
            index = connection["connection"]
            context = f"{raw} connection {index}"
            decoded_connection = decoded_by_index[index]
            validate_available_attribution(
                connection, rows, decoded_connection, sample["role"], context
            )
            if sample["role"] == "server":
                validate_server_window(connection, rows, decoded_connection, context)
            else:
                check(SERVER_WINDOW not in connection,
                      f"{context}: client fabricated a server-only window")

    validate_no_attribution_metrics(data["groups"])
    for group in data["groups"]:
        metrics = group["metrics"]
        if group["dimensions"]["role"] == "server":
            metadata = group.get(SERVER_WINDOW, {})
            check(metadata.get("definition") == SERVER_WINDOW_DEFINITION,
                  "server group lacks the new window definition")
            for suffix in ("elapsed_ns", "thread_cpu_ns"):
                metric = metrics.get(f"{SERVER_WINDOW}_{suffix}", {})
                check(metric.get("count") == 2,
                      f"server group lost {SERVER_WINDOW}_{suffix} samples")
        else:
            check(not any(name.startswith(f"{SERVER_WINDOW}_") for name in metrics),
                  "client group contains server-only window metrics")


def main():
    turtle, report, interpret, adapters, pki, client, server = sys.argv[1:8]
    connections = int(sys.argv[8]) if len(sys.argv) > 8 else 1
    root = Path(tempfile.mkdtemp(prefix=f"turtle-pipeline-{client}-{server}-"))
    try:
        pids = []
        for mode in ("timing", "memory"):
            for auth in ("server-auth", "mutual-auth"):
                output = root / f"{mode}-{auth}"
                run(turtle, "run", "--client", client, "--server", server,
                    "--adapter-dir", adapters, "--pki", pki, "--samples", "2", "--warmups", "1",
                    "--connections", str(connections),
                    "--mode", mode, f"--{auth}", "--no-affinity", "--no-perf", "--output", output)
                for sample in sorted(output.glob("sample-*")):
                    for role in ("client", "server"):
                        pids.append(validate_role(sample / f"{role}.jsonl", mode, interpret))
                    for conn in range(1 + connections):
                        for source, dest in (("client", "server"), ("server", "client")):
                            sent = (sample / f"{source}.conn-{conn}.sent.bin").read_bytes()
                            received = (sample / f"{dest}.conn-{conn}.received.bin").read_bytes()
                            check(sent == received and sent, "captured directional streams differ")
        check(len(pids) == len(set(pids)), "role process reused across samples")
        run(report, root, root / "report")
        summary = (root / "report/summary.json").read_text()
        data = json.loads(summary)
        check(data["invalid_samples"] == 0, "raw boundaries do not form valid partitions")
        check(len(data["groups"]) == 8 * connections, "role/auth/mode/connection groups mixed")
        for group in data["groups"]:
            check(len(group["metrics"]["elapsed_ns"]["values"]) == 2,
                  "connections from the same process were pooled as independent samples")
        for sample in data["samples"]:
            check(len(sample["connections"]) == connections, "measured connections missing")
            for conn in sample["connections"]:
                total = sum(conn[f"{kind}_ns"] for kind in ("computation", "io", "wait", "gap"))
                check(total == conn["elapsed_ns"], "interval conservation failed")
                if sample["role"] == "client":
                    window = conn["client_hello_to_finished_send"]
                    check(window["start_event_sequence"] <= window["end_event_sequence"], "alternate window event order")
                    check(window["elapsed_ns"] <= conn["elapsed_ns"], "alternate window is outside main window")
        validate_report_evidence(data)
        run(report, root, root / "report")
        check((root / "report/summary.json").read_text() == summary, "raw replay changed statistics")
        shutil.rmtree(root)
        print(f"PASS {client} -> {server}: isolated real TLS, decrypt, partition, replay")
    except Exception as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout, error.stderr, file=sys.stderr)
        print(f"Artifacts retained: {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
