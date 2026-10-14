#!/usr/bin/env python3
"""Normal-path integration only: real TLS -> raw artifacts -> decode -> replay."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, capture_output=True, text=True)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_role(raw, mode, interpret):
    rows = [json.loads(line) for line in raw.read_text().splitlines()]
    header, events = rows[0], rows[1:]
    check(header["valid"], header["invalid_reason"])
    check(not header["declaration"]["is_mock"], "mock used for real TLS test")
    check(header["config"]["isolate"], "isolation was silently disabled")
    for conn in header["connections"]:
        check(conn["negotiated"]["version"] == "TLS1.3", "wrong TLS version")
        check(not conn["negotiated"]["resumed"], "full handshake was resumed")
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
    return header["pid"]


def main():
    turtle, report, interpret, adapters, pki, client, server = sys.argv[1:]
    root = Path(tempfile.mkdtemp(prefix=f"turtle-pipeline-{client}-{server}-"))
    try:
        pids = []
        for mode in ("timing", "memory"):
            for auth in ("server-auth", "mutual-auth"):
                output = root / f"{mode}-{auth}"
                run(turtle, "run", "--client", client, "--server", server,
                    "--adapter-dir", adapters, "--pki", pki, "--samples", "2", "--warmups", "1",
                    "--mode", mode, f"--{auth}", "--no-affinity", "--no-perf", "--output", output)
                for sample in sorted(output.glob("sample-*")):
                    for role in ("client", "server"):
                        pids.append(validate_role(sample / f"{role}.jsonl", mode, interpret))
                    for conn in (0, 1):
                        for source, dest in (("client", "server"), ("server", "client")):
                            sent = (sample / f"{source}.conn-{conn}.sent.bin").read_bytes()
                            received = (sample / f"{dest}.conn-{conn}.received.bin").read_bytes()
                            check(sent == received and sent, "captured directional streams differ")
        check(len(pids) == len(set(pids)), "role process reused across samples")
        run(report, root, root / "report")
        summary = (root / "report/summary.json").read_text()
        data = json.loads(summary)
        check(data["invalid_samples"] == 0, "raw boundaries do not form valid partitions")
        check(len(data["groups"]) == 8, "role/auth/mode groups mixed")
        for sample in data["samples"]:
            for conn in sample["connections"]:
                total = sum(conn[f"{kind}_ns"] for kind in ("computation", "io", "wait", "gap"))
                check(total == conn["elapsed_ns"], "interval conservation failed")
                if sample["role"] == "client":
                    window = conn["client_hello_to_finished_send"]
                    check(window["start_event_sequence"] <= window["end_event_sequence"], "alternate window event order")
                    check(window["elapsed_ns"] <= conn["elapsed_ns"], "alternate window is outside main window")
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
