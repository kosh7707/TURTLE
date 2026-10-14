#!/usr/bin/env python3
"""Compare actual TCP message decryption with OpenSSL's same-run callback."""

import json
from pathlib import Path
import shutil
import sys
import tempfile

from pipeline import check, run, validate_role


def main():
    turtle, report, interpret, adapters, pki = sys.argv[1:]
    root = Path(tempfile.mkdtemp(prefix="turtle-tickets-"))
    try:
        run(turtle, "run", "--client", "openssl", "--server", "openssl",
            "--adapter-dir", adapters, "--pki", pki, "--samples", "2", "--tickets", "2",
            "--mode", "trace", "--no-affinity", "--no-perf", "--output", root / "raw")
        for sample in sorted((root / "raw").glob("sample-*")):
            for role in ("client", "server"):
                raw = sample / f"{role}.jsonl"
                validate_role(raw, "trace", interpret)
                decoded = json.loads(raw.with_suffix(".decoded.json").read_text())["connections"][0]
                plaintext = (sample / f"{role}.plaintext.bin").read_bytes()
                observations = [json.loads(line) for line in
                                (sample / f"{role}.plaintext.jsonl").read_text().splitlines()]
                for outgoing in (True, False):
                    direction = "client_sent" if (role == "client") == outgoing else "server_sent"
                    oracle = [plaintext[item["offset"]] for item in observations
                              if item["content_type"] == 22 and item["outgoing"] == outgoing]
                    actual = [item["handshake_type"] for item in decoded[direction]["messages"]
                              if "handshake_type" in item]
                    check(oracle == actual and actual, "decoded messages differ from same-run library callback")
                tickets = [item for item in decoded["server_sent"]["messages"]
                           if item["name"] == "NewSessionTicket"]
                check(len(tickets) == 2, "requested tickets were not observed")
        run(report, root / "raw", root / "report")
        summary = json.loads((root / "report/summary.json").read_text())
        check(summary["invalid_samples"] == 0, "ticket experiment has invalid boundaries")
        for sample in summary["samples"]:
            if sample["role"] == "client":
                window = sample["connections"][0]["client_hello_to_finished_send"]
                check(window["elapsed_ns"] < sample["connections"][0]["elapsed_ns"],
                      "alternate handshake window does not end before pingpong completion")
        shutil.rmtree(root)
        print("PASS same-TCP-run message oracle, two tickets and alternate boundary")
    except Exception:
        print(f"Artifacts retained: {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
