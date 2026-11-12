#!/usr/bin/env python3
"""Compare actual TCP message decryption with OpenSSL's same-run callback."""

import json
from pathlib import Path
import shutil
import sys
import tempfile

from pipeline import check, run, validate_role
from report_attribution import record_range, validate_server_window


def main():
    turtle, report, interpret, adapters, pki = sys.argv[1:]
    root = Path(tempfile.mkdtemp(prefix="turtle-tickets-"))
    try:
        run(turtle, "--client", "openssl", "--server", "openssl",
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
            else:
                raw = Path(sample["path"])
                rows = [json.loads(line) for line in raw.read_text().splitlines()]
                decoded = json.loads(raw.with_suffix(".decoded.json").read_text())["connections"][0]
                connection = sample["connections"][0]
                window = validate_server_window(
                    connection, rows, decoded, f"ticket profile {raw}"
                )
                _, finished_end = record_range(decoded["server_sent"], "Finished")
                messages = decoded["server_sent"]["messages"]
                later = [message for message in messages
                         if message["name"] in ("NewSessionTicket", "ApplicationData")]
                check(later and all(
                    min(item["begin"] for item in message["record_stream_ranges"]) >= finished_end
                    for message in later
                ), "ticket/application records did not follow the server Finished envelope")
                ccs_begin, ccs_end = record_range(decoded["server_sent"], "ChangeCipherSpec")
                check(ccs_begin < ccs_end <= finished_end and
                      window["elapsed_ns"] < connection["elapsed_ns"],
                      "server window does not include CCS or exclude later completion")
        shutil.rmtree(root)
        print("PASS message oracle, two tickets, and client/server handshake boundaries")
    except Exception:
        print(f"Artifacts retained: {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
