#!/usr/bin/env python3
"""Independently check a raw TLS attempt's TCP copies with TShark (no live privileges)."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess

from check_capture import PACKET_FIELDS, fields_args, flow_from_packets, require, rows


def verify(attempt, executable):
    report = json.loads((attempt / "analysis.json").read_text())
    role, = report["captures"]
    endpoint = json.loads((attempt / role / "endpoint.json").read_text())
    capture = attempt / (role + ".pcap")
    fields = (*PACKET_FIELDS, "tcp.options.sack_le", "tcp.options.sack_re")
    packets = rows(subprocess.check_output(
        [executable, "-n", "-r", str(capture), "-o", "tcp.relative_sequence_numbers:FALSE",
         "-Y", "tcp && ip", *fields_args(fields)], text=True))
    flow = flow_from_packets(packets)
    peers = {"client": "server", "server": "client"}
    bases, records, streams, observed = {}, {}, {}, {}
    for sender, peer in peers.items():
        local = "send" if sender == role else "receive"
        size = endpoint["scenario"]["wire_" + local + "_bytes"]
        streams[sender] = (attempt / role / ("wire_" + local + ".bin")).read_bytes()[:size]
        d = sender + "_to_" + peer
        observed[sender] = report["captures"][role][d]["packets"]
        syn = next(p for p in packets if (p["ip.src"], p["tcp.srcport"]) == flow[sender]
                   and int(p["tcp.flags"], 16) & 2)
        bases[sender] = (int(syn["tcp.seq_raw"]) + 1) % 2**32
        # Use ciphertext lengths from the measured socket image, not TURTLE ordinals.
        offset, records[sender] = 0, []
        while offset < size:
            h = streams[sender][offset:offset+5]
            end = offset + 5 + int.from_bytes(h[3:5], "big")
            require(len(h) == 5 and end <= size, "incomplete TLS record")
            records[sender].append((offset, end))
            offset = end
        require(records[sender] == [(r["wire_begin"], r["wire_end"])
                                     for r in report["roles"][role]["records"][local]], "record mismatch")

    copies, checks = {}, {}
    for sender, peer in peers.items():
        d = sender + "_to_" + peer
        seen = bytearray(len(streams[sender]))
        repeats = Counter()
        by_id = {p["id"]: p for p in observed[sender]}
        count = 0
        for p in packets:
            if (p["ip.src"], p["tcp.srcport"]) != flow[sender]:
                continue
            count += 1
            pid, flags = int(p["frame.number"]), int(p["tcp.flags"], 16)
            cpp = by_id[pid]
            require(int(p["tcp.seq_raw"]) == cpp["sequence"] and int(p["tcp.ack_raw"]) == cpp["ack"],
                    f"SEQ/ACK mismatch at packet {pid}")
            sack = list(zip(*(map(int, p[k].split(",")) if p[k] else []
                              for k in ("tcp.options.sack_le", "tcp.options.sack_re"))))
            require(sack == list(map(tuple, cpp["sack_blocks"])), f"SACK mismatch at packet {pid}")
            payload = bytes.fromhex(p["tcp.payload"].replace(":", ""))
            if not payload:
                continue
            a = (int(p["tcp.seq_raw"]) + bool(flags & 2) - bases[sender]) % 2**32
            b = min(a + len(payload), len(seen))
            repeated_ranges = [(r["wire_begin"],r["wire_end"],r["record"])
                               for r in cpp["retransmitted_record_ranges"]]
            reported = Counter()
            for lo, hi, record in repeated_ranges:
                reported[record] += max(0, min(b, hi)-max(a, lo))
            actual = Counter()
            for index,(lo,hi) in enumerate(records[sender], 1):
                left, right = max(a,lo), min(b,hi)
                if left >= right:
                    continue
                require(payload[left-a:right-a] == streams[sender][left:right],
                        f"capture differs from local TLS at packet {pid}")
                actual[index] += seen[left:right].count(1)
                seen[left:right] = b"\x01" * (right-left)
            require(actual == reported, f"repeated record ranges differ at packet {pid}")
            repeats.update(actual)
            ack = (int(p["tcp.ack_raw"]) - bases[peer]) % 2**32
            copies[pid] = (d, a, a+len(payload), ack, flags & 16)
        require(count == len(by_id) and all(seen), f"incomplete packet/byte coverage: {d}")
        checks[d] = {"packets":count, "scenario_bytes":len(seen),
                     "repeated_bytes_by_record":{r:n for r,n in repeats.items() if n}}
    precedence = report["observations"].get("presend_tcp_order", {})
    for w in precedence.get("ack_witnesses", []):
        d, a, b, ack, ack_flag = copies[w["packet_id"]]
        sender, peer = d.split("_to_")
        rec = records[sender][w["contains_first_byte_of_record"] - 1]
        opp = records[peer][w["peer_record_fully_received_before_this_copy"] - 1]
        require(d == w["direction"] and a <= rec[0] < b and ack_flag and
                ack == w["ack_stream_offset"] and ack >= opp[1], "unsupported copy-specific ACK witness")
    return {"run_id": report["run_id"], "purpose": report["purpose"], "status":"verified",
            "directions":checks,"ack_witnesses":precedence.get("ack_witnesses", [])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args()
    print(json.dumps(verify(args.attempt,args.tshark),indent=2))
