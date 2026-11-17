#!/usr/bin/env python3
"""원본 pcap을 Wireshark로 읽는 선택적 개발 검증. C++ 분석 결과와 독립 대조한다."""
import argparse
import csv
from decimal import Decimal
import hashlib
from itertools import groupby
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

PLUGIN = Path(__file__).with_name("turtle.lua").resolve()
ROLES = ("client", "server")
DIRECTIONS = ("client_to_server", "server_to_client")
PREFS = ["-o", "tcp.desegment_tcp_streams:TRUE", "-o", "tcp.reassemble_out_of_order:TRUE",
         "-o", "tcp.analyze_sequence_numbers:TRUE"]
PACKET_FIELDS = ("frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.len",
                 "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.len",
                 "tcp.payload", "tcp.stream", "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                 "tcp.analysis.spurious_retransmission", "tcp.analysis.out_of_order")
RECORD_FIELDS = ("frame.number", "ip.src", "tcp.srcport", "turtle.magic", "turtle.record_number",
                 "turtle.tls_type", "turtle.tls_version", "turtle.tls_length", "turtle.tls_record",
                 "tls.record.length", "tls.handshake.type", "_ws.malformed", "turtle.invalid_frame")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fields_args(fields):
    return ["-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=a",
            *[arg for field in fields for arg in ("-e", field)]]


def rows(text):
    return list(csv.DictReader(text.splitlines(), delimiter="\t", quoting=csv.QUOTE_NONE))


class Tshark:
    def __init__(self, executable, directory):
        self.executable = shutil.which(executable)
        if not self.executable:
            raise ValueError(f"tshark 실행 파일 없음: {executable}")
        self.directory = Path(directory)
        self.commands = []

    def run(self, name, args):
        command = [self.executable, *args]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (self.directory / name).write_text(result.stdout)
        (self.directory / (name + ".stderr")).write_text(result.stderr)
        self.commands.append({"argv": command, "returncode": result.returncode,
                              "stdout": name, "stderr": name + ".stderr"})
        save(self.directory / "commands.json", self.commands)
        require(result.returncode == 0, f"tshark 실패: {name}: {result.stderr.strip()[:1000]} (전체 오류는 {name}.stderr)")
        require("Lua Error" not in result.stderr, f"Lua 해석 오류: {name}")
        return result.stdout


def flow_from_packets(packets):
    initial = [p for p in packets if int(p["tcp.flags"], 16) & 0x12 == 2]
    flows = {(p["ip.src"], p["tcp.srcport"], p["ip.dst"], p["tcp.dstport"], p["tcp.stream"]) for p in initial}
    require(len(flows) == 1, "초기 SYN이 있는 단일 IPv4 TCP 연결 필요")
    src, sport, dst, dport, stream = flows.pop()
    require({p["tcp.stream"] for p in packets} == {stream}, "다른 TCP 연결이 캡처에 포함됨")
    return {"client": (src, sport), "server": (dst, dport), "stream": stream}


def follow_stream(text, flow):
    endpoints, streams = {}, [bytearray(), bytearray()]
    for line in text.splitlines():
        if line.startswith("Node "):
            name, address = line.split(": ", 1)
            endpoints[int(name.split()[1])] = tuple(address.rsplit(":", 1))
        elif re.fullmatch(r"\t?[0-9a-fA-F]+", line):
            streams[int(line.startswith("\t"))].extend(bytes.fromhex(line.strip()))
        elif line.strip() and not (line.startswith("=") or line.startswith("Follow:") or line.startswith("Filter:")):
            raise ValueError(f"Follow TCP Stream의 불완전하거나 미지원인 출력: {line[:100]}")
    require(set(endpoints.values()) == {flow["client"], flow["server"]}, "Follow TCP Stream의 연결 불일치")
    return {direction: bytes(streams[next(i for i, ep in endpoints.items() if ep == flow[role])])
            for direction, role in zip(DIRECTIONS, ROLES)}


def decode_records(decoded, flow, wire, tls, expect_hello):
    observations = {d: {} for d in DIRECTIONS}
    hellos = {d: [] for d in DIRECTIONS}
    multi_record_packets = []
    for row in decoded:
        require(not row["_ws.malformed"] and not row["turtle.invalid_frame"],
                f"Wireshark 해석 오류: 패킷 {row['frame.number']}")
        if not row["turtle.record_number"]:
            continue
        direction = DIRECTIONS[0 if (row["ip.src"], row["tcp.srcport"]) == flow["client"] else 1]
        columns = [row[f].split(",") for f in RECORD_FIELDS[3:9]]
        require(len({len(c) for c in columns}) == 1, "Wireshark 레코드 필드 개수 불일치")
        if len(columns[0]) > 1:
            multi_record_packets.append(int(row["frame.number"]))
        require(row["tls.record.length"].split(",") == columns[4], "내장 TLS 해석기와 길이 불일치")
        for magic, number, kind, version, size, raw in zip(*columns):
            number, kind, version, size = int(number), int(kind), int(version, 16), int(size)
            record = bytes.fromhex(raw.replace(":", ""))
            require(magic == "TU" and number > 0, "프레임 매직 또는 번호 불일치")
            require(record[:5] == bytes([kind]) + version.to_bytes(2, "big") + size.to_bytes(2, "big")
                    and len(record) == 5 + size, "TLS 원본 필드 불일치")
            old = observations[direction].get(number)
            require(old is None or old["tls_hex"] == record.hex(), "같은 방향·번호의 TLS 바이트 불일치")
            if old is None:
                observations[direction][number] = {"number": number, "content_type": kind,
                    "tls_payload_bytes": size, "tls_hex": record.hex(), "dissected_in_packets": []}
            observations[direction][number]["dissected_in_packets"].append(int(row["frame.number"]))
        if row["tls.handshake.type"]:
            hellos[direction].extend(int(x) for x in row["tls.handshake.type"].split(","))
    result = {}
    for direction in DIRECTIONS:
        selected = observations[direction]
        require(sorted(selected) == list(range(1, len(selected) + 1)), f"방향별 번호 누락: {direction}")
        framed, original, records = bytearray(), bytearray(), []
        for number in sorted(selected):
            row = selected[number]
            raw = bytes.fromhex(row.pop("tls_hex"))
            row.update(wire_begin=len(framed), tls_begin=len(original))
            framed.extend(b"TU" + number.to_bytes(2, "big") + raw)
            original.extend(raw)
            row.update(wire_end=len(framed), tls_end=len(original))
            records.append(row)
        require(framed == wire[direction], f"Wireshark 레코드와 wire 스트림 불일치: {direction}")
        require(original == tls[direction], f"Wireshark 프레임 제거와 원본 TLS 불일치: {direction}")
        result[direction] = records
    if expect_hello:
        require(1 in hellos[DIRECTIONS[0]] and 2 in hellos[DIRECTIONS[1]], "내장 TLS 해석기의 Hello 관측 누락")
    return result, hellos, multi_record_packets


def verify_packets(packets, flow, wire, records, core=None):
    result = {}
    for direction, role in zip(DIRECTIONS, ROLES):
        selected = [p for p in packets if (p["ip.src"], p["tcp.srcport"]) == flow[role]]
        syn = next((p for p in selected if int(p["tcp.flags"], 16) & 2), None)
        require(syn is not None, f"SYN 누락: {direction}")
        initial = int(syn["tcp.seq_raw"])
        expected, seen = wire[direction], bytearray(len(wire[direction]))
        # 독립 확인: 코어의 구간 병합 대신 바이트별 방문 비트와 레코드 소속을 사용한다.
        labels = []
        for r in records[direction]:
            labels.extend([(r["number"], "frame_header", None)] * 4)
            labels.extend((r["number"], "tls_header" if i < 5 else "tls_payload", r["tls_begin"] + i)
                          for i in range(r["tls_end"] - r["tls_begin"]))
        payload_bytes = repeated = 0
        packet_rows, flags_count = [], {f: 0 for f in PACKET_FIELDS[14:]}
        for p in selected:
            flags, seq = int(p["tcp.flags"], 16), int(p["tcp.seq_raw"])
            raw = bytes.fromhex(p["tcp.payload"].replace(":", ""))
            size = int(p["tcp.len"])
            require(size == len(raw), "TCP 페이로드 길이 불일치")
            begin = (seq + bool(flags & 2) - initial - 1) & 0xffffffff
            end = begin + size
            duplicates, links = [], []
            if raw:
                require(end <= len(expected) and expected[begin:end] == raw, f"TCP 바이트 불일치: {direction}, 패킷 {p['frame.number']}")
                for visited, positions in groupby(range(begin, end), key=seen.__getitem__):
                    positions = list(positions)
                    if visited:
                        duplicates.append([positions[0], positions[-1] + 1])
                        repeated += len(positions)
                seen[begin:end] = b"\1" * size
                payload_bytes += size
                for (number, part), positions in groupby(range(begin, end), key=lambda i: labels[i][:2]):
                    positions = list(positions)
                    a, b = positions[0], positions[-1] + 1
                    links.append({"record": number, "part": part, "wire_begin": a, "wire_end": b,
                                  "tls_begin": labels[a][2], "tls_end": None if part == "frame_header" else labels[b-1][2] + 1})
            row = {"id": int(p["frame.number"]), "timestamp_ns": int(Decimal(p["frame.time_epoch"]) * 1_000_000_000),
                   "src": p["ip.src"], "dst": p["ip.dst"], "sport": int(p["tcp.srcport"]), "dport": int(p["tcp.dstport"]),
                   "sequence": seq, "ack": int(p["tcp.ack_raw"]), "flags": flags,
                   "link_bytes": int(p["frame.len"]), "ip_bytes": int(p["ip.len"]),
                   "wire_begin": begin if raw else None, "wire_end": end if raw else None,
                   "payload_bytes": size, "retransmitted_ranges": duplicates, "records": links}
            packet_rows.append(row)
            for field in flags_count:
                flags_count[field] += bool(p[field])
        require(all(seen), f"TCP 바이트 수집 누락: {direction}")
        if core is not None:
            original = core[direction]
            require(original["availability"] == "available" and original["full_stream_matches"]
                    and original["full_coverage_complete"], f"TURTLE 캡처 분석 미완료: {direction}")
            require(packet_rows == original["packets"], f"TURTLE 패킷·재전송·레코드 범위와 불일치: {direction}")
            require(payload_bytes == original["payload_bytes"] and repeated == original["retransmitted_payload_bytes"],
                    f"TURTLE 바이트 합계 불일치: {direction}")
        result[direction] = {"packet_count": len(selected), "unique_payload_bytes": len(expected),
                             "payload_bytes": payload_bytes, "retransmitted_payload_bytes": repeated,
                             "wireshark_packet_flags": flags_count, "packets": packet_rows}
    return result


def verify_capture(runner, name, pcap, wire, tls, core=None, expect_hello=True):
    base = ["-n", "-2", "-r", str(pcap), *PREFS]
    packets = rows(runner.run(name + "-packets.tsv", [*base, "-Y", "tcp && ip", *fields_args(PACKET_FIELDS)]))
    flow = flow_from_packets(packets)
    follow = runner.run(name + "-follow.txt", [*base, "-q", "-z", "follow,tcp,raw," + flow["stream"]])
    require(follow_stream(follow, flow) == wire, f"Follow TCP Stream 바이트 불일치: {name}")
    decode = [*base, "-X", "lua_script:" + str(PLUGIN), "-d", f"tcp.port=={flow['server'][1]},turtle"]
    decoded = rows(runner.run(name + "-records.tsv", [*decode, "-Y", "turtle || _ws.malformed", *fields_args(RECORD_FIELDS)]))
    records, hellos, multiple = decode_records(decoded, flow, wire, tls, expect_hello)
    checked = verify_packets(packets, flow, wire, records, core)
    runner.run(name + "-details.txt", [*decode, "-Y", "turtle", "-V"])
    return {"flow": flow, "records": records, "native_tls_handshake_types": hellos,
            "multiple_records_in_packets": multiple, "directions": checked}


def verify_attempt(attempt, output, executable="tshark"):
    attempt, output = Path(attempt).resolve(), Path(output).resolve()
    require(not output.is_relative_to(attempt), "검증 출력은 원자료 시도 디렉터리 밖에 둡니다")
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema": "turtle.wireshark-verification.v1", "purpose": "development_validation_only",
              "attempt": str(attempt), "status": "failed", "captures": {}}
    inputs = [attempt / "analysis.json", *(attempt / (r + ".pcap") for r in ROLES),
              *(attempt / r / f for r in ROLES for f in ("endpoint.json", "tls_send.bin", "tls_receive.bin", "wire_send.bin", "wire_receive.bin"))]
    try:
        result["input_sha256"] = {str(p.relative_to(attempt)): digest(p) for p in inputs}
        result["tool_sha256"] = {p.name: digest(p) for p in (PLUGIN, Path(__file__))}
        runner = Tshark(executable, output)
        result["tshark_version"] = runner.run("version.txt", ["--version"]).splitlines()[0]
        analysis = json.loads((attempt / "analysis.json").read_text())
        require(analysis["schema"] == "turtle.attempt-report.v4" and analysis["success"] and analysis["network_complete"],
                "성공과 네트워크 수집이 완료된 v3 시도 필요")
        wire, tls = {}, {}
        for direction, sender, receiver in zip(DIRECTIONS, ROLES, reversed(ROLES)):
            for target, suffix in ((wire, "wire"), (tls, "tls")):
                target[direction] = (attempt / sender / (suffix + "_send.bin")).read_bytes()
                require(target[direction] == (attempt / receiver / (suffix + "_receive.bin")).read_bytes(),
                        f"양쪽 엔드포인트 {suffix} 스트림 불일치: {direction}")
        for role in ROLES:
            result["captures"][role] = verify_capture(runner, role, attempt / (role + ".pcap"), wire, tls, analysis["captures"][role])
        require(result["input_sha256"] == {str(p.relative_to(attempt)): digest(p) for p in inputs}, "검증 중 원자료 변경")
        result["status"] = "passed"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
        raise
    finally:
        save(output / "verification.json", result)
    return result


def gui_command(attempt, role, tshark="tshark", wireshark="wireshark"):
    pcap = Path(attempt).resolve() / (role + ".pcap")
    command = [tshark, "-n", "-r", str(pcap), "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "-T", "fields", "-e", "tcp.dstport"]
    ports = set(subprocess.run(command, check=True, capture_output=True, text=True, timeout=60).stdout.split())
    require(len(ports) == 1, "GUI 열기: 단일 서버 포트를 찾을 수 없음")
    return [wireshark, "-r", str(pcap), "-X", "lua_script:" + str(PLUGIN), "-d", f"tcp.port=={ports.pop()},turtle", *PREFS,
            "-Y", "turtle || tcp.analysis.retransmission || tcp.analysis.out_of_order"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="완료한 시도를 읽어 별도 디렉터리에 검증 저장")
    verify.add_argument("attempt", type=Path)
    verify.add_argument("output", type=Path)
    verify.add_argument("--tshark", default="tshark")
    gui = sub.add_parser("open", help="원본 pcap을 TURTLE 해석기와 함께 GUI에서 열기")
    gui.add_argument("attempt", type=Path)
    gui.add_argument("--capture", choices=ROLES, default="client")
    gui.add_argument("--tshark", default="tshark")
    gui.add_argument("--wireshark", default="wireshark")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            result = verify_attempt(args.attempt, args.output, args.tshark)
            print(f"{result['status']}: {args.output / 'verification.json'}")
        else:
            subprocess.run(gui_command(args.attempt, args.capture, args.tshark, args.wireshark), check=True)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Wireshark 검증 실패: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
