#!/usr/bin/env python3
r"""Independently verify detailed TCP endpoint artifacts (strace is optional).

Trace a fresh run (never use its timings as performance evidence):
  strace -ff -xx -yy -s 65535 -e trace=sendto,recvfrom -o /tmp/io \
      turtle run spec.json NEW_RUN
  python3 tools/verify_socket_trace.py NEW_RUN /tmp/io > socket-proof.json

Use detailed configurations with io_chunk=2 and io_chunk=0 and measure both
adapters to cover fragmented headers and batched records. By default the suite
must demonstrate all three shapes; --allow-incomplete-shapes is diagnostic.
Paths should be private: strace retains bytes passed to the kernel.
"""
import argparse
import json
import re
import sys
from bisect import bisect_right
from pathlib import Path


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def load(path):
    return json.loads(path.read_text())


# Verify only actual internet TCP sockets. strace -xx avoids ambiguous C
# escapes; -yy gives a socket identifier as well as the fd.
TCP_IO = re.compile(
    r'^(sendto|recvfrom)\((\d+)<TCP:\[([^\]]+)\]>, '
    r'"((?:\\x[\da-f]{2})*)"(\.\.\.)?, (\d+), ([^,]+), .*\)\s+= (\d+)\s*$'
)


def trace_io(path):
    calls = {'send': [], 'receive': []}
    sockets = set()
    for line in path.read_text().splitlines():
        if not line.startswith(('sendto(', 'recvfrom(')) or '<TCP:' not in line:
            continue
        if re.search(r'= -1\b|= \? ', line) or 'MSG_PEEK' in line:
            continue  # retries/errors and non-consuming probes advance no offset
        m = TCP_IO.fullmatch(line)
        require(m is not None, f'{path}: undecodable TCP syscall; expected strace -ff -xx -yy -s 65535')
        op, fd, peer, data, trunc, requested, _, done = m.groups()
        done = int(done)
        if done == 0:
            continue
        sockets.add(fd)
        # TCP may tear down before strace resolves the peer, leaving an inode
        # in place of its tuple; fd and the per-process files remain authoritative.
        raw = bytes.fromhex(data.replace('\\x', ''))
        require(not trunc and done <= int(requested) and len(raw) >= done,
                f'{path}: truncated TCP bytes; increase strace -s')
        calls['send' if op == 'sendto' else 'receive'].append((int(requested), raw[:done]))
    require(len(sockets) == 1 and all(calls.values()), f'{path}: expected one bidirectional TLS socket')
    return calls


def records(data):
    pos, result = 0, []
    while pos < len(data):
        require(pos + 5 <= len(data) and data[pos] in (20, 21, 22, 23) and
                data[pos + 1] == 3 and data[pos + 2] in (1, 2, 3),
                f'{pos}: incomplete/invalid TLS record header')
        end = pos + 5 + int.from_bytes(data[pos + 3:pos + 5], 'big')
        require(end <= len(data), f'{pos}: incomplete TLS record body')
        result.append((pos, end))
        pos = end
    return result


def direction_proof(folder, way, events, calls, reported=None, scenario_end=None):
    sock = [e for e in events if e['direction'] == way and e['kind'] == 'socket' and e['transferred'] > 0]
    hooks = {e['id']: e for e in events if e['direction'] == way and e['kind'] == 'transport'}
    require(len(sock) == len(calls) and bool(hooks), f'{way}: syscall count or public I/O evidence missing')
    stream = b''.join(chunk for _, chunk in calls)
    for name in ('wire_', 'tls_'):
        require((folder / (name + way + '.bin')).read_bytes() == stream, f'{way}: traced bytes != {name}stream')
    parents = {}
    off = 0
    for e, (requested, chunk) in zip(sock, calls):
        a, b = off, off + len(chunk)
        require(e['success'] and e['requested'] == requested and e['transferred'] == b - a and
                (e['wire_begin'], e['wire_end'], e['tls_begin'], e['tls_end']) == (a, b, a, b),
                f"{way}: socket event {e['id']} diverges from traced [{a},{b})")
        parent = e['parent']
        require(parent in hooks, f"{way}: socket event {e['id']} lacks library I/O parent")
        h = hooks[parent]
        require(h['call_id'] == e['call_id'] and h['begin']['wall_ns'] <= e['begin']['wall_ns']
                <= e['end']['wall_ns'] <= h['end']['wall_ns'], f"{way}: hook nesting {parent}")
        parents.setdefault(parent, []).append((a, b))
        off = b
    for hid, h in hooks.items():
        parts = parents.get(hid, [])
        n = sum(b - a for a, b in parts)
        require(h.get('source') in ('openssl_bio', 'adapter_io') and max(0, h['transferred']) == n
                and h['wire_end'] - h['wire_begin'] == n and h['tls_begin'] == h['wire_begin']
                and h['tls_end'] == h['wire_end'], f'{way}: wrong library I/O range {hid}')
        if n:
            require(h['success'] and h['requested'] >= n and parts[0][0] == h['wire_begin'] and
                    parts[-1][1] == h['wire_end'], f'{way}: hook range not covered {hid}')
    # Reassemble TLS from strace data, not the recorder's record numbers.
    rs = records(stream)
    ends = [e['wire_end'] for e in sock]
    split_header = split_record = coalesced = False
    links = []
    measured = []
    if reported is not None:
        # The analysis excludes close_notify. Verify that its cutoff actually
        # coincides with the socket byte count at the first shutdown call.
        task_bytes = sum(len(chunk) for e, (_, chunk) in zip(sock, calls)
                         if events[e['call_id'] - 1]['operation'] != 'shutdown')
        require(scenario_end == task_bytes, f'{way}: measured cutoff differs from syscall evidence')
    for a, b in rs:
        first, last = bisect_right(ends, a), bisect_right(ends, b - 1)
        split_header |= ends[first] < a + 5
        split_record |= first != last
        coalesced |= a > 0 and sock[first]['wire_begin'] < a
        if reported is not None and a < scenario_end:
            require(b <= scenario_end, f'{way}: cutoff inside a TLS record')
            measured.append((a, b))
            row = reported[len(measured)-1]
            require((row['wire_begin'], row['wire_end'], row['body_bytes']) == (a, b, b - a - 5),
                    f'{way}: reported TLS record boundary differs from strace')
            for key, io in [('socket_ranges', sock[first:last + 1]),
                            ('public_io_ranges', [hooks[i] for i in
                             sorted({e['parent'] for e in sock[first:last + 1]})])]:
                expected = []
                for e in io:
                    for part, lo, hi in [('tls_header', a, a + 5), ('tls_payload', a + 5, b)]:
                        x, y = max(lo, e['wire_begin']), min(hi, e['wire_end'])
                        if x < y:
                            expected.append((e['id'], part, x, y))
                got = [(v['event_id'], v['part'], v['wire_begin'], v['wire_end']) for v in row[key]]
                require(got == expected, f"{way}: analysis {key} differs at record {len(measured)}")
        links.append({'range': [a, b], 'body_length': b - a - 5,
                      'socket_ids': [e['id'] for e in sock[first:last + 1]],
                      'library_ids': sorted({e['parent'] for e in sock[first:last + 1]})})
    if reported is not None:
        require(measured and len(measured) == len(reported), f'{way}: analysis record count mismatch')
    if any(h['source'] == 'openssl_bio' for h in hooks.values()):
        headers = [bytes(e['header']) for e in events if e['kind'] == 'header' and e['direction'] == way]
        require(headers == [stream[a:a + 5] for a, _ in rs], f'{way}: OpenSSL header notices differ from traced stream')
    return {'socket_calls': len(sock), 'bytes': off, 'public_io_calls': len(hooks), 'records': links,
            'split_header': split_header, 'split_record': split_record, 'coalesced_records': coalesced}


def verify(root, prefix, allow_incomplete):
    manifest = load(root / 'manifest.json')
    require(manifest['status'] == 'complete' and load(root / 'analysis.json')['complete'],
            'run is incomplete or its required evidence failed')
    checked, pids = [], set()
    for attempt in manifest['attempts']:
        folder = root / attempt['directory']
        peers = [load(folder / r / 'endpoint.json') for r in ('client', 'server')]
        measured = [s for s in peers if s['role'] == s['measured_role']]
        require(len(measured) == 1, 'no unique measured endpoint')
        s = measured[0]
        if s['recording'] != 'detailed':
            continue
        role, pid = s['role'], s['pid']
        require(all(p['run_id'] == attempt['run_id'] and p['status'] == 'ok' for p in peers) and
                s['observations_complete'] and pid not in pids, 'failed attempt, incomplete data or PID reuse')
        pids.add(pid)
        report = load(folder / 'analysis.json')
        require(report['run_id'] == s['run_id'] and report['success'], 'attempt analysis missing/mismatched')
        reported = report['roles'][role]['records']
        folder /= role
        ev = [json.loads(line) for line in (folder / 'events.jsonl').read_text().splitlines()]
        require(all(e['run_id'] == s['run_id'] and e['role'] == role and e['id'] == i
                    for i, e in enumerate(ev, 1)), 'event identity/gap')
        calls = trace_io(Path(f'{prefix}.{pid}'))
        checked.append({'run_id': s['run_id'], 'purpose': s['purpose'], 'pid': pid, 'role': role,
                        'implementation': s['implementation'],
                        'directions': {way: direction_proof(folder, way, ev, c, reported[way],
                            s['scenario']['wire_' + way + '_bytes']) for way, c in calls.items()}})
    require(bool(checked), 'no detailed attempts')
    coverage = {shape: any(d[shape] for a in checked for d in a['directions'].values())
                for shape in ('split_header', 'split_record', 'coalesced_records')}
    require(allow_incomplete or all(coverage.values()), f'missing independent shape evidence: {coverage}')
    return {'schema': 'turtle.socket-trace-proof.v1', 'coverage': coverage, 'attempts': checked}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('run', type=Path)
    parser.add_argument('trace_prefix', type=Path)
    parser.add_argument('--allow-incomplete-shapes', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.run, args.trace_prefix, args.allow_incomplete_shapes)))
    except (ValueError, OSError, KeyError, IndexError, TypeError) as exc:
        sys.exit(f'trace verification failed: {exc}')


if __name__ == '__main__':
    main()
