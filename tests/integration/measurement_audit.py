#!/usr/bin/env python3
"""실제 양쪽 TLS 자료를 독립 계산으로 대조합니다. 인터넷을 사용하지 않습니다."""
import argparse
import copy
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from tls_transcript import tls_records, validate_wire_hellos


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def run(command, log):
    command = list(map(str, command))
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    log.write_text(json.dumps(command) + '\n' + result.stdout + result.stderr)
    require(result.returncode == 0, f'{log}: exit {result.returncode}')


def verify_bytes(events, direction, stream):
    kind = 'IO_SEND_RETURN' if direction == 'sent' else 'IO_RECV_RETURN'
    offset = 0
    for event in events:
        if event['kind'] != kind:
            continue
        require(event['stream_begin'] == offset, 'stream overlap or omitted bytes')
        count = event['transferred']
        require(event['result'] == 0 or count == 0, 'unsuccessful I/O counted bytes')
        offset += count
        require(event['stream_end'] == offset, 'stream end differs from successful bytes')
    require(offset == len(stream) and offset > 0, 'stream capture differs from I/O bytes')
    tls_records(stream, direction)


def verify_partition(part, local, start, end, heap):
    require(part['start_ns'] == start['monotonic_ns'] and
            part['end_ns'] == end['monotonic_ns'], 'primary endpoint differs from raw contract')
    require(part['elapsed_ns'] == end['monotonic_ns'] - start['monotonic_ns'], 'elapsed delta')
    require(part['thread_cpu_ns'] == end['thread_cpu_ns'] - start['thread_cpu_ns'], 'CPU delta')
    # Sum closed raw intervals, not the report's adjacent-event state machine.
    # I/O is inside calls, waits are outside calls; subtract the intersection once.
    totals = {'calls': 0, 'io': 0, 'wait': 0}
    pending = {}
    for event in local:
        kind = event['kind']
        group = ('calls' if kind in ('CALL_BEGIN', 'CALL_END') else
                 'io' if kind.startswith('IO_') else
                 'wait' if kind in ('WAIT_BEGIN', 'WAIT_END') else None)
        if group is None:
            continue
        if kind.endswith(('_BEGIN', '_ENTER')):
            require(group not in pending, 'overlapping raw boundary interval')
            pending[group] = event
        else:
            require(group in pending, 'unpaired raw boundary')
            begin = pending.pop(group)
            lo = max(begin['monotonic_ns'], start['monotonic_ns'])
            hi = min(event['monotonic_ns'], end['monotonic_ns'])
            totals[group] += max(0, hi - lo)
    require(not pending, 'unfinished raw intervals')
    expected = {'computation_ns': totals['calls'] - totals['io'],
                'io_ns': totals['io'], 'wait_ns': totals['wait'],
                'gap_ns': part['elapsed_ns'] - totals['calls'] - totals['wait']}
    require(all(part[k] == v for k, v in expected.items()), 'cost attribution differs from raw intervals')
    if heap:
        snapshots = [e for e in local if start['sequence'] < e['sequence'] <= end['sequence'] and
                     e['kind'] != 'KERNEL_RX']  # shares the receive snapshot; no new meter read
        expected_peak = max([start['heap']['live']] + [e['heap']['interval_peak'] for e in snapshots])
        require(part['heap_peak_bytes'] == expected_peak, 'heap interval peak')
    else:
        require(part['heap_peak_bytes'] is None, 'unobserved heap became numeric')
    return expected


def verify_flush_calls(events):
    ends = [e for e in events if e['kind'] == 'CALL_END' and e['call'] == 'output_flush']
    require(ends, 'Finished+Ping has no output flush boundary')
    for end in ends:
        call = [e for e in events if e['call_id'] == end['call_id']]
        begin = next(e for e in call if e['kind'] == 'CALL_BEGIN')
        sends = [e for e in call if e['kind'] == 'IO_SEND_RETURN']
        require(len(sends) == 1, 'flush must describe one socket submission')
        sent = sends[0]
        require(begin['requested'] == sent['requested'] == end['requested'] > 0,
                'flush requested bytes differ from socket submission')
        for field in ('result', 'transferred', 'system_error'):
            require(end[field] == sent[field], f'flush lost I/O {field}')


def verify_case(case, analysis, scenario, mode, linkage, connections, warmups):
    rows_by_role = {}
    for role in ('client', 'server'):
        raw = case / role / 'raw' / f'{role}.jsonl'
        rows = [json.loads(line) for line in raw.read_text().splitlines()]
        rows_by_role[role] = rows
        h, events = rows[0], rows[1:]
        require(h['valid'] and not h['declaration']['is_mock'], 'normal TLS failed')
        require(h['schema'] == 3 and h['measurement_contract_revision'] == 4 and
                h['control_protocol'] == 2, 'contract versions changed')
        require(h['adapter_connection']['mode'] == linkage, 'adapter linkage differs')
        require(h['capture_dropped'] == 0, 'capture lost events')
        require([e['sequence'] for e in events] == list(range(1, len(events) + 1)), 'capture sequence')
        require([c['index'] for c in h['connections']] == list(range(connections + warmups)), 'connection IDs')
        require([c['warmup'] for c in h['connections']] ==
                [True] * warmups + [False] * connections, 'warmup placement')
        require(all(e['run_id'] == h['run_id'] and e['context_id'] == h['context_id']
                    for e in events), 'event identity')
        run([analysis / 'turtle-interpret', raw, raw.with_suffix('.decoded.json')], case / f'{role}-decode.log')
        decoded = json.loads(raw.with_suffix('.decoded.json').read_text())
        for conn, d in zip(h['connections'], decoded['connections'], strict=True):
            index = conn['index']
            local = [e for e in events if e['connection'] == index]
            if scenario == 'finished-ping' and role == 'server':
                verify_flush_calls(local)
            require(conn['scenario_completed'] and d['decryption_complete'], 'incomplete scenario/decode')
            require(conn['application_verified'] == (scenario != 'handshake'), 'application applicability')
            require(conn['negotiated']['version'] == 'TLS1.3' and
                    not conn['negotiated']['resumed'] and not conn['negotiated']['hello_retry_request'], 'full TLS')
            require(conn['verification'] == ('passed' if role == 'client' or h['config']['tls']['mutual_auth']
                                             else 'not_applicable'), 'authentication result')
            streams = {}
            for direction in ('sent', 'received'):
                streams[direction] = (raw.parent / f'{role}.conn-{index}.{direction}.bin').read_bytes()
                verify_bytes(local, direction, streams[direction])
            cstream, sstream = ((streams['sent'], streams['received']) if role == 'client' else
                               (streams['received'], streams['sent']))
            validate_wire_hellos(cstream, sstream, str(raw))
            for direction, count in (('client_sent', h['config']['tls']['client_application_bytes']),
                                     ('server_sent', h['config']['tls']['server_application_bytes'])):
                messages = d[direction]['messages']
                require(sum(m['name'] == 'Finished' for m in messages) == 1, 'Finished message count')
                require(sum(m['length'] for m in messages if m['name'] == 'ApplicationData') ==
                        (0 if scenario == 'handshake' else count), 'decoded application bytes')
            if mode == 'trace' and h['declaration']['plaintext_hook']:
                plaintext = (raw.parent / f'{role}.plaintext.bin').read_bytes()
                notices = [json.loads(line) for line in (raw.parent / f'{role}.plaintext.jsonl').read_text().splitlines()]
                for outgoing in (True, False):
                    direction = 'client_sent' if (role == 'client') == outgoing else 'server_sent'
                    oracle = [plaintext[n['offset']] for n in notices if n['connection'] == index and
                              n['content_type'] == 22 and n['outgoing'] == outgoing]
                    actual = [m['handshake_type'] for m in d[direction]['messages'] if 'handshake_type' in m]
                    require(oracle == actual, 'library plaintext notifications differ from decoded messages')
    require(rows_by_role['client'][0]['run_id'] == rows_by_role['server'][0]['run_id'], 'run identity')
    for index in range(connections + warmups):
        for role, peer in (('client', 'server'), ('server', 'client')):
            sent = (case / role / 'raw' / f'{role}.conn-{index}.sent.bin').read_bytes()
            received = (case / peer / 'raw' / f'{peer}.conn-{index}.received.bin').read_bytes()
            require(sent == received, 'opposite endpoints captured different TLS bytes')
    run([analysis / 'turtle-report', '--pair', case / 'client/raw/client.jsonl',
         case / 'server/raw/server.jsonl', case / 'report'], case / 'report.log')
    summary = json.loads((case / 'report/summary.json').read_text())
    require(summary['invalid_samples'] == 0, 'report rejected normal TLS evidence')
    checks = []
    for sample in summary['samples']:
        role = sample['role']
        h, *events = rows_by_role[role]
        require(len(sample['connections']) == connections, 'warmups in statistics or measured connection omitted')
        for part in sample['connections']:
            index = part['connection']
            local = [e for e in events if e['connection'] == index]
            # Select from the scenario's meaning, independently of end_sequence.
            start = next(e for e in local if e['kind'] == 'CALL_BEGIN' and e['call'] == 'handshake') if role == 'client' else next(
                             e for e in local if e['kind'] == 'IO_RECV_RETURN' and e['transferred'] > 0)
            if scenario == 'handshake':
                end = next(e for e in local if e['kind'] == 'CALL_END' and e['call'] == 'handshake' and e['result'] == 2)
            else:
                server_first = scenario in ('server-ping', 'finished-ping')
                final_send = (role == 'client') == server_first
                end = [e for e in local if e['kind'] == 'CALL_END' and e['result'] == 2 and
                       e['call'] == ('app_send' if final_send else 'app_recv')][-1]
            require(h['connections'][index]['start_sequence'] == start['sequence'] and
                    h['connections'][index]['end_sequence'] == end['sequence'], 'raw measurement endpoint')
            expected = verify_partition(part, local, start, end, h['capabilities']['heap_tracking'])
            windows = part['prototype']['windows']
            require(windows['module_load']['status'] ==
                    ('not_applicable' if linkage == 'builtin' or index else 'available'), 'module-load applicability')
            if mode != 'trace':
                require(part['prototype']['internal_spans_complete'] is None, 'disabled trace became complete')
            elif h['declaration']['internal_events']:
                require(part['prototype']['internal_spans_complete'], 'internal spans missing')
            checks.append({'role': role, 'connection': index, 'start': start['sequence'],
                           'end': end['sequence'], 'independent_partition_ns': expected,
                           'heap_peak_bytes': part['heap_peak_bytes']})
    require(all(g['metrics']['elapsed_ns']['count'] == 1 for g in summary['groups']),
            'same-context connections treated as independent samples')
    if scenario != 'handshake':
        server_first = scenario in ('server-ping', 'finished-ping')
        for group in summary['groups']:
            common = group['handshake_call_begin_to_application_complete']
            require(common['client_end_call'] == ('app_send' if server_first else 'app_recv') and
                    common['server_end_call'] == ('app_recv' if server_first else 'app_send'),
                    'common-window metadata names the wrong final operation')
    # Deliberately corrupted copies must fail the independent oracle.
    bad = copy.deepcopy(local)
    successful = next(e for e in bad if e['kind'] == 'IO_SEND_RETURN' and e['transferred'])
    successful['transferred'] += 1
    try:
        verify_bytes(bad, 'sent', sent)
    except AssertionError:
        pass
    else:
        raise AssertionError('byte-duplication mutation escaped oracle')
    bad_part = copy.deepcopy(part)
    bad_part['computation_ns'] += 1
    try:
        verify_partition(bad_part, local, start, end, h['capabilities']['heap_tracking'])
    except AssertionError:
        pass
    else:
        raise AssertionError('double-counted computation escaped oracle')
    return checks


def execute_case(case, build, module, pki, analysis, scenario, mode, policy, mutual,
                 connections=1, warmups=0, size=32):
    case.mkdir(parents=True)
    for role in ('client', 'server'):
        (case / role).mkdir()
    ready = case / 'server/ready.json'
    common = ['--pki', str(pki), '--no-affinity', '--no-perf', '--scenario', scenario,
              '--mode', mode, '--send-policy', policy, '--connections', str(connections),
              '--warmups', str(warmups), '--client-bytes', str(size), '--server-bytes', str(size + 1),
              '--timeout-ms', '30000', '--output', 'raw']
    if module:
        common += ['--module', str(module)]
    if mutual:
        common += ['--mutual-auth']
    server_command = [str(build / 'turtle-server'), *common, '--listen', '127.0.0.1:0',
                      '--control-listen', '127.0.0.1:0', '--ready-file', str(ready)]
    with (case / 'server.log').open('w') as log:
        log.write(json.dumps(server_command) + '\n'); log.flush()
        server = subprocess.Popen(server_command, cwd=case / 'server', stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                require(server.poll() is None, f'server exited: {case}')
                try:
                    ports = json.loads(ready.read_text()); break
                except (OSError, json.JSONDecodeError):
                    require(time.monotonic() < deadline, 'listener not ready')
                    time.sleep(.005)
            command = [str(build / 'turtle-client'), *common, '--connect', f"127.0.0.1:{ports['port']}",
                       '--control-connect', f"127.0.0.1:{ports['control_port']}"]
            result = subprocess.run(command, cwd=case / 'client', capture_output=True, text=True, timeout=35)
            (case / 'client.log').write_text(json.dumps(command) + '\n' + result.stdout + result.stderr)
            require(result.returncode == 0, f'client exited: {case}')
            require(server.wait(timeout=35) == 0, f'server failed: {case}')
        finally:
            if server.poll() is None:
                server.kill(); server.wait()
    return verify_case(case, analysis, scenario, mode, 'module' if module else 'builtin', connections, warmups)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True, help='module/analysis build')
    parser.add_argument('--pki', type=Path, required=True)
    parser.add_argument('--builtin', action='append', default=[], help='library=build path')
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    build, pki = args.build.resolve(), args.pki.resolve()
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='turtle-measurement-'))
    output.mkdir(parents=True, exist_ok=True)
    builds = [(lib, build, build / 'adapters' / f'{lib}.so') for lib in ('openssl', 'wolfssl', 'mbedtls')
              if (build / 'adapters' / f'{lib}.so').exists()]
    builds += [(value.split('=', 1)[0], Path(value.split('=', 1)[1]).resolve(), None) for value in args.builtin]
    results = []
    try:
        for (lib, endpoint, module), scenario, mode, policy, mutual in itertools.product(
                builds, ('handshake', 'server-ping', 'finished-ping', 'client-request'),
                ('timing', 'memory', 'trace'), ('native', 'server-hello-first'), (False, True)):
            if args.quick and (policy != 'server-hello-first' or not mutual):
                continue
            case = output / f'{lib}-{"module" if module else "builtin"}-{scenario}-{mode}-{policy}-{int(mutual)}'
            checks = execute_case(case, endpoint, module, pki, build, scenario, mode, policy, mutual)
            results.append({'case': case.name, 'status': 'passed', 'checks': checks})
            (output / 'verification.json').write_text(json.dumps(results, indent=2) + '\n')
        for lib, endpoint, module in builds:
            for size in (16383, 16384, 16385):
                case = output / f'{lib}-{"module" if module else "builtin"}-record-edge-{size}'
                checks = execute_case(case, endpoint, module, pki, build, 'client-request', 'memory',
                                      'native', True, connections=2, warmups=1, size=size)
                results.append({'case': case.name, 'status': 'passed', 'checks': checks})
                (output / 'verification.json').write_text(json.dumps(results, indent=2) + '\n')
        print(f'PASS: {len(results)} actual TLS pairs, raw byte/message/boundary/cost oracles')
        if args.output is None:
            shutil.rmtree(output)
    except Exception:
        print(f'Original evidence retained: {output}', flush=True)
        raise


if __name__ == '__main__':
    main()
