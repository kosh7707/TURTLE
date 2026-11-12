#!/usr/bin/env python3
"""Actual TLS 1.3 scenarios, byte envelopes and internal work spans (no downloads)."""
import argparse
import itertools
import json
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=40)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}\n{result.stderr}")


def check(value, message):
    if not value:
        raise AssertionError(message)


def verify(turtle, report, interpret, adapters, pki, root, client, server, scenario, policy, mutual,
           client_bytes=32, server_bytes=32, connections=1, group='secp256r1', tx_timestamps=False):
    command = [turtle, '--adapter-dir', adapters, '--pki', pki,
               '--client', client, '--server', server, '--scenario', scenario,
               '--send-policy', policy, '--client-bytes', client_bytes, '--server-bytes', server_bytes,
               '--samples', 1, '--connections', connections, '--no-affinity', '--no-perf',
               '--mode', 'trace', '--group', group, '--output', root]
    if mutual:
        command += ['--mutual-auth']
    if tx_timestamps:
        command += ['--tx-timestamps']
    run(*command)
    headers = {}
    for role in ('client', 'server'):
        raw = root / 'sample-000001' / (role + '.jsonl')
        rows = [json.loads(line) for line in raw.read_text().splitlines()]
        header, events = rows[0], rows[1:]
        headers[role] = header
        check(header['schema'] == 3 and header['measurement_contract_revision'] == 4, 'version axes')
        check(header['valid'] and not header['declaration']['is_mock'], header['invalid_reason'])
        check(header['declaration']['patch_hash'], 'instrumentation provenance absent')
        check(header['declaration']['internal_events'], 'internal trace support absent')
        decoded_path = raw.with_suffix('.decoded.json')
        run(interpret, raw, decoded_path)
        decoded = json.loads(decoded_path.read_text())['connections']
        for index, conn in enumerate(header['connections']):
            check(conn['scenario_completed'], 'scenario incomplete')
            check(conn['application_verified'] == (scenario != 'handshake'), 'application applicability')
            check(conn['verification'] in ('passed', 'not_applicable'), 'verification missing')
            check(not conn['negotiated']['resumed'] and not conn['negotiated']['hello_retry_request'], 'not baseline TLS')
            by_kind = {}
            local = [e for e in events if e['connection'] == index]
            for event in local:
                by_kind.setdefault(event['kind'], []).append(event)
            tcp_start = by_kind['TCP_CONNECT_BEGIN' if role == 'client' else 'ACCEPT_BEGIN'][0]
            tcp_end = by_kind['TCP_CONNECT_END' if role == 'client' else 'ACCEPT_END'][0]
            check(tcp_start['sequence'] < tcp_end['sequence'] < by_kind['OPEN_BEGIN'][0]['sequence'], 'TCP/open order')
            if index:
                previous_close = [e for e in events if e['connection'] == index-1 and e['kind'] == 'CLOSE_END'][0]
                check(previous_close['sequence'] < tcp_start['sequence'], 'connection precreated before previous cleanup')
            else:
                check(by_kind['MODULE_END'][0]['sequence'] < by_kind['SETUP_BEGIN'][0]['sequence'] < tcp_start['sequence'], 'module/setup/trial order')
            check(decoded[index]['decryption_complete'], 'decryption incomplete')
            for direction in ('client_sent', 'server_sent'):
                messages = decoded[index][direction]['messages']
                check(sum(m['name'] == 'Finished' for m in messages) == 1, 'Finished missing/duplicate')
                size = sum(m['length'] for m in messages if m['name'] == 'ApplicationData')
                expected = (client_bytes if direction == 'client_sent' else server_bytes) if scenario != 'handshake' else 0
                check(size == expected, f'payload mismatch {size} != {expected}')
            stack = {}
            for e in local:
                # Generation must not silently include record crypto or socket I/O.
                if any(key[0] == 'message_generate' for key in stack):
                    check(not e['kind'].startswith('IO_'), 'socket I/O inside message generation')
                    check(not (e['kind'] == 'INTERNAL_BEGIN' and
                               e['trace_operation'] in ('record_encrypt', 'record_decrypt')),
                          'record crypto inside message generation')
                if e['kind'] not in ('INTERNAL_BEGIN', 'INTERNAL_END'):
                    continue
                key = e['trace_operation'], e['message_id']
                if e['kind'] == 'INTERNAL_BEGIN':
                    check(key not in stack, 'duplicate internal begin')
                    stack[key] = e
                else:
                    check(key in stack, 'internal end without begin')
                    check(e['monotonic_ns'] >= stack.pop(key)['monotonic_ns'], 'internal clock order')
            check(not stack, 'unfinished internal span')
            if 'message_generate' in header['declaration']['internal_events']:
                generated = {e['message_type'] for e in local if e['kind'] == 'INTERNAL_END' and
                             e['trace_operation'] == 'message_generate'}
                processed = {e['message_type'] for e in local if e['kind'] == 'INTERNAL_END' and
                             e['trace_operation'] == 'message_process'}
                client_types = {1, 20} | ({11, 15} if mutual else set())
                server_types = {2, 8, 11, 15, 20} | ({13} if mutual else set())
                check((client_types if role == 'client' else server_types) <= generated,
                      f'missing message generation: {role} {generated}')
                check((server_types if role == 'client' else client_types) <= processed,
                      f'missing message processing: {role} {processed}')
            if role == 'server' and scenario in ('server-ping', 'finished-ping'):
                processed = [e for e in local if e['kind'] == 'INTERNAL_END' and e['trace_operation'] == 'message_process' and e['message_type'] == 20]
                check(processed and by_kind['APPLICATION_WRITE_END'][0]['sequence'] < processed[-1]['sequence'], 'Ping did not precede ClientFinished processing')
            if role == 'server' and policy == 'server-hello-first':
                hello = next(m for m in decoded[index]['server_sent']['messages'] if m['name'] == 'ServerHello')
                end = max(r['end'] for r in hello['record_stream_ranges'])
                sent = next(e for e in by_kind['IO_SEND_RETURN'] if e['stream_begin'] < end <= e['stream_end'])
                encryption = next(e for e in by_kind['INTERNAL_BEGIN'] if e['trace_operation'] == 'record_encrypt')
                check(sent['sequence'] < encryption['sequence'], 'ServerHello was not submitted before encrypted flight work')
        for index in range(connections):
            sent = (raw.parent / f'{role}.conn-{index}.sent.bin').read_bytes()
            peer = 'server' if role == 'client' else 'client'
            received = (raw.parent / f'{peer}.conn-{index}.received.bin').read_bytes()
            check(sent == received, 'endpoint stream bytes differ')
    run(report, root, root / 'report')
    output = json.loads((root / 'report' / 'summary.json').read_text())
    for sample in output['samples']:
        check(sample['valid'], sample['invalid_reason'])
        for conn in sample['connections']:
            evidence = conn['prototype']
            check(evidence['internal_spans_complete'] and evidence['internal_spans'], 'report spans incomplete')
            windows = evidence['windows']
            for name in ('handshake_api', 'connection_prepare'):
                check(windows[name]['status'] == 'available', f'missing {name}')
            if sample['role'] == 'client':
                for name in ('open_to_client_finished_submit', 'tcp_to_client_finished_submit'):
                    check(windows[name]['status'] == 'available', f'missing {name}')
            else:
                check(windows['first_tls_receive_to_client_finished_processed']['status'] == 'available', 'Finished boundary absent')
                if scenario == 'finished-ping':
                    check(evidence['finished_ping_batch']['same_output_batch'] is True, 'Finished and Ping batches differ')
    return {'client': client, 'server': server, 'scenario': scenario, 'policy': policy,
            'mutual_auth': mutual, 'connections': connections, 'status': 'passed'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('turtle', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('interpret', type=Path)
    parser.add_argument('adapters', type=Path)
    parser.add_argument('pki', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix='turtle-prototype-') if args.output is None else None
    root = args.output or Path(temporary.name)
    root.mkdir(parents=True, exist_ok=True)
    libraries = [lib for lib in ('openssl', 'wolfssl', 'mbedtls') if (args.adapters / (lib + '.so')).exists()]
    results = []
    for client, server, scenario, policy, mutual in itertools.product(
        libraries, libraries, ('handshake', 'server-ping', 'finished-ping', 'client-request'),
        ('native', 'server-hello-first'), (False, True)):
        destination = root / f'{client}-{server}-{scenario}-{policy}-{int(mutual)}'
        results.append(verify(args.turtle, args.report, args.interpret, args.adapters, args.pki,
                              destination, client, server, scenario, policy, mutual))
    for lib in libraries:
        results.append(verify(args.turtle, args.report, args.interpret, args.adapters, args.pki,
                              root / f'{lib}-directional-repeated', lib, lib, 'finished-ping', 'native', True,
                              client_bytes=65537, server_bytes=65539, connections=2))
    (root / 'verification.json').write_text(json.dumps({'type': 'turtle-prototype-verification',
        'schema': 1, 'runs': results, 'performance_experiment': False}, indent=2) + '\n')
    print(f'{len(results)} real TLS scenario runs passed')


if __name__ == '__main__':
    main()
