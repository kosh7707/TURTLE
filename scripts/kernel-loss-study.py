#!/usr/bin/env python3
"""지정 바이트 손실·커널 재전송·랜덤 손실을 실제 TLS와 원자료로 검증합니다."""
import argparse
import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def execute(command, log):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=180)
    log.write_text(result.stdout + result.stderr)
    return result.returncode


def analyze(root, build):
    spec = importlib.util.spec_from_file_location(
        'tcp_correlator', Path(__file__).with_name('tcp-correlate.py'))
    correlator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(correlator)
    rows, failures = [], []
    order = json.loads((root / 'execution-order.json').read_text())
    for entry in order:
        run = root / entry['directory']
        if entry.get('returncode') != 0:
            failures.append({'run': entry['directory'], 'reason': 'execution_failed'})
        provenance_file = run / 'network-provenance.json'
        provenance = json.loads(provenance_file.read_text()) if provenance_file.exists() else {}
        if provenance.get('status') != 'complete' or not provenance.get('host_network_identity', {}).get('unchanged'):
            failures.append({'run': entry['directory'], 'reason': 'network_or_cleanup_incomplete'})
        targets = entry['targeted_drop']
        raw_files = sorted(p for p in run.glob('sample-*/*.jsonl') if p.stem in ('client', 'server'))
        if len(raw_files) != entry['samples'] * 2:
            failures.append({'run': entry['directory'], 'reason': 'endpoint_artifacts_missing'})
        for raw in raw_files:
            header = json.loads(raw.read_text().splitlines()[0])
            if not header['valid'] or not all(c['scenario_completed'] and c['application_verified']
                                              for c in header['connections']):
                failures.append({'run': str(raw.relative_to(root)), 'reason': 'tls_or_payload_incomplete'})
                continue
            if execute([build / 'turtle-interpret', raw, raw.with_suffix('.decoded.json')], raw.with_suffix('.interpret.log')):
                failures.append({'run': str(raw.relative_to(root)), 'reason': 'tls_decode_failed'})
                continue
            mapped = correlator.correlate(run / 'packets.jsonl', raw)
            raw.with_suffix('.tcp.json').write_text(json.dumps(mapped, indent=2) + '\n')
            if mapped['status'] != 'available':
                failures.append({'run': str(raw.relative_to(root)), 'reason': 'tcp_or_kernel_mapping_missing'})
            for connection in mapped['connections']:
                events = connection.get('kernel_events', [])
                drops = [e for e in events if e['kind'] == 'targeted_drop']
                retrans = [e for e in events if e['kind'] == 'tcp_retransmit_skb']
                target = targets['tls_c2s' if header['role'] == 'client' else 'tls_s2c']
                recovered = all(any(r['result'] == 0 and r['monotonic_ns'] > d['monotonic_ns'] and
                                    correlator.overlap((r['stream_begin'], r['stream_end']),
                                                       (d['stream_begin'], d['stream_end'])) for r in retrans)
                                for d in drops)
                proven = len(drops) == (0 if target is None else 1) and recovered and all(
                    d['stream_begin'] <= target < d['stream_end'] for d in drops)
                if not proven:
                    failures.append({'run': str(raw.relative_to(root)), 'connection': connection['connection'],
                                     'reason': 'targeted_drop_or_kernel_recovery_not_proven'})
                rows.append({'run': entry['directory'], 'role': header['role'], 'library': header['declaration']['library'],
                    'sample': raw.parent.name, 'connection': connection['connection'],
                    'case': entry['case'], 'target_byte': target, 'status': connection['status'],
                    'targeted_drops': len(drops), 'kernel_retransmissions': len(retrans),
                    'qdisc_drops': sum(e['kind'] == 'qdisc_drop' for e in events),
                    'observed_retransmitted_bytes': connection.get('observed_retransmitted_payload_bytes'),
                    'targeted_recovery_proven': proven, 'source': str(raw.relative_to(root))})
        if raw_files and execute([build / 'turtle-report', run, run / 'report'], run / 'report.log'):
            failures.append({'run': entry['directory'], 'reason': 'report_failed'})
        elif raw_files:
            summary = json.loads((run / 'report/summary.json').read_text())
            if any(not sample.get('network_integrity', {}).get('eligible') for sample in summary['samples']):
                failures.append({'run': entry['directory'], 'reason': 'required_network_evidence_ineligible'})
        if entry['case'] == 'random-loss' and not any(r['run'] == entry['directory'] and r['qdisc_drops'] for r in rows):
            failures.append({'run': entry['directory'], 'reason': 'random_draw_produced_no_observed_tls_drop'})
    document = {'type': 'turtle-kernel-loss-verification', 'schema': 1,
                'status': 'complete' if not failures else 'incomplete', 'performance_experiment': False,
                'rows': rows, 'failures': failures,
                'notes': ['시행 실패와 관측 누락을 삭제하거나 새 성공 시행으로 대체하지 않습니다.',
                          '랜덤 손실 난수 seed는 고정되지 않았습니다. 실제 qdisc 제거 사건을 보존합니다.',
                          '커널 관측 실행은 initial user namespace의 root 권한이며 일반 시간 비교와 구별합니다.']}
    (root / 'verification.json').write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n')
    if rows:
        with (root / 'kernel-loss-table.csv').open('w', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
    print(f'{len(rows)} endpoint/connection rows; {len(failures)} failures')
    return int(bool(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'analyze'))
    parser.add_argument('--build', type=Path, default=Path('build'))
    parser.add_argument('--pki', type=Path, default=Path('pki/default'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--libraries', default='openssl,wolfssl,mbedtls')
    args = parser.parse_args()
    root, build, pki = args.output.resolve(), args.build.resolve(), args.pki.resolve()
    if args.action == 'run':
        if os.geteuid() != 0: parser.error('run requires sudo; analyze needs no privilege')
        if args.samples < 1: parser.error('samples must be positive')
        root.mkdir(parents=True, exist_ok=False)
        profile = {'name': 'kernel-loss-functional-validation', 'pki': str(pki),
                   'tls': {'scenario': 'client-request', 'mutual_auth': True,
                           'client_application_bytes': 32768, 'server_application_bytes': 32768},
                   'measurement': {'mode': 'trace', 'connections': 2, 'warmups': 0,
                                   'pin_cores': False, 'perf': False, 'tx_timestamps': True,
                                   'timeout_ms': 30000}}
        profile_path = root / 'tls-profile.json'
        profile_path.write_text(json.dumps(profile, indent=2) + '\n')
        template = json.loads((Path(__file__).resolve().parent.parent /
                              'examples/networks/tls-kernel-no-loss.json').read_text())
        cases = [('no-loss', None, None, 0), ('client-first', 0, None, 0),
                 ('server-first', None, 0, 0), ('both-application', 8192, 16384, 0),
                 ('random-loss', None, None, 5)]
        order = []
        for library in args.libraries.split(','):
            for case, client_byte, server_byte, loss in cases:
                network = json.loads(json.dumps(template))
                network['targeted_drop'] = {'tls_c2s': client_byte, 'tls_s2c': server_byte}
                for policy in network['paths'].values():
                    policy.update(delay_ms=2, loss_percent=loss)
                net_path = root / f'{case}.json'
                net_path.write_text(json.dumps(network, indent=2) + '\n')
                destination = f'{library}-{case}'
                command = [
                    sys.executable, Path(__file__).with_name('netem-study.py'), 'run', '--build', build,
                    '--profile', profile_path, '--net-profile', net_path, '--client', library, '--server', library,
                    '--samples', args.samples, '--output', root / destination]
                entry = {'case': case, 'directory': destination, 'samples': args.samples,
                         'targeted_drop': network['targeted_drop'], 'command': list(map(str, command))}
                order.append(entry)
                (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
                entry['returncode'] = execute(command, root / f'{destination}.log')
                (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
                print(f'{destination}: exit {entry["returncode"]}', flush=True)
    result = analyze(root, build)
    if os.geteuid() == 0 and os.environ.get('SUDO_UID'):
        for path in [*root.rglob('*'), root]:
            os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']), follow_symlinks=False)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
