#!/usr/bin/env python3
"""같은 ML-KEM 기반에서 한 엔드포인트씩 최적화를 바꾸고 원자료로 표를 재생성합니다."""
import argparse
import csv
import json
from pathlib import Path
import random
import subprocess


CASES = {'baseline': ('mlkem-c', 'mlkem-c'),
         'client-avx2': ('mlkem-avx2', 'mlkem-c'),
         'server-avx2': ('mlkem-c', 'mlkem-avx2')}


def command(argv, log):
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=90)
    log.write_text(result.stdout + result.stderr)
    return result.returncode


def analyze(root, build):
    rows, failures = [], []
    for entry in json.loads((root / 'execution-order.json').read_text()):
        directory = root / entry['directory']
        for role in ('client', 'server'):
            raw = directory / 'sample-000001' / (role + '.jsonl')
            if not raw.exists():
                failures.append({'source': str(raw.relative_to(root)), 'reason': 'endpoint_artifact_missing'})
                continue
            header = json.loads(raw.read_text().splitlines()[0])
            if not header['valid']:
                failures.append({'source': str(raw.relative_to(root)), 'reason': header['invalid_reason']})
                continue
            if command([build / 'turtle-interpret', raw, raw.with_suffix('.decoded.json')],
                       raw.with_suffix('.interpret.log')):
                failures.append({'source': str(raw.relative_to(root)), 'reason': 'interpret_failed'})
        if command([build / 'turtle-report', directory, directory / 'report'], directory / 'report.log'):
            failures.append({'source': entry['directory'], 'reason': 'report_failed'})
            continue
        summary = json.loads((directory / 'report/summary.json').read_text())
        for sample in summary['samples']:
            if not sample['valid']:
                continue
            role = sample['role']
            raw = directory / 'sample-000001' / (role + '.jsonl')
            header = json.loads(raw.read_text().splitlines()[0])
            variant = CASES[entry['case']][0 if role == 'client' else 1]
            peer = CASES[entry['case']][1 if role == 'client' else 0]
            for connection in sample['connections']:
                prototype = connection['prototype']
                spans = prototype['internal_spans']
                kem = [s for s in spans if s['operation'] in
                       ('kem_keygen', 'kem_encapsulate', 'kem_decapsulate')]
                polynomial = [s for s in spans if s['operation'].startswith('kem_polynomial_')]
                observed = header['mode'] == 'trace'
                expected_tag = 2 if variant == 'mlkem-avx2' else 1
                path_valid = (len(polynomial) == (3 if role == 'client' else 1) and
                              all(s['message_type'] == expected_tag for s in polynomial) and
                              len(kem) == (2 if role == 'client' else 1) and
                              all(s['result'] == 0 for s in kem) and
                              prototype['internal_spans_complete']) if observed else None
                if path_valid is False:
                    failures.append({'source': str(raw.relative_to(root)),
                                     'reason': 'required_kem_execution_path_not_proven'})
                windows = prototype['windows']
                main = windows['tcp_to_client_finished_submit' if role == 'client' else
                               'first_tls_receive_to_client_finished_processed']
                row = {'mode': header['mode'], 'sample': entry['sample'], 'case': entry['case'],
                       'role': role, 'variant': variant, 'peer_variant': peer,
                       'connection': connection['connection'], 'group': 'ML_KEM_768',
                       'path_status': 'verified' if path_valid else 'missing' if observed else 'trace-disabled',
                       'kem_calls': len(kem) if observed else None,
                       'polynomial_calls': len(polynomial) if observed else None,
                       'kem_api_elapsed_ns': sum(s['elapsed_ns'] for s in kem) if observed else None,
                       'kem_api_thread_cpu_ns': sum(s['thread_cpu_ns'] for s in kem) if observed else None,
                       'polynomial_elapsed_ns': sum(s['elapsed_ns'] for s in polynomial) if observed else None,
                       'polynomial_thread_cpu_ns': sum(s['thread_cpu_ns'] for s in polynomial) if observed else None,
                       'completion_status': main['status'], 'completion_elapsed_ns': main['elapsed_ns'],
                       'completion_thread_cpu_ns': main['thread_cpu_ns'],
                       'heap_peak_bytes': connection.get('heap_peak_bytes'),
                       'heap_status': 'allocator-observed' if header['mode'] == 'memory' else 'unobserved',
                       'windows': windows, 'source': str(raw.relative_to(root)),
                       'source_version': header['declaration']['source_version'],
                       'patch_hash': header['declaration']['patch_hash']}
                rows.append(row)
    result = {'type': 'turtle-mlkem-pilot', 'schema': 1, 'performance_experiment': False,
              'independent_unit': 'fresh-endpoint-process-pair', 'connections_per_context': 1,
              'warmups': 0, 'rows': rows, 'failures': failures,
              'limitations': ['WSL 진단 실행은 네이티브 Linux 성능 결론이 아닙니다.',
                             '같은 역할의 상대 엔드포인트가 고정된 조건끼리 비교합니다.',
                             '다항식 구간은 KEM API 구간 안에 있으므로 시간을 합산하지 않습니다.',
                             'AVX2 최적화는 ML-KEM 내부 SHA3·표현 변환·임시 메모리 경로도 바꿉니다.',
                             '시간·추적·메모리 실행은 별도 표본이며 서로 합치지 않습니다.']}
    (root / 'mlkem-summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    if rows:
        with (root / 'mlkem-table.csv').open('w', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=[key for key in rows[0] if key != 'windows'],
                                    extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
    print(f'{len(rows)} endpoint rows, {len(failures)} execution/observation failures retained')
    return int(bool(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'analyze'))
    parser.add_argument('--build', type=Path, default=Path('build'))
    parser.add_argument('--pki', type=Path, default=Path('pki/default'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--seed', type=int, default=17)
    parser.add_argument('--no-affinity', action='store_true')
    args = parser.parse_args()
    build, pki, root = args.build.resolve(), args.pki.resolve(), args.output.resolve()
    if args.action == 'run':
        if args.samples < 1:
            parser.error('samples >= 1이 필요합니다')
        root.mkdir(parents=True, exist_ok=False)
        rng, order = random.Random(args.seed), []
        for mode in ('timing', 'trace', 'memory'):
            for sample in range(args.samples):
                cases = list(CASES)
                rng.shuffle(cases)
                for case in cases:
                    client, server = CASES[case]
                    destination = root / mode / f'sample-{sample:04d}' / case
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    argv = [build / 'turtle', 'run', '--client', client, '--server', server,
                            '--adapter-dir', build / 'adapters', '--pki', pki, '--mutual-auth',
                            '--group', 'ML_KEM_768', '--scenario', 'client-request', '--send-policy', 'native',
                            '--samples', 1, '--connections', 1, '--warmups', 0, '--mode', mode,
                            '--no-perf', '--output', destination]
                    if args.no_affinity:
                        argv += ['--no-affinity']
                    order.append({'mode': mode, 'sample': sample, 'case': case,
                                  'directory': str(destination.relative_to(root)),
                                  'command': list(map(str, argv))})
                    (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
                    order[-1]['returncode'] = command(argv, destination.parent / (case + '.log'))
                    (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
    return analyze(root, build)


if __name__ == '__main__':
    raise SystemExit(main())
