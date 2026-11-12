#!/usr/bin/env python3
"""BiTHaC 기준/캐시 실행과 오프라인 표 재생성. 표본 단위는 새 역할 프로세스입니다."""
import argparse
import csv
import json
from pathlib import Path
from raw_record import read_tls_records, lifetime_span
import random
import subprocess


def command(argv, log):
    result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=90)
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'실행 실패({result.returncode}), 원자료 보존: {log}')


def analyze(root, build):
    rows, contexts, failures = [], [], []
    for run in sorted(root.glob('*/*/*/attempts.jsonl')):
        directory = run.parent
        for raw in sorted(directory.glob('sample-*/*.jsonl')):
            if raw.stem not in ('client', 'server'):
                continue
            records = read_tls_records(raw)
            header, events = records[0], records[1:]
            if not header['valid']:
                failures.append({'file': str(raw.relative_to(root)), 'reason': header['invalid_reason']})
                continue
            command([build / 'turtle-interpret', raw, raw.with_suffix('.decoded.json')],
                    raw.with_suffix('.interpret.log'))
        command([build / 'turtle-report', directory, directory / 'report'], directory / 'report.log')
        summary = json.loads((directory / 'report/summary.json').read_text())
        for sample in summary['samples']:
            raw = directory / 'sample-000001' / (sample['role'] + '.jsonl')
            records = read_tls_records(raw)
            header, events = records[0], records[1:]
            if not header['valid']:
                continue
            decoded = json.loads(raw.with_suffix('.decoded.json').read_text())['connections']
            base = {'mode': header['mode'], 'sample': directory.parent.name,
                    'variant': directory.name, 'role': header['role']}
            window, begin, end = lifetime_span(header, events)
            contexts.append({**base, 'window': window, 'elapsed_ns': end['monotonic_ns'] - begin['monotonic_ns'],
                             'thread_cpu_ns': end['thread_cpu_ns'] - begin['thread_cpu_ns'],
                             'includes_ready_and_release_waits': True,
                             'excludes_process_start_module_unload_and_record_output': True})
            for connection in sample['connections']:
                index = connection['connection']
                data = decoded[index][header['role'] + '_sent']
                certificates = [m['length'] for m in data['messages'] if m['name'] == 'Certificate']
                hits = [e for e in events if e['connection'] == index and
                        e['kind'] == 'INTERNAL_END' and e['trace_operation'] == 'cached_certificate_write']
                row = {**base, 'connection': index,
                       'cache_condition': 'disabled' if directory.name == 'bithac-baseline' else
                           'initially-empty' if index == 0 else 'after-recorded-first-connection',
                       'certificate_message_bytes': sum(certificates),
                       'tls_stream_sent_bytes': (raw.parent / f'{raw.stem}.conn-{index}.sent.bin').stat().st_size,
                       'cached_path_calls': len(hits) if header['mode'] == 'trace' else None,
                       'cached_path_status': 'observed' if header['mode'] == 'trace' else 'trace-disabled',
                       'elapsed_ns': connection.get('elapsed_ns'),
                       'thread_cpu_ns': connection.get('thread_cpu_ns'),
                       'heap_peak_bytes': connection.get('heap_peak_bytes'),
                       'heap_status': 'allocator-observed' if header['mode'] == 'memory' else 'unobserved',
                       'windows': connection['prototype']['windows'],
                       'source': str(raw.relative_to(root)),
                       'patch_hash': header['declaration']['patch_hash']}
                rows.append(row)
    evidence = {'type': 'turtle-bithac-pilot', 'schema': 1,
                'performance_experiment': False, 'independent_unit': 'fresh-endpoint-process-pair',
                'both_endpoints_changed': True, 'warmups': 0,
                'rows': rows, 'contexts': contexts, 'failed_endpoints': failures,
                'limitations': ['연결 위치는 같은 컨텍스트의 종속 관측입니다.',
                               '프로토콜 확장 비교이며 표준 TLS 구현 최적화와 다릅니다.',
                               '추적과 메모리는 진단 실행이며 시간 모드와 합치지 않습니다.',
                               '원 논문의 장비와 시간 구간을 재현한 성능 결론이 아닙니다.']}
    (root / 'bithac-summary.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
    if rows:
        fields = [key for key in rows[0] if key != 'windows']
        with (root / 'bithac-table.csv').open('w', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
    print(f'{len(rows)} endpoint/connection rows, {len(failures)} failed endpoints retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'analyze'))
    parser.add_argument('--build', type=Path, default=Path('build'))
    parser.add_argument('--pki', type=Path, default=Path('pki/default'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--connections', type=int, default=2)
    parser.add_argument('--seed', type=int, default=17)
    parser.add_argument('--no-affinity', action='store_true')
    args = parser.parse_args()
    build, pki, root = args.build.resolve(), args.pki.resolve(), args.output.resolve()
    if args.action == 'run':
        if args.samples < 1 or args.connections < 2:
            parser.error('samples >= 1, connections >= 2가 필요합니다')
        root.mkdir(parents=True, exist_ok=False)
        rng = random.Random(args.seed)
        order = []
        for mode in ('timing', 'trace', 'memory'):
            for sample in range(args.samples):
                variants = ['bithac-baseline', 'bithac']
                rng.shuffle(variants)
                for variant in variants:
                    destination = root / mode / f'sample-{sample:04d}' / variant
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    argv = [build / 'turtle-local', '--client', variant, '--server', variant,
                            '--adapter-dir', build / 'adapters', '--pki', pki, '--mutual-auth',
                            '--scenario', 'client-request', '--send-policy', 'native',
                            '--samples', 1, '--connections', args.connections, '--warmups', 0,
                            '--mode', mode, '--no-perf', '--output', destination]
                    if args.no_affinity:
                        argv += ['--no-affinity']
                    order.append({'mode': mode, 'sample': sample, 'variant': variant,
                                  'command': list(map(str, argv))})
                    (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
                    command(argv, destination.parent / (variant + '.log'))
    analyze(root, build)


if __name__ == '__main__':
    main()
