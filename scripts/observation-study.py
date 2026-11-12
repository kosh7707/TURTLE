#!/usr/bin/env python3
"""같은 TLS 조건의 시간·추적·송신 시각·CPU 표본 수집 부담을 별도 실행으로 비교합니다."""
import argparse
import csv
import json
from pathlib import Path
import random
import statistics
import subprocess
import sys


def invoke(command, log):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=180)
    log.write_text(result.stdout + result.stderr)
    return result.returncode


def analyze(root, build):
    rows, failures, notes = [], [], []
    for entry in json.loads((root / 'execution-order.json').read_text()):
        directory = root / entry['directory']
        run = directory / 'run' if entry['condition'] == 'cpu-profile' else directory
        if entry['condition'] == 'cpu-profile':
            profile_path = directory / 'cpu-profile.json'
            profile = json.loads(profile_path.read_text()) if profile_path.exists() else {}
            if profile.get('status') != 'available' or profile.get('record_returncode') != 0:
                failures.append({'run': entry['directory'], 'reason': 'cpu_collection_or_analysis_incomplete'})
            elif entry.get('returncode') != 0:
                notes.append({'run': entry['directory'], 'initial_tool_returncode': entry.get('returncode'),
                              'current_analysis': 'available', 'record_returncode': profile['record_returncode'],
                              'note': 'original perf.data reanalyzed; no TLS trial replaced'})
        elif entry.get('returncode') != 0:
            failures.append({'run': entry['directory'], 'reason': 'collection_failed'})
        if invoke([build / 'turtle-report', run, run / 'report'], directory / 'report.log'):
            failures.append({'run': entry['directory'], 'reason': 'report_failed'})
            continue
        summary = json.loads((run / 'report/summary.json').read_text())
        if len(summary['samples']) != entry['samples'] * 2:
            failures.append({'run': entry['directory'], 'reason': 'endpoint_denominator_incomplete'})
        for sample in summary['samples']:
            if not sample['valid'] or len(sample['connections']) != 1:
                failures.append({'run': entry['directory'], 'reason': 'invalid_execution_or_connection_count'})
                continue
            connection = sample['connections'][0]
            rows.append({'block': entry['block'], 'condition': entry['condition'], 'role': sample['role'],
                'sample': sample['sample'], 'elapsed_ns': connection['elapsed_ns'],
                'thread_cpu_ns': connection['thread_cpu_ns'],
                'source': str(Path(entry['directory']) / ('run' if entry['condition'] == 'cpu-profile' else '') /
                              f'sample-{sample["sample"]:06d}' / f'{sample["role"]}.jsonl')})
    groups = []
    for role in ('client', 'server'):
        reference = [r for r in rows if r['role'] == role and r['condition'] == 'timing']
        for condition in ('timing', 'trace', 'trace-tx', 'cpu-profile'):
            local = [r for r in rows if r['role'] == role and r['condition'] == condition]
            metrics = {}
            for metric in ('elapsed_ns', 'thread_cpu_ns'):
                values = [r[metric] for r in local]
                base = [r[metric] for r in reference]
                median = statistics.median(values) if values else None
                reference_median = statistics.median(base) if base else None
                metrics[metric] = {'count': len(values), 'values': values, 'median': median,
                    'q1_q3': statistics.quantiles(values, n=4, method='inclusive')[::2] if len(values) > 1 else None,
                    'median_change_percent_from_timing': 100 * (median / reference_median - 1)
                        if median is not None and reference_median else None}
            groups.append({'role': role, 'condition': condition, 'metrics': metrics})
    document = {'type': 'turtle-observation-pilot', 'schema': 1, 'performance_experiment': False,
        'status': 'complete' if not failures else 'incomplete', 'rows': rows, 'groups': groups, 'failures': failures,
        'reanalysis_notes': notes,
        'independent_unit': 'fresh endpoint process pair; one measured connection; zero warmups',
        'window': 'existing role primary_window, through application scenario completion',
        'limitations': ['WSL에서 관측 설정에 따른 변동을 확인한 예비 자료입니다. 인과적 성능 효과나 보편적 부담률이 아닙니다.',
                       '시간 모드에도 공통 호출·대기 계측이 남으므로 전체 계측 비용은 아닙니다.',
                       'CPU 수집 실행은 같은 조건의 별도 표본입니다. perf 시작·분석 비용은 엔드포인트 주 구간 밖입니다.',
                       '커널 BPF 수집·패킷 캡처의 부담은 네이티브 본 실험에서 같은 권한·토폴로지로 별도 평가합니다.']}
    (root / 'observation-summary.json').write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n')
    if rows:
        with (root / 'observation-table.csv').open('w', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    print(f'{len(rows)} endpoint rows; {len(failures)} failures')
    return int(bool(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'analyze'))
    parser.add_argument('--build', type=Path, default=Path('build'))
    parser.add_argument('--pki', type=Path, default=Path('pki/default'))
    parser.add_argument('--perf', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--blocks', type=int, default=4)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--seed', type=int, default=29)
    args = parser.parse_args()
    root, build, pki = args.output.resolve(), args.build.resolve(), args.pki.resolve()
    if args.action == 'run':
        if args.blocks < 1 or args.samples < 1 or args.perf is None:
            parser.error('positive blocks/samples and --perf are required')
        root.mkdir(parents=True, exist_ok=False)
        order, rng = [], random.Random(args.seed)
        for block in range(args.blocks):
            conditions = ['timing', 'trace', 'trace-tx', 'cpu-profile']
            rng.shuffle(conditions)
            for condition in conditions:
                directory = f'block-{block:02d}-{condition}'
                if condition == 'cpu-profile':
                    command = [sys.executable, Path(__file__).with_name('cpu-profile.py'), 'run',
                        '--perf', args.perf.resolve(), '--build', build, '--pki', pki,
                        '--samples', args.samples, '--no-affinity', '--output', root / directory]
                else:
                    command = [build / 'turtle-local', '--client', 'openssl', '--server', 'openssl',
                        '--adapter-dir', build / 'adapters', '--pki', pki, '--mutual-auth',
                        '--scenario', 'client-request', '--samples', args.samples, '--connections', 1,
                        '--warmups', 0, '--mode', 'timing' if condition == 'timing' else 'trace',
                        '--no-affinity', '--no-perf', '--output', root / directory]
                    if condition == 'trace-tx': command += ['--tx-timestamps']
                entry = {'block': block, 'condition': condition, 'samples': args.samples,
                         'directory': directory, 'command': list(map(str, command))}
                order.append(entry)
                (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
                entry['returncode'] = invoke(command, root / f'{directory}.log')
                (root / 'execution-order.json').write_text(json.dumps(order, indent=2) + '\n')
                print(f'{directory}: exit {entry["returncode"]}', flush=True)
    return analyze(root, build)


if __name__ == '__main__':
    raise SystemExit(main())
