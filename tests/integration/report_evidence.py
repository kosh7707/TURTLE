#!/usr/bin/env python3
"""정상 TLS 자료의 복사본으로 누락과 종료 뒤 실패의 보고 반영을 확인합니다."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from measurement_audit import execute_case, require, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--pki', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    build, pki = args.build.resolve(), args.pki.resolve()
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='turtle-evidence-'))
    output.mkdir(parents=True, exist_ok=True)
    source = args.source.resolve() if args.source else output / 'original'
    if not args.source:
        execute_case(source, build, build / 'adapters/openssl.so', pki, build,
                     'client-request', 'memory', 'native', False)
    results = []
    for case in ('peer_events_missing', 'connection_missing', 'cleanup_failed', 'heap_missing'):
        directory = output / case
        directory.mkdir()
        for role in ('client', 'server'):
            raw = source / role / 'raw' / f'{role}.jsonl'
            rows = [json.loads(line) for line in raw.read_text().splitlines()]
            if case == 'peer_events_missing' and role == 'server':
                rows = rows[:1]
            if case == 'connection_missing':
                rows[0]['config']['connections'] += 1
            if case == 'heap_missing' and role == 'client':
                start = rows[0]['connections'][0]['start_sequence']
                end = rows[0]['connections'][0]['end_sequence']
                next(e for e in rows[1:] if start < e['sequence'] < end)['heap'] = None
            (directory / f'{role}.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
            if case == 'cleanup_failed' and role == 'client':
                (directory / 'client.failure.json').write_text(json.dumps({
                    'run_id': rows[0]['run_id'], 'context_id': rows[0]['context_id'],
                    'valid': False, 'phase': 'cleanup', 'reason': 'fixture: completion acknowledgement absent'}))
        run([args.report.resolve() if args.report else build / 'turtle-report', directory,
             directory / 'report'], directory / 'report.log')
        report = json.loads((directory / 'report/summary.json').read_text())
        try:
            client = next(s for s in report['samples'] if s['role'] == 'client')
            if case == 'peer_events_missing':
                require(client['valid'], 'local complete measurement must remain descriptive')
                require(client.get('peer_measurement_status') == 'missing', 'peer header became complete evidence')
                require(all(not g['automatic_comparison_eligible'] for g in report['groups']),
                        'peer with no events became comparison eligible')
            elif case == 'connection_missing':
                require(report['invalid_samples'] == 2 and not report['groups'], 'missing requested connection became success')
                require(all(s['invalid_reason'] for s in report['samples']), 'missing connection reason absent')
            elif case == 'cleanup_failed':
                require(report['invalid_samples'] == 2 and not report['groups'], 'cleanup failure became success')
                require(all('acknowledgement' in s['invalid_reason'] for s in report['samples']), 'failure reason lost')
            else:
                require(client['connections'][0]['heap_peak_bytes'] is None, 'missing heap became a partial peak')
                require(all('heap_peak_bytes' not in g['metrics'] for g in report['groups']
                            if g['dimensions']['role'] == 'client'), 'missing heap entered statistics')
            results.append({'case': case, 'status': 'passed'})
        except AssertionError as error:
            results.append({'case': case, 'status': 'failed', 'reason': str(error)})
    directory = output / 'revision_separation'
    for revision in (3, 4):
        target = directory / str(revision)
        target.mkdir(parents=True)
        for role in ('client', 'server'):
            raw = source / role / 'raw' / f'{role}.jsonl'
            rows = [json.loads(line) for line in raw.read_text().splitlines()]
            rows[0]['measurement_contract_revision'] = revision
            for row in rows:
                row['run_id'] += f'-revision-{revision}'
            (target / f'{role}.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    # Both copies have valid, recorded CALL_END boundaries. Different revision
    # metadata must still prevent pooling even if the numeric values are equal.
    run([build / 'turtle-report', directory, directory / 'report'], directory / 'report.log')
    summary = json.loads((directory / 'report/summary.json').read_text())
    require(summary['invalid_samples'] == 0 and len(summary['groups']) == 4,
            'measurement revisions were pooled or old explicit boundaries rejected')
    require(not summary['comparisons'], 'different measurement revisions compared')
    results.append({'case': 'revision_separation', 'status': 'passed'})
    (output / 'verification.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))
    require(all(r['status'] == 'passed' for r in results), f'original and mutations retained: {output}')
    if args.output is None:
        shutil.rmtree(output)


if __name__ == '__main__':
    main()
