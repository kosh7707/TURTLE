#!/usr/bin/env python3
"""별도 실행의 perf.data를 보존하고 엔드포인트·측정 구간별 함수/모듈 표본 비중을 계산합니다."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
from raw_record import read_tls_records, lifetime_span
import re
import shutil
import subprocess


SAMPLE = re.compile(r'^\s*(\d+)/(\d+)\s+(\d+)\.(\d+):\s+(\d+)\s+(\S+):\s+([0-9a-fA-F]+)\s+(.+)$')
PERF_VDSO = re.compile(r'/tmp/perf-vdso\.so-[A-Za-z0-9]+')


def parse_samples(text):
    samples, other = [], []
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = SAMPLE.match(line)
        if not match or ' (' not in match[8] or not match[8].endswith(')'):
            other.append(line)
            continue
        symbol, module = match[8].rsplit(' (', 1)
        samples.append({'pid': int(match[1]), 'tid': int(match[2]),
                        'monotonic_ns': int(match[3]) * 1000000000 + int(match[4].ljust(9, '0')),
                        'period': int(match[5]), 'event': match[6], 'ip': match[7],
                        'symbol': symbol, 'module': module[:-1]})
    return samples, other


def distribution(samples):
    total = sum(s['period'] for s in samples)
    functions, modules = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    for sample in samples:
        for row in (functions[(sample['module'], sample['symbol'])], modules[sample['module']]):
            row[0] += 1
            row[1] += sample['period']
    return {'status': 'available' if total else 'missing',
            'reason': None if total else 'no_perf_samples_in_window',
            'sample_count': len(samples), 'sample_period_sum': total if samples else None,
            'unknown_symbol_samples': sum(s['symbol'] == '[unknown]' for s in samples),
            'functions': [{'module': module, 'symbol': symbol, 'samples': count,
                           'period_weight': weight, 'period_fraction': weight / total if total else None}
                          for (module, symbol), (count, weight) in sorted(functions.items(), key=lambda p: -p[1][1])],
            'modules': [{'module': module, 'samples': count, 'period_weight': weight,
                         'period_fraction': weight / total if total else None}
                        for module, (count, weight) in sorted(modules.items(), key=lambda p: -p[1][1])]}


def invoke(argv, destination):
    environment = {**os.environ, 'DEBUGINFOD_URLS': '', 'LC_ALL': 'C'}
    result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=180,
                            env=environment)
    destination.write_text(result.stdout)
    destination.with_suffix(destination.suffix + '.stderr').write_text(result.stderr)
    return result.returncode


def elf_build_id(path):
    result = subprocess.run(['readelf', '-n', path], capture_output=True, text=True,
                            env={**os.environ, 'LC_ALL': 'C'}, timeout=30)
    match = re.search(r'Build ID: ([0-9a-fA-F]+)', result.stdout)
    return match[1].lower() if not result.returncode and match else None


def copy_binaries(root, expected):
    binaries = []
    for name, build_id in expected.items():
        source = Path(name)
        if not source.is_absolute():
            binaries.append({'source': name, 'build_id': build_id, 'status': 'unsupported',
                             'reason': 'not_a_file_backed_user_binary'})
            continue
        # Preserve original absolute names below symfs, so replay does not depend
        # on the current build or installed shared-library version.
        target = root / 'symbols' / source.relative_to('/')
        entry = {'source': name, 'build_id': build_id, 'path': str(target.relative_to(root)),
                 'status': 'missing', 'reason': 'recorded_binary_unavailable'}
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            observed = elf_build_id(target)
            entry['observed_build_id'] = observed
            if observed == build_id:
                entry.update(status='available', reason=None,
                             sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            else:
                entry['reason'] = 'recorded_build_id_mismatch'
                target.unlink()
        binaries.append(entry)
    return binaries


def binary_provenance(root, perf):
    destination = root / 'binary-provenance.json'
    if not destination.exists():
        code = invoke([perf, 'buildid-list', '-i', root / 'perf.data'], root / 'perf.buildids.txt')
        expected, other = {}, []
        for line in (root / 'perf.buildids.txt').read_text().splitlines():
            match = re.fullmatch(r'([0-9a-fA-F]+)\s+(.+)', line)
            if match:
                expected[match[2]] = match[1].lower()
            elif line.strip():
                other.append(line)
        manifest = {'schema': 1, 'buildid_list_returncode': code, 'unparsed': other,
                    'perf_data_sha256': hashlib.sha256((root / 'perf.data').read_bytes()).hexdigest(),
                    'binaries': copy_binaries(root, expected)}
        destination.write_text(json.dumps(manifest, indent=2) + '\n')
    manifest = json.loads(destination.read_text())
    return verify_binaries(root, manifest)


def verify_binaries(root, manifest):
    failures = []
    virtual, unparsed = [], []
    for line in manifest['unparsed']:
        if PERF_VDSO.fullmatch(line.strip()):
            virtual.append({'source': line.strip(), 'status': 'unsupported', 'build_id': None,
                            'reason': 'ephemeral_perf_vdso_without_recorded_build_id'})
        else:
            unparsed.append(line)
    if manifest['buildid_list_returncode'] or unparsed or not manifest['binaries']:
        failures.append('recorded_build_ids_missing')
    if hashlib.sha256((root / 'perf.data').read_bytes()).hexdigest() != manifest['perf_data_sha256']:
        failures.append('perf_data_changed_since_binary_snapshot')
    for entry in manifest['binaries']:
        if entry['status'] == 'unsupported':
            continue
        if entry['status'] != 'available':
            failures.append(entry['source'] + ': ' + entry['reason'])
            continue
        saved = root / entry['path']
        if not saved.is_file() or hashlib.sha256(saved.read_bytes()).hexdigest() != entry['sha256']:
            failures.append(entry['source'] + ': saved_binary_missing_or_changed')
    return {**manifest, 'status': 'missing' if failures else 'available', 'failures': failures,
            'unsupported_virtual_objects': virtual, 'unrecognized_build_id_lines': unparsed}


def preserve_unresolved_symbols(samples, binaries):
    unsupported = {entry['source'] for entry in binaries['binaries'] if entry['status'] == 'unsupported'}
    for sample in samples:
        module = sample['module']
        if (module in unsupported or module in ('[vdso]', '[vdso32]', '[vdsox32]') or
                PERF_VDSO.fullmatch(module)):
            sample['symbol'] = '[unknown]'
            sample['symbol_status'] = 'unpreserved_virtual_object'


def analyze(root, perf):
    manifest = json.loads((root / 'profile-manifest.json').read_text())
    data = root / 'perf.data'
    if not data.exists() or data.stat().st_size == 0:
        summary = {'type': 'turtle-cpu-profile', 'schema': 1, 'status': 'missing',
                   'reason': 'perf_data_missing', 'record_returncode': manifest.get('returncode')}
        (root / 'cpu-profile.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 1
    binaries = binary_provenance(root, perf)
    # An explicit, possibly incomplete symfs prevents stale live binaries from
    # silently supplying symbols after a rebuild. Unknown samples remain data.
    (root / 'symbols').mkdir(exist_ok=True)
    code = invoke([perf, 'script', '-i', data, '--symfs', root / 'symbols', '--ns', '--show-lost-events',
                   '-F', 'pid,tid,time,event,period,ip,sym,dso'], root / 'perf.script.txt')
    attributes_code = invoke([perf, 'evlist', '-i', data, '-v'], root / 'perf.events.txt')
    invoke([perf, 'report', '-i', data, '--stdio', '--header-only'], root / 'perf.header.txt')
    samples, other = parse_samples((root / 'perf.script.txt').read_text())
    preserve_unresolved_symbols(samples, binaries)
    windows, failures = [], []
    for raw in sorted((root / 'run').glob('sample-*/*.jsonl')):
        if raw.stem not in ('client', 'server'):
            continue
        records = read_tls_records(raw)
        header, events = records[0], records[1:]
        if not header['valid']:
            failures.append({'source': str(raw.relative_to(root)), 'reason': header['invalid_reason']})
            continue
        if not header['config'].get('cpu_profile', False):
            failures.append({'source': str(raw.relative_to(root)), 'reason': 'separate_profile_marker_missing'})
            continue
        pid = header['pid']
        local = [s for s in samples if s['pid'] == pid and s['tid'] == pid]
        by_sequence = {e['sequence']: e for e in events}
        name, begin, end = lifetime_span(header, events)
        spans = [(name, None, begin, end)]
        for connection in header['connections']:
            if connection['start_sequence'] is not None:
                spans.append(('primary', connection['index'], by_sequence[connection['start_sequence']],
                              by_sequence[connection['end_sequence']]))
        for name, index, begin, end in spans:
            selection = [s for s in local if begin['monotonic_ns'] <= s['monotonic_ns'] <= end['monotonic_ns']]
            windows.append({'source': str(raw.relative_to(root)), 'role': header['role'], 'pid': pid,
                            'tid': pid, 'connection': index, 'window': name,
                            'begin_monotonic_ns': begin['monotonic_ns'], 'end_monotonic_ns': end['monotonic_ns'],
                            'elapsed_ns': end['monotonic_ns'] - begin['monotonic_ns'],
                            'thread_cpu_ns': end['thread_cpu_ns'] - begin['thread_cpu_ns'],
                            'thread_cpu_scope': 'thread-user-plus-kernel', **distribution(selection)})
    files = {str(data): hashlib.sha256(data.read_bytes()).hexdigest()}
    for entry in binaries['binaries']:
        if entry['status'] == 'available':
            files[entry['path']] = entry['sha256']
    complete = (binaries['status'] == 'available' and not manifest.get('returncode') and
                not code and not attributes_code and windows and samples and
                not other and not failures)
    summary = {'type': 'turtle-cpu-profile', 'schema': 1,
               'status': 'available' if complete else 'missing',
               'record_returncode': manifest.get('returncode'), 'script_returncode': code,
               'sampling_event': manifest['event'], 'frequency_hz': manifest['frequency_hz'],
               'clock': 'CLOCK_MONOTONIC via perf record --clockid mono',
               'process_scope': 'fresh endpoint PIDs, main TID only; local runner samples excluded from windows',
               'cpu_scope': 'task follows scheduler; no per-core attribution',
               'event_attributes_file': 'perf.events.txt', 'unparsed_or_lost_records': other,
               'binary_provenance': binaries,
               'tool_warnings': {p.name: p.read_text() for p in root.glob('*.stderr') if p.stat().st_size},
               'windows': windows, 'failed_endpoints': failures, 'artifact_sha256': files,
               'limitations': ['비중은 관측 표본의 period 가중치이며 총 CPU 시간이나 총 사이클이 아닙니다.',
                              '짧은 연결 구간은 표본이 없을 수 있으며 이를 0으로 표현하지 않습니다.',
                              '알 수 없는 함수 표본도 분모와 원자료에 남습니다.',
                              '저장·build ID 확인이 없는 vDSO 등 가상 객체의 함수 이름은 unknown으로 유지합니다.',
                              'symbols/에는 build ID가 일치한 실행 파일을 보존합니다. 별도 debug-info 파일·커널 심볼은 보장하지 않습니다.',
                              '호출 스택·커널 재전송 tracepoint는 수집하지 않습니다.',
                              '이 실행의 경과시간은 표본 계측 부담을 포함합니다. 일반 시간 실행과 합치지 않습니다.']}
    (root / 'cpu-profile.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    with (root / 'cpu-functions.csv').open('w', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=['source', 'role', 'pid', 'window', 'connection',
                                                   'module', 'symbol', 'samples', 'period_weight', 'period_fraction'])
        writer.writeheader()
        for window in windows:
            for function in window['functions']:
                writer.writerow({**{k: window[k] for k in ('source', 'role', 'pid', 'window', 'connection')},
                                 **function})
    print(f'{len(samples)} samples, {len(windows)} endpoint windows, status={summary["status"]}')
    return int(not complete)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'analyze'))
    parser.add_argument('--perf', type=Path)
    parser.add_argument('--build', type=Path, default=Path('build'))
    parser.add_argument('--pki', type=Path, default=Path('pki/default'))
    parser.add_argument('--client')
    parser.add_argument('--client-bin', type=Path)
    parser.add_argument('--server')
    parser.add_argument('--server-bin', type=Path)
    parser.add_argument('--group', default='secp256r1')
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--event', choices=('cycles:u', 'cpu-clock:u', 'cycles', 'cpu-clock'), default='cycles:u')
    parser.add_argument('--frequency', type=int, default=997)
    parser.add_argument('--no-affinity', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    perf = args.perf or shutil.which('perf')
    if perf is None:
        parser.error('--perf에 perf 실행 파일을 지정하거나 PATH에 준비해야 합니다')
    if shutil.which('readelf') is None:
        parser.error('수집 바이너리 build ID 대조에 binutils의 readelf가 필요합니다')
    perf = Path(perf).resolve()
    root, build, pki = args.output.resolve(), args.build.resolve(), args.pki.resolve()
    if args.action == 'run':
        if args.samples < 1 or not 1 <= args.frequency <= 100000:
            parser.error('samples >= 1, frequency 1..100000이 필요합니다')
        root.mkdir(parents=True, exist_ok=False)
        argv = [perf, 'record', '-e', args.event, '-F', args.frequency, '--clockid', 'mono',
                '--no-buildid-cache', '-o', root / 'perf.data', '--', build / 'turtle-local',
                '--group', args.group, '--pki', pki,
                '--adapter-dir', build / 'adapters', '--mutual-auth', '--scenario', 'client-request',
                '--samples', args.samples, '--connections', 1, '--warmups', 0,
                '--mode', 'timing', '--cpu-profile', '--no-perf', '--output', root / 'run']
        for option in ('client', 'server', 'client_bin', 'server_bin'):
            value = getattr(args, option)
            if value is not None:
                argv += ['--' + option.replace('_', '-'), value]
        if args.no_affinity:
            argv += ['--no-affinity']
        manifest = {'schema': 1, 'event': args.event, 'frequency_hz': args.frequency,
                    'command': list(map(str, argv)), 'kernel': os.uname().release,
                    'performance_experiment': False, 'call_graph': False}
        invoke([perf, '--version'], root / 'perf.version.txt')
        (root / 'profile-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        manifest['returncode'] = invoke(argv, root / 'record.stdout')
        (root / 'profile-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return analyze(root, perf)


if __name__ == '__main__':
    raise SystemExit(main())
