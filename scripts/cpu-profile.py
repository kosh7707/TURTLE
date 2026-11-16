#!/usr/bin/env python3
"""별도 수집 실행의 perf.data·실행 바이너리·심볼 출처와 구간별 CPU 표본을 보존합니다."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
from collections import defaultdict
from run import run
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
        manifest = {'contract': 'turtle-message-symbols/1', 'buildid_list_returncode': code, 'unparsed': other,
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


def analyze(root,perf):
    root=Path(root)
    manifest=json.loads((root/'profile.json').read_text())
    if manifest.get('contract')!='turtle-message-cpu-collection/1':raise ValueError('unsupported CPU collection')
    roles={}
    for role in ('client','server'):
        data=root/role
        if not (data/'perf.data').is_file() or not (data/'perf.data').stat().st_size:
            roles[role]=dict(status='missing',reason='perf.data unavailable');continue
        binaries=binary_provenance(data,perf)
        (data/'symbols').mkdir(exist_ok=True)
        code=invoke([perf,'script','-i',data/'perf.data','--symfs',data/'symbols','--ns','--show-lost-events','-F','pid,tid,time,event,period,ip,sym,dso'],data/'perf.script.txt')
        invoke([perf,'evlist','-i',data/'perf.data','-v'],data/'perf.events.txt')
        invoke([perf,'report','-i',data/'perf.data','--stdio','--header-only'],data/'perf.header.txt')
        samples,other=parse_samples((data/'perf.script.txt').read_text());preserve_unresolved_symbols(samples,binaries)
        endpoint=json.loads((root/'run'/role/'manifest.json').read_text())
        if not endpoint['observation']['cpu_samples']=='separate-collection-requested':raise ValueError('CPU collection marker absent')
        events=[json.loads(line) for line in (root/'run'/role/'events.jsonl').read_text().splitlines()]
        local=[s for s in samples if s['pid']==endpoint['pid'] and s['tid']==endpoint['pid']]
        windows=[]
        for e in events:
            if e['begin'] is None or e['end'] is None:continue
            first,last=e['begin']['monotonic_ns'],e['end']['monotonic_ns']
            windows.append(dict(kind=e['kind'],connection_id=e['connection_id'],message_id=e['message_id'],record_id=e['record_id'],begin_ns=first,end_ns=last,
                                distribution=distribution([s for s in local if first<=s['monotonic_ns']<last])))
        roles[role]=dict(status='available' if code==0 and samples and not other and binaries['status']=='available' else 'missing',
                         windows=windows,sample_count=len(samples),unparsed_or_lost=other,binaries=binaries,main_thread=endpoint['pid'],all_main_thread=distribution(local))
    report=dict(contract='turtle-message-cpu-report/1',collection=manifest,roles=roles,
                semantics='sample-period fractions; overlapping parent/child windows are separate views; not exact function call durations')
    (root/'cpu-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['run','analyze']);p.add_argument('--perf',default=shutil.which('perf'));p.add_argument('--build',default='build-message');p.add_argument('--pki',default='pki/default');p.add_argument('--output',required=True);p.add_argument('--client',default='openssl');p.add_argument('--server',default='openssl');p.add_argument('--group',default='P-256');p.add_argument('--connections',type=int,default=20);p.add_argument('--event',choices=['cycles:u','cpu-clock:u'],default='cycles:u');p.add_argument('--frequency',type=int,default=997)
    a=p.parse_args();root=Path(a.output).resolve()
    if not a.perf:p.error('perf path is required')
    perf=str(Path(a.perf).resolve())
    if a.action=='run':
        root.mkdir(parents=True,exist_ok=False)
        manifest=dict(contract='turtle-message-cpu-collection/1',event=a.event,frequency_hz=a.frequency,clock='CLOCK_MONOTONIC',kernel=os.uname().release,ordinary_performance_sample=False,collection_overhead=dict(status='not-collected',separate_collector_cpu_ns=None,endpoint_instrumentation='perf sampling active; no overhead subtraction'),prefixes={},success=False)
        for role in ('client','server'):
            (root/role).mkdir()
            manifest['prefixes'][role]=[perf,'record','-e',a.event,'-F',str(a.frequency),'--clockid','mono','--no-buildid-cache','-o',str(root/role/'perf.data'),'--']
        invoke([perf,'--version'],root/'perf.version.txt')
        try:
            run(a.build,a.pki,root/'run',a.client,a.server,prefixes=manifest['prefixes'],group=a.group,connections=a.connections,depth='white-box',mutual_auth=True,cpu_samples=True)
            manifest['success']=True
        except Exception as error:manifest['failure']=str(error)
        (root/'profile.json').write_text(json.dumps(manifest,indent=2)+'\n')
    report=analyze(root,perf)
    return 0 if all(r['status']=='available' for r in report['roles'].values()) else 1


if __name__=='__main__':raise SystemExit(main())
