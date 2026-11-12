#!/usr/bin/env python3
"""준비한 고정 의존성으로 새 빌드·설치 경로에서 정상 TLS를 재현합니다. 다운로드하지 않습니다."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--deps', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    source, deps, work = args.source.resolve(), args.deps.resolve(), args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    commands, checks = [], []

    def run(command, name):
        command = list(map(str, command))
        commands.append({'name': name, 'command': command})
        (work / 'commands.json').write_text(json.dumps(commands, ensure_ascii=False, indent=2) + '\n')
        with (work / (name + '.log')).open('w') as log:
            subprocess.run(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)

    builds = {}
    for linkage, library in [('module', 'all'), ('builtin', 'openssl'), ('builtin', 'wolfssl'), ('builtin', 'mbedtls')]:
        name = f'{linkage}-{library}'
        build, install = work / ('build-' + name), work / ('install-' + name)
        options = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DTURTLE_WARNINGS_AS_ERRORS=ON',
                   f'-DTURTLE_DEPS_ROOT={deps}', f'-DTURTLE_ADAPTER_LINKAGE={linkage}',
                   f'-DCMAKE_INSTALL_RPATH={deps / "openssl/lib"}']
        if linkage == 'module':
            options += ['-DTURTLE_BUILD_MODULES=ON', '-DTURTLE_WITH_OPENSSL=ON',
                        '-DTURTLE_WITH_WOLFSSL=ON', '-DTURTLE_WITH_MBEDTLS=ON']
        else:
            options += [f'-DTURTLE_IMPLEMENTATION={library}', '-DTURTLE_BUILD_ANALYSIS=OFF']
        run(['cmake', '-S', source, '-B', build, *options], name + '-configure')
        run(['cmake', '--build', build, '--parallel', args.jobs], name + '-build')
        run(['cmake', '--install', build, '--prefix', install], name + '-install')
        builds[name] = (build, install)
    pki = work / 'pki'
    run([source / 'scripts/make-pki.sh', pki], 'certificates')
    analysis = builds['module-all'][0]
    for linkage in ('module', 'builtin'):
        for library in ('openssl', 'wolfssl', 'mbedtls'):
            build, install = builds['module-all' if linkage == 'module' else f'builtin-{library}']
            for scenario in ('handshake', 'server-ping', 'finished-ping', 'client-request'):
                name = f'{library}-{linkage}-{scenario}'
                output = work / 'results' / name
                command = ['python3', source / 'scripts/run-local.py', '--build', analysis,
                           '--client-bin', install / 'bin/turtle-client',
                           '--server-bin', install / 'bin/turtle-server', '--pki', pki,
                           '--scenario', scenario, '--mode', 'trace', '--no-perf', '--no-affinity',
                           '--samples', '1', '--warmups', '1', '--connections', '2',
                           '--client-bytes', '16385', '--server-bytes', '16386',
                           '--mutual-auth', '--timeout-ms', '30000', '--output', output]
                if linkage == 'module':
                    command += ['--client', library, '--server', library, '--adapter-dir', build / 'adapters']
                run(command, name + '-execute')
                hashes = {}
                for raw in sorted(output.rglob('*.jsonl')):
                    if raw.name not in ('client.jsonl', 'server.jsonl'):
                        continue
                    header = json.loads(raw.open().readline())
                    assert header['valid'] and header['measurement_contract_revision'] == 4, raw
                    assert header['control_protocol'] == 2 and not header['declaration']['is_mock'], raw
                    assert len(header['connections']) == 3, raw
                    assert all(c['scenario_completed'] for c in header['connections']), raw
                    assert all(c['negotiated']['version'] == 'TLS1.3' and not c['negotiated']['resumed'] for c in header['connections']), raw
                    hashes[str(raw)] = hashlib.sha256(raw.read_bytes()).hexdigest()
                    decoded = raw.with_suffix('.decoded.json')
                    run([analysis / 'turtle-interpret', raw, decoded], name + '-' + raw.stem + '-decode')
                    document = json.loads(decoded.read_text())
                    assert all(c['decryption_complete'] for c in document['connections']), decoded
                report = output / 'report'
                run([analysis / 'turtle-report', output, report], name + '-report')
                summary = json.loads((report / 'summary.json').read_text())
                assert summary['invalid_samples'] == 0 and len(summary['samples']) == 2, report
                assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == sha for p, sha in hashes.items())
                checks.append({'case': name, 'endpoint_samples': 2, 'connections_per_endpoint': 3,
                               'measurement_connections_per_endpoint': 2, 'raw_sha256': hashes,
                               'report': str(report / 'summary.json')})
                (work / 'verification.json').write_text(json.dumps(checks, indent=2) + '\n')
    print(f'PASS: {len(checks)} actual TLS pairs; independent client/server, decode and report')


if __name__ == '__main__':
    main()
