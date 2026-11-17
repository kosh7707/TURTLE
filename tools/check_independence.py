#!/usr/bin/env python3
"""선택적 격리 검증: Python 도구는 밖에서 실행하고, 안에서는 CMake·C++만 실행한다."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--framework-prefix', type=Path, required=True)
    parser.add_argument('--openssl-prefix', type=Path, required=True)
    parser.add_argument('--wolfssl-prefix', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--privileged-tests', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    source.mkdir()
    for name in ('src', 'include', 'implementations', 'tests', 'cmake'):
        shutil.copytree(ROOT / name, source / name)
    shutil.copy2(ROOT / 'CMakeLists.txt', source / 'CMakeLists.txt')
    # No tools directory or Python source enters the sandbox.
    mounts = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--uid', '0', '--gid', '0',
              '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
              '--symlink', 'usr/lib', '/lib', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
              '--tmpfs', '/run', '--tmpfs', '/home', '--dir', '/work', '--bind', str(source), '/work',
              '--ro-bind', str(args.framework_prefix.resolve()), '/deps/native',
              '--ro-bind', str(args.openssl_prefix.resolve()), '/deps/openssl',
              '--ro-bind', str(args.wolfssl_prefix.resolve()), '/deps/wolfssl', '--chdir', '/work',
              '--clearenv', '--setenv', 'PATH', '/usr/bin:/usr/sbin:/deps/native/bin',
              '--setenv', 'HOME', '/tmp', '--setenv', 'LC_ALL', 'C',
              '--setenv', 'LD_LIBRARY_PATH', '/deps/openssl/lib:/deps/wolfssl/lib']
    if args.privileged_tests:
        if os.geteuid() != 0:
            raise RuntimeError('--privileged-tests requires root')
        mounts.remove('--unshare-all')
        mounts[1:1] = ['--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts', '--cap-add', 'ALL',
                        '--ro-bind', '/sys', '/sys']
    if Path('/lib64').exists():
        mounts += ['--symlink', 'usr/lib64', '/lib64']
    hidden = set()
    for base in (Path('/usr/bin'), Path('/usr/local/bin')):
        hidden.update(p.resolve() for p in base.glob('python*') if p.is_file())
    for base in (Path('/usr/lib'), Path('/usr/local/lib')):
        hidden.update(p.resolve() for p in base.glob('**/libpython*.so*') if p.is_file())
    unavailable_tools = []
    for name in ('tcpdump',):
        resolved = shutil.which(name)
        if resolved:
            unavailable_tools.append(Path(resolved).resolve())
    for path in sorted(set(unavailable_tools)):
        mounts += ['--ro-bind', '/dev/null', str(path)]
    for path in sorted(hidden):
        mounts += ['--ro-bind', '/dev/null', str(path)]
    prefix = '-DCMAKE_PREFIX_PATH=/deps/native'
    commands = [
        ['cmake', '-S', '.', '-B', 'out/build', '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', prefix,
         '-DTURTLE_IMPLEMENTATION_DIRS=/work/implementations/openssl;/work/implementations/wolfssl',
         '-DOPENSSL_ROOT_DIR=/deps/openssl', '-DWOLFSSL_ROOT_DIR=/deps/wolfssl'],
        ['cmake', '--build', 'out/build', '--parallel', str(args.jobs)],
        ['cmake', '--install', 'out/build', '--prefix', '/work/out/install'],
        ['cmake', '-S', 'tests', '-B', 'out/tests', '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', prefix,
         '-DTURTLE_BINARY_DIR=/work/out/build', '-DTURTLE_TEST_OPENSSL=ON', '-DTURTLE_TEST_WOLFSSL=ON',
         '-DOPENSSL_ROOT_DIR=/deps/openssl'],
        ['cmake', '--build', 'out/tests', '--parallel', str(args.jobs)],
        ['ctest', '--test-dir', 'out/tests', '--output-on-failure', '--parallel', str(args.jobs)],
        ['/work/out/install/bin/turtle', 'analyze', '/work/out/tests/artifacts/tls_openssl_openssl_classical/run'],
        ['ldd', '/deps/native/bin/perf'],
        ['sh', '-c', 'test ! -e /work/tools && test ! -e /work/python && test -z "$(ls -A /home)"'],
    ]
    if args.privileged_tests:
        commands[3] += ['-DTURTLE_TEST_NETEM=ON', '-DTURTLE_TEST_PERF=ON',
                        '-DTURTLE_PERF_EXECUTABLE=/deps/native/bin/perf']
    evidence = {'schema': 'turtle.independence.v2', 'status': 'running', 'network': 'isolated', 'privileged_tests': args.privileged_tests,
                'hidden_python_executables_and_libraries': list(map(str, sorted(hidden))),
                'unavailable_tools': list(map(str, unavailable_tools)), 'commands': []}
    for i, command in enumerate(commands):
        log = output / f'{i:02d}.log'
        with log.open('w') as stream:
            result = subprocess.run([*mounts, *command], stdout=stream, stderr=subprocess.STDOUT)
        evidence['commands'].append({'argv': command, 'returncode': result.returncode, 'log': log.name})
        (output / 'verification.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if result.returncode:
            evidence['status'] = 'failed'
            (output / 'verification.json').write_text(json.dumps(evidence, indent=2) + '\n')
            raise RuntimeError('isolated command failed: ' + str(log))
    evidence['status'] = 'passed'
    (output / 'verification.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(output / 'verification.json')


if __name__ == '__main__':
    main()
