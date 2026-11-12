#!/usr/bin/env python3
"""빌드 헬퍼의 경로·구성·호출 순서 계약입니다. 실제 빌드나 TLS 시험이 아닙니다."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    script = Path(sys.argv[1]).resolve()
    repository = script.parent.parent
    with tempfile.TemporaryDirectory(prefix='turtle-build-helpers-') as temporary:
        root = Path(temporary)
        caller = root / 'caller with spaces'
        caller.mkdir()
        tools = root / 'tools'
        tools.mkdir()
        log = root / 'commands.jsonl'
        for name in ('cmake', 'ctest'):
            program = tools / name
            program.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['BUILD_HELPER_COMMANDS'], 'a') as stream:
    stream.write(json.dumps({'program': name, 'args': sys.argv[1:]}) + '\\n')
if name == 'cmake' and '-S' in sys.argv and os.environ.get('BUILD_HELPER_FAIL_CONFIGURE'):
    sys.exit(23)
''')
            program.chmod(0o755)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('TURTLE_') and key not in ('JOBS', 'REPEAT', 'STATIC_CHECKS')}
        environment.update(PATH=str(tools) + os.pathsep + os.environ['PATH'],
                           BUILD_HELPER_COMMANDS=str(log), TURTLE_DEPS_ROOT=str(root / 'deps'), JOBS='3')

        def invoke(*args, check=False, expect=0, **overrides):
            log.unlink(missing_ok=True)
            result = subprocess.run([str(script.parent / 'check.sh' if check else script), *args],
                                    cwd=caller, env={**environment, **overrides}, capture_output=True, text=True)
            assert result.returncode == expect, (result.returncode, result.stdout, result.stderr)
            return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

        def value(command, flag):
            return command['args'][command['args'].index(flag) + 1]

        def definitions(command):
            return dict(arg[2:].split('=', 1) for arg in command['args'] if arg.startswith('-D'))

        # Calling from another directory must still select the repository and its active build.
        rows = invoke()
        assert [r['program'] for r in rows] == ['cmake', 'cmake']
        assert value(rows[0], '-S') == str(repository)
        assert value(rows[0], '-B') == str(repository / 'build-module')
        assert value(rows[1], '--build') == value(rows[0], '-B')
        assert value(rows[1], '--parallel') == '3'
        options = definitions(rows[0])
        assert options['TURTLE_ADAPTER_LINKAGE'] == 'module'
        assert options['TURTLE_WITH_WOLFSSL'] == 'OFF'
        assert options['TURTLE_WITH_MBEDTLS'] == 'OFF'

        # An explicit dependency root controls both detection and CMake, including paths with spaces.
        deps = caller / 'prepared deps'
        for rel in ('install/wolfssl-5.8.2-stable/include/wolfssl/ssl.h',
                    'install/mbedtls-3.6.4-pic/include/mbedtls/ssl.h',
                    'install/bithac-baseline/lib/libwolfssl.a'):
            path = deps / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        rows = invoke('module', '--', '-DTURTLE_DEPS_ROOT:PATH=prepared deps',
                      '-DCMAKE_CXX_FLAGS=-O2 -g', TURTLE_BUILD_DIR='custom build')
        options = definitions(rows[0])
        assert options['TURTLE_DEPS_ROOT'] == str(deps)
        assert options['TURTLE_WITH_WOLFSSL'] == options['TURTLE_WITH_MBEDTLS'] == 'ON'
        assert options['TURTLE_WITH_BITHAC'] == 'OFF'  # An incomplete comparison pair is not enabled.
        assert options['CMAKE_CXX_FLAGS'] == '-O2 -g'
        assert value(rows[0], '-B') == str(caller / 'custom build')

        # Endpoint-only builds must not pull in another role, modules or analysis dependencies.
        for profile, library, client, server in [('client', 'wolfssl', 'ON', 'OFF'),
                                                 ('server', 'mbedtls', 'OFF', 'ON'),
                                                 ('builtin', 'openssl', 'ON', 'ON')]:
            rows = invoke(profile, library)
            options = definitions(rows[0])
            assert value(rows[0], '-B') == str(repository / f'build-{profile}-{library}')
            assert options['TURTLE_BUILD_CLIENT'] == client and options['TURTLE_BUILD_SERVER'] == server
            assert options['TURTLE_ADAPTER_LINKAGE'] == 'builtin'
            assert options['TURTLE_IMPLEMENTATION'] == library
            for option in ('TURTLE_BUILD_MODULES', 'TURTLE_BUILD_ANALYSIS', 'TURTLE_BUILD_LOOKUP'):
                assert options[option] == 'OFF'
        rows = invoke('analysis')
        options = definitions(rows[0])
        assert options['TURTLE_BUILD_CLIENT'] == options['TURTLE_BUILD_SERVER'] == 'OFF'
        assert options['TURTLE_BUILD_ANALYSIS'] == options['TURTLE_WITH_INTERPRETER'] == 'ON'

        # Tests have a separate source, output and build type even when a production override is set.
        rows = invoke('tests', TURTLE_BUILD_DIR='production')
        assert value(rows[0], '-S') == str(repository / 'tests')
        assert value(rows[0], '-B') == str(repository / 'build-tests-independent')
        assert definitions(rows[0])['CMAKE_BUILD_TYPE'] == 'Debug'
        rows = invoke(check=True, TURTLE_BUILD_DIR='production', TURTLE_TEST_BUILD_DIR='test build',
                      TURTLE_BUILD_TYPE='MinSizeRel', REPEAT='1', STATIC_CHECKS='0')
        assert [r['program'] for r in rows] == ['cmake', 'cmake', 'cmake', 'cmake', 'ctest']
        assert definitions(rows[0])['CMAKE_BUILD_TYPE'] == 'Release'
        assert definitions(rows[2])['CMAKE_BUILD_TYPE'] == 'Debug'
        assert value(rows[2], '-B') == value(rows[4], '--test-dir') == str(caller / 'test build')
        assert value(rows[4], '--repeat') == 'until-fail:1'

        # Configuration errors stop before build; invalid destinations stop before touching CMake.
        rows = invoke(BUILD_HELPER_FAIL_CONFIGURE='1', expect=23)
        assert len(rows) == 1 and '-S' in rows[0]['args']
        assert not invoke(check=True, TURTLE_BUILD_DIR='same', TURTLE_TEST_BUILD_DIR='same', expect=2)
        assert not invoke(TURTLE_BUILD_DIR=str(repository), expect=2)
        assert not invoke(JOBS='0', expect=2)
        assert not invoke('unknown', expect=2)
        assert not invoke('--help')
    print('PASS: 빌드 헬퍼 경로·구성·호출 순서 계약 (가짜 CMake/CTest)')


if __name__ == '__main__':
    main()
