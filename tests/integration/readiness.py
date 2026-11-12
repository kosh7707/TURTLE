#!/usr/bin/env python3
"""실제 TCP 연결과 준비 판정, 첫 TLS 연결 및 준비 실패 원자료를 확인합니다."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def header(directory, role):
    return json.loads((directory / f'{role}.jsonl').read_text().splitlines()[0])


def pair(build, pki, case, failure=None):
    client_dir, server_dir = case / 'client', case / 'server'
    client_dir.mkdir(parents=True)
    server_dir.mkdir()
    ready = server_dir / 'listening.json'
    module = build / 'adapters/openssl.so'
    common = ['--pki', str(pki), '--module', str(module), '--no-affinity', '--no-perf',
              '--timeout-ms', '5000', '--scenario', 'client-request', '--mutual-auth']
    server_args = ['--module', str(case / 'not-installed.so')] if failure == 'setup' else []
    server = subprocess.Popen([build / 'turtle-server', *common, *server_args,
                               '--listen', '0.0.0.0:0', '--control-listen', '0.0.0.0:0',
                               '--mode', 'memory', '--ready-file', ready, '--output', 'raw'],
                              cwd=server_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    try:
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None:
                raise AssertionError(server.communicate())
            try:
                ports = json.loads(ready.read_text())
                break
            except (OSError, json.JSONDecodeError):
                if time.monotonic() >= deadline:
                    raise TimeoutError('server did not listen')
                time.sleep(.005)
        assert ports['state'] == 'listening' and ports['test_ready'] is False
        extra = ['--scenario', 'handshake'] if failure == 'scenario' else []
        client = subprocess.run([build / 'turtle-client', *common, *extra,
                                 '--connect', f"127.0.0.1:{ports['port']}",
                                 '--control-connect', f"127.0.0.1:{ports['control_port']}",
                                 '--output', 'raw'], cwd=client_dir, capture_output=True,
                                text=True, timeout=10)
        out, err = server.communicate(timeout=10)
        if failure:
            assert client.returncode != 0 and server.returncode != 0, (client.stderr, err)
        else:
            assert client.returncode == server.returncode == 0, (client.stderr, out, err)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()
    client, server = header(client_dir / 'raw', 'client'), header(server_dir / 'raw', 'server')
    for value in (client, server):
        state = value['preparation']
        assert state['control_connected']
        assert state['control']['local']['address'] == '127.0.0.1'
        assert state['control']['peer']['address'] == '127.0.0.1'
        if failure:
            assert not value['valid'] and value['invalid_reason']
            assert not state['peer_prepared']
            assert value['connections'] == []
        else:
            assert value['valid'] and state['stage'] == 'ready'
            assert state['local_prepared'] and state['peer_prepared']
            assert value['config']['warmups'] == 0
            assert len(value['connections']) == 1
            connection = value['connections'][0]
            assert connection['index'] == 0 and not connection['warmup']
            assert connection['scenario_completed'] and connection['verification'] == 'passed'
            assert state['local']['peer_authentication'] == 'not_checked'
            assert state['local']['data_connection'] == 'not_probed'
    if failure == 'scenario':
        assert all(v['failure_phase'] == 'scenario' for v in (client, server))
        assert not client['preparation']['scenario_agreed']
    elif failure == 'setup':
        assert server['preparation']['stage'] == 'local_preparation'
        assert client['preparation']['stage'] == 'peer_preparation'
        assert client['preparation']['local_prepared']
        assert 'peer aborted' in client['invalid_reason']
    else:
        assert client['preparation']['peer'] == server['preparation']['local']
        assert server['preparation']['peer'] == client['preparation']['local']
        assert client['preparation']['local']['mode'] == 'timing'
        assert client['preparation']['peer']['mode'] == 'memory'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('pki', type=Path)
    args = parser.parse_args()
    build, pki = args.build.resolve(), args.pki.resolve()
    with tempfile.TemporaryDirectory(prefix='turtle-readiness-') as temporary:
        root = Path(temporary)
        pair(build, pki, root / 'ready')
        pair(build, pki, root / 'different-scenario', 'scenario')
        pair(build, pki, root / 'missing-module', 'setup')
        # Reserve a local port without a listener: a connect failure is distinct
        # from scenario or preparation failure and does not consume a TLS trial.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(('127.0.0.1', 0))
            output = root / 'not-listening'
            result = subprocess.run([build / 'turtle-client', '--module', build / 'adapters/openssl.so',
                                     '--pki', pki, '--no-affinity', '--no-perf',
                                     '--control-connect', f'127.0.0.1:{reserved.getsockname()[1]}',
                                     '--timeout-ms', '1000', '--output', output],
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode != 0
            value = header(output, 'client')
            assert not value['valid'] and value['failure_phase'] == 'control_connect'
            assert not value['preparation']['control_connected']
            assert value['preparation']['local'] is None and value['preparation']['peer'] is None
            assert value['connections'] == []
    print('PASS: TCP readiness, wildcard bind, first TLS connection, separate failure stages')


if __name__ == '__main__':
    main()
