#!/usr/bin/env python3
"""별도 작업·출력 경로의 두 실행 파일로 실제 TLS와 schema 3 결합을 확인합니다."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('pki', type=Path)
    args = parser.parse_args()
    build, pki = args.build.resolve(), args.pki.resolve()
    with tempfile.TemporaryDirectory(prefix='turtle-independent-') as temporary:
        root = Path(temporary)
        for library in ('openssl', 'wolfssl', 'mbedtls'):
            module = build / 'adapters' / (library + '.so')
            if not module.exists(): continue
            for scenario in ('handshake', 'server-ping', 'finished-ping', 'client-request'):
                case = root / library / scenario
                client_dir, server_dir = case / 'c', case / 's'
                client_dir.mkdir(parents=True); server_dir.mkdir()
                ready = server_dir / 'ready.json'
                cpu = str(min(os.sched_getaffinity(0)))
                common = ['--module', str(module), '--pki', str(pki), '--cpu', cpu, '--no-perf',
                          '--scenario', scenario, '--mode', 'trace', '--mutual-auth',
                          '--warmups', '1', '--connections', '2', '--client-bytes', '32769',
                          '--server-bytes', '19013', '--send-policy', 'server-hello-first']
                server = subprocess.Popen([build / 'turtle-server', *common, '--listen', '0.0.0.0:0',
                                           '--control-listen', '0.0.0.0:0', '--ready-file', str(ready),
                                           '--clock-domain', 'independent-server-clock', '--output', 'raw'], cwd=server_dir,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        if server.poll() is not None: raise AssertionError(server.communicate())
                        try: ports = json.loads(ready.read_text()); break
                        except (OSError, json.JSONDecodeError):
                            if time.monotonic() >= deadline: raise TimeoutError('listener')
                            time.sleep(.005)
                    client = subprocess.run([build / 'turtle-client', *common,
                                             '--connect', f"127.0.0.1:{ports['port']}",
                                             '--control-connect', f"127.0.0.1:{ports['control_port']}",
                                             '--clock-domain', 'independent-client-clock', '--output', 'raw'], cwd=client_dir, capture_output=True, text=True, timeout=30)
                    assert client.returncode == 0, client.stderr
                    out, err = server.communicate(timeout=30)
                    assert server.returncode == 0, (out, err)
                finally:
                    if server.poll() is None: server.kill(); server.wait()
                headers = []
                for role, folder in (('client', client_dir), ('server', server_dir)):
                    raw = folder / 'raw' / f'{role}.jsonl'
                    rows = [json.loads(line) for line in raw.read_text().splitlines()]
                    h = rows[0]; headers.append(h)
                    assert h['schema'] == 3 and h['valid'], h['invalid_reason']
                    preparation = h['preparation']
                    assert preparation['stage'] == 'ready'
                    assert all(preparation[key] for key in ('control_connected', 'scenario_agreed',
                                                           'local_prepared', 'peer_prepared'))
                    assert preparation['control']['transport'] == 'tcp/ipv4'
                    assert preparation['local']['data_connection'] == 'not_probed'
                    assert preparation['local']['measurement']['perf_status'] == 'disabled'
                    assert preparation['peer']['role'] != role
                    assert h['pinned_cpu'] == int(cpu)
                    assert h['adapter_connection']['mode'] == 'module'
                    assert h['config']['cpu'] == int(cpu)
                    assert not any(k in h['config'] for k in ('client_cpu', 'server_cpu', 'runner_cpu'))
                    assert h['config']['tls'][('server' if role == 'client' else 'client') + '_key'] == ''
                    assert [c['warmup'] for c in h['connections']] == [True, False, False]
                    assert all(c['scenario_completed'] and c['verification'] == 'passed' for c in h['connections'])
                    assert all(e['run_id'] == h['run_id'] and e['context_id'] == h['context_id'] for e in rows[1:])
                    subprocess.run([build / 'turtle-interpret', raw, raw.with_suffix('.decoded.json')], check=True)
                    decoded = json.loads(raw.with_suffix('.decoded.json').read_text())
                    assert all(c['decryption_complete'] for c in decoded['connections'])
                assert headers[0]['run_id'] == headers[1]['run_id'] and headers[0]['run_id']
                assert headers[0]['preparation']['peer'] == headers[1]['preparation']['local']
                assert headers[1]['preparation']['peer'] == headers[0]['preparation']['local']
                assert headers[0]['clock_domain'] != headers[1]['clock_domain']
                result = case / 'report'
                subprocess.run([build / 'turtle-report', '--pair', client_dir / 'raw/client.jsonl',
                                server_dir / 'raw/server.jsonl', result], check=True, capture_output=True)
                summary = json.loads((result / 'summary.json').read_text())
                assert summary['invalid_samples'] == 0
                assert all(g['dimensions']['peer_mode'] == 'trace' and
                           g['dimensions']['peer_run_controls']['local_boundary_observer'] is False
                           for g in summary['groups'])
                assert all(s['peer_header_status'] == 'verified' for s in summary['samples'])
                assert all(s['cross_endpoint_elapsed_ns'] is None for s in summary['samples'])
                # A completion failure after raw output must remain an invalid sample in replay.
                if scenario == 'handshake':
                    (client_dir / 'raw/client.failure.json').write_text(json.dumps({
                        'run_id': headers[0]['run_id'], 'context_id': headers[0]['context_id'],
                        'valid': False, 'phase': 'cleanup', 'reason': 'completion acknowledgement unavailable'}))
                    subprocess.run([build / 'turtle-report', '--pair', client_dir / 'raw/client.jsonl',
                                    server_dir / 'raw/server.jsonl', case / 'cleanup-report'], check=True, capture_output=True)
                    failed = json.loads((case / 'cleanup-report/summary.json').read_text())
                    assert failed['invalid_samples'] == 2
                    assert all('completion acknowledgement' in s['invalid_reason'] for s in failed['samples'])
        print('PASS: independent processes, private paths, local CPU, actual TLS, explicit pair analysis')


if __name__ == '__main__': main()
