#!/usr/bin/env python3
"""독립 프로세스 하나씩으로 새 실행 계약의 정상 TLS 표본을 만듭니다."""
import argparse
import contextlib
import json
import hashlib
import os
import signal
import platform
import shutil
import pathlib
import socket
import subprocess
import time
import uuid


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def endpoint_ports():
    # Keep both reservations open until selection is complete: two separate
    # bind(0)/close calls may legitimately return the same ephemeral port.
    with contextlib.ExitStack() as reservations:
        numbers = []
        for _ in range(2):
            listener = reservations.enter_context(socket.socket())
            listener.bind(('127.0.0.1', 0))
            numbers.append(listener.getsockname()[1])
        return numbers


def run(build, pki, output, client='openssl', server='openssl', prefixes=None, role_options=None, **options):
    output = pathlib.Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    tls_port, control_port = endpoint_ports()
    spec = dict(contract='turtle-message-run/1', run_id=str(uuid.uuid4()),
                pki=str(pathlib.Path(pki).resolve()), port=tls_port, control_port=control_port)
    spec.update(options)
    provenance=dict(contract="turtle-message-launch/1",run_id=spec["run_id"],platform=platform.platform(),binaries={},processes=[],success=False)
    prefixes=prefixes or {}
    role_options=role_options or {}
    build=pathlib.Path(build).resolve()
    if (build/"build-manifest.json").exists():
        shutil.copyfile(build/"build-manifest.json",output/"build-manifest.json")
    processes = []
    handles = []
    try:
        for role, backend in [('server', server), ('client', client)]:
            config = output / (role + '.json')
            config.write_text(json.dumps(dict(spec, **dict(role_options.get(role, {}), output=str(output / role))), indent=2))
            log = (output / (role + '.log')).open('w')
            handles.append(log)
            binary = pathlib.Path(build).resolve() / f'turtle-{backend}-{role}'
            provenance['binaries'][role]=dict(path=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
            argv=list(prefixes.get(role, []))+[str(binary), str(config)]
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,start_new_session=True)
            provenance['processes'].append(dict(role=role,argv=argv,pid=process.pid))
            processes.append(process)
            if role == 'server':
                deadline = time.monotonic() + 15
                while not (output / 'server/ready').exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('server startup failed: ' + (output / 'server.log').read_text())
                    time.sleep(.01)
        wait_seconds=30+spec.get("timeout_ms",30000)/1000*(spec.get("connections",1)+spec.get("warmups",0))
        codes = [p.wait(timeout=wait_seconds) for p in processes]
        if any(codes):
            raise RuntimeError('\n'.join((output / (r + '.log')).read_text() for r in ['client', 'server']))
        provenance["success"]=True
        return output
    finally:
        for p in processes:
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            if p.poll() is None:
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    p.wait()
        for item,p in zip(provenance["processes"],processes): item["returncode"]=p.returncode
        (output/"launch.json").write_text(json.dumps(provenance,indent=2)+"\n")
        for h in handles:
            h.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', default='build-message')
    parser.add_argument('--pki', default='pki/default')
    parser.add_argument('--output', required=True)
    parser.add_argument('--client', default='openssl')
    parser.add_argument('--server', default='openssl')
    parser.add_argument('--group', default='P-256')
    parser.add_argument('--allocations', action='store_true')
    parser.add_argument('--perf-counters', action='store_true')
    parser.add_argument('--scenario', default='client-request')
    parser.add_argument('--depth', default='black-box')
    parser.add_argument('--mutual-auth', action='store_true')
    parser.add_argument('--records', default='preserve')
    parser.add_argument('--send', default='flight')
    parser.add_argument('--record-size', type=int, default=16384)
    parser.add_argument('--io-chunk', type=int, default=0)
    parser.add_argument('--connections', type=int, default=1)
    parser.add_argument('--stream', action='store_true')
    parser.add_argument('--client-bytes', type=int, default=32)
    parser.add_argument('--server-bytes', type=int, default=32)
    args = vars(parser.parse_args())
    run(**args)


if __name__ == '__main__':
    main()
