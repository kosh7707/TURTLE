#!/usr/bin/env python3
"""독립 엔드포인트를 새 프로세스로 배치하는 로컬 실험 실행기."""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time
import uuid
from profile_config import flatten_experiment, endpoint_profile


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def physical_cpus():
    cores = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        base = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        try:
            key = ((base / 'physical_package_id').read_text().strip(),
                   (base / 'core_id').read_text().strip())
        except OSError:
            continue
        cores.setdefault(key, cpu)
    return list(cores.values())


def line(sock, deadline):
    data = bytearray()
    while b'\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
            raise TimeoutError('local observer deadline exceeded')
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError('endpoint exited before local observation boundary')
        data.extend(chunk)
        if len(data) > 4096:
            raise RuntimeError('local observation frame exceeds capacity')
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_build = Path(__file__).resolve().parent
    if default_build.name == 'scripts':
        default_build = default_build.parent / 'build'
    parser.add_argument('--build', type=Path, default=default_build)
    parser.add_argument('--client-bin', type=Path)
    parser.add_argument('--server-bin', type=Path)
    parser.add_argument('--client')
    parser.add_argument('--server')
    parser.add_argument('--adapter-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--samples', type=int)
    parser.add_argument('--network-manifest', type=Path)
    parser.add_argument('--runner-cpu', type=int)
    parser.add_argument('--client-cpu', type=int)
    parser.add_argument('--server-cpu', type=int)
    parser.add_argument('--ca-cpu', type=int)
    parser.add_argument('--no-affinity', action='store_true')
    args, common = parser.parse_known_args()
    build = args.build.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    document = json.loads(args.profile.read_text()) if args.profile else None
    profile = flatten_experiment(document) if document else {}
    base = args.profile.resolve().parent if args.profile else Path.cwd()
    # An experiment owns both endpoint profiles. They are resolved separately
    # before spawning; no endpoint sees the other endpoint's paths or CPU.
    for section in ('tls', 'lookup'):
        for key, value in profile.get(section, {}).items():
            if key.endswith(('_file', '_certificate', '_key')) and isinstance(value, str) and value:
                profile[section][key] = str((base / value).resolve())
    if 'pki' in profile:
        profile['pki'] = str((base / profile['pki']).resolve())
    measurement = profile.setdefault('measurement', {})
    args.samples = args.samples if args.samples is not None else int(measurement.get('samples', 1))
    if args.samples < 1: parser.error('samples must be positive')
    timeout = int(measurement.get('timeout_ms', 10000))
    grace = int(measurement.get('flush_grace_ms', 500))
    if '--timeout-ms' in common:
        timeout = int(common[common.index('--timeout-ms') + 1])
    policy = measurement.pop('failure_policy', 'fail-fast')
    if '--batch' not in common and 'batch' in measurement:
        common += ['--batch', str(measurement['batch'])]
    measurement.pop('samples', None)
    lookup = bool(profile.get('lookup', {}).get('enabled', False))
    inherited_affinity = os.sched_getaffinity(0)
    cpus = [args.runner_cpu, args.client_cpu, args.server_cpu] + ([args.ca_cpu] if lookup else [])
    no_affinity = args.no_affinity or not measurement.get('pin_cores', True)
    for i, key in enumerate(('runner_cpu', 'client_cpu', 'server_cpu', 'ca_cpu')[:len(cpus)]):
        cpus[i] = cpus[i] if cpus[i] is not None else measurement.pop(key, None)
    if not no_affinity:
        available = physical_cpus()
        for i, cpu in enumerate(cpus):
            if cpu is None:
                cpus[i] = next((c for c in available if c not in cpus), None)
        keys = []
        for cpu in cpus:
            if cpu not in inherited_affinity: raise RuntimeError('requested local CPU unavailable')
            topology = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
            keys.append(((topology / 'physical_package_id').read_text(), (topology / 'core_id').read_text()))
        if None in cpus or len(set(keys)) != len(cpus):
            raise RuntimeError(f'{len(cpus)} local physical CPUs unavailable; use --no-affinity')
        os.sched_setaffinity(0, {cpus[0]})
    manifest = json.loads(args.network_manifest.read_text()) if args.network_manifest else None
    network = socket.socket(fileno=os.dup(manifest['phase_control_fd'])) if manifest else None
    network_ids = []

    def phase(sample, name, edge, deadline):
        if not network:
            return
        request = dict(type='phase', schema=1, attempt=sample, phase=name, edge=edge)
        network.sendall((json.dumps(request) + '\n').encode())
        reply = line(network, deadline)
        expected = f'{sample}:{name}:{edge}'
        if reply.get('observation_id') != expected:
            raise RuntimeError('network observation acknowledgement differs')
        network_ids.append(expected)

    counts = dict(requested=args.samples, started=0, success=0, timeout=0, error=0,
                  incomplete=0, not_attempted=0, missing_artifacts=0, missing_artifact_rows=[])
    ledger = (output / 'attempts.jsonl').open('x')

    def row(kind, **fields):
        value = dict(type='turtle-attempt-ledger', schema=1, record_kind=kind, **fields)
        ledger.write(json.dumps(value) + '\n'); ledger.flush(); os.fsync(ledger.fileno())

    row('run_config', requested_count=args.samples, failure_policy=policy)
    for sample in range(1, args.samples + 1):
        directory = output / f'sample-{sample:06d}'
        directory.mkdir()
        run_id = str(uuid.uuid4())
        deadline = time.monotonic() + timeout / 1000
        children, controls, files = [], [], []
        network_ids.clear()
        entry = dict(attempt_id=sample, requested_count=args.samples, started=True,
                     run_id=run_id, final_status='incomplete', failure_phase='startup', reason='',
                     secondary_reasons=[], measurement_deadline_monotonic_ns=int(deadline * 1e9),
                     flush_grace_ms=grace, participants=['tls-server', 'tls-client'] + (['mock-ca'] if lookup else []),
                     artifact_status=['missing', 'missing'], artifacts={}, connections=[],
                     network_observation_ids=[])
        row('attempt_started', **entry); counts['started'] += 1
        try:
            phase(sample, 'setup', 'begin', deadline)
            server_address = manifest['addresses']['server'] if manifest else '127.0.0.1'
            source_address = manifest['addresses']['client_tls'] if manifest else '127.0.0.1'
            ports = {'port': 44330 if manifest else 0, 'control_port': 44331 if manifest else 0}
            if lookup:
                lookup_address = manifest['addresses']['ca'] if manifest else '127.0.0.1'
                lookup_source = manifest['addresses']['client_ca'] if manifest else '127.0.0.1'
                service_profile = directory / 'lookup.profile.json'
                write_json(service_profile, endpoint_profile(profile))
                service_ready = directory / 'lookup.ready.json'
                command = [str(build / 'turtle-lookup'), '--profile', str(service_profile),
                           '--output', str(directory), '--run-id', run_id, '--sample', str(sample),
                           '--listen', f'{lookup_address}:{44332 if manifest else 0}',
                           '--control-listen', f'{lookup_address}:{44333 if manifest else 0}',
                           '--ready-file', str(service_ready)] + common
                command += ['--no-affinity'] if no_affinity else ['--cpu', str(cpus[3])]
                inherited = []
                if manifest:
                    ns = manifest['namespace_fds']['ca']
                    command = ['nsenter', f'--net=/proc/self/fd/{ns}', '--'] + command
                    inherited.append(ns)
                log = (directory / 'lookup.log').open('w'); files.append(log)
                service = subprocess.Popen(command, pass_fds=inherited, stdout=log, stderr=subprocess.STDOUT,
                                           preexec_fn=lambda: os.sched_setaffinity(0, inherited_affinity))
                children.append(service)
                while True:
                    if service.poll() is not None: raise RuntimeError('lookup preparation failed; see lookup.log')
                    if time.monotonic() >= deadline: raise TimeoutError('lookup listener deadline exceeded')
                    try:
                        lookup_ports = json.loads(service_ready.read_text()); break
                    except (OSError, json.JSONDecodeError): time.sleep(.005)
                profile['lookup'].update(address=lookup_address, source_address=lookup_source,
                                         **lookup_ports)
            ready = directory / 'server.ready.json'
            for role in ('server', 'client'):
                own_profile = json.loads(json.dumps(profile))
                for section, values in (document or {}).get('endpoints', {}).get(role, {}).items():
                    if isinstance(values, dict): own_profile.setdefault(section, {}).update(values)
                    else: own_profile[section] = values
                if 'pki' in own_profile:
                    own_profile['pki'] = str((base / own_profile['pki']).resolve())
                for section in ('tls', 'lookup'):
                    for key, value in own_profile.get(section, {}).items():
                        if key.endswith(('_file', '_certificate', '_key')) and isinstance(value, str) and value:
                            own_profile[section][key] = str((base / value).resolve())
                tls = own_profile.setdefault('tls', {})
                for opposite in (('client_certificate', 'client_key') if role == 'server' else ('server_certificate', 'server_key')):
                    tls.pop(opposite, None)
                endpoint_profile_path = directory / f'{role}.profile.json'
                write_json(endpoint_profile_path, endpoint_profile(own_profile))
                executable = (args.server_bin if role == 'server' else args.client_bin) or build / f'turtle-{role}'
                command = [str(executable.resolve()), '--profile', str(endpoint_profile_path), '--output', str(directory),
                           '--run-id', run_id, '--sample', str(sample),
                           '--listen' if role == 'server' else '--connect', f"{server_address}:{ports['port']}",
                           '--control-listen' if role == 'server' else '--control-connect',
                           f"{server_address}:{ports['control_port']}"] + common
                if manifest:
                    command += ['--network-evidence', str(args.network_manifest.resolve())]
                implementation = args.server if role == 'server' else args.client
                if implementation:
                    module = (args.adapter_dir or build / 'adapters') / f'{implementation}.so'
                    command += ['--module', str(module.resolve())]
                if no_affinity:
                    command += ['--no-affinity']
                else:
                    command += ['--cpu', str(cpus[2 if role == 'server' else 1])]
                inherited = []
                if manifest:
                    parent, child = socket.socketpair()
                    command += ['--phase-fd', str(child.fileno())]
                    inherited.append(child.fileno())
                    ns = manifest['namespace_fds'][role]
                    command = ['nsenter', f'--net=/proc/self/fd/{ns}', '--'] + command
                    inherited.append(ns)
                if role == 'server':
                    command += ['--ready-file', str(ready)]
                else:
                    command += ['--source-address', source_address]
                log = (directory / f'{role}.log').open('w'); files.append(log)
                process = subprocess.Popen(command, pass_fds=inherited, stdout=log, stderr=subprocess.STDOUT,
                                           preexec_fn=lambda: os.sched_setaffinity(0, inherited_affinity))
                children.append(process)
                if manifest:
                    controls.append(parent)
                    child.close()
                if role == 'server':
                    while not ready.exists():
                        if process.poll() is not None:
                            raise RuntimeError('server preparation failed; see server.log')
                        if time.monotonic() >= deadline:
                            raise TimeoutError('server listener preparation deadline exceeded')
                        time.sleep(.005)
                    # A ready file is complete only after its producer closes it.
                    while True:
                        try:
                            ports = json.loads(ready.read_text()); break
                        except json.JSONDecodeError:
                            if time.monotonic() >= deadline: raise
                            time.sleep(.001)
            entry['failure_phase'] = 'tcp_ready' if controls else 'scenario'
            for name in (('setup', 'scenario') if controls else ()):
                requests = [line(c, deadline) for c in controls]
                if any(r.get('phase') != name or r.get('edge') != 'end' or r.get('attempt') != sample for r in requests):
                    raise RuntimeError('endpoint observation boundary differs')
                phase(sample, name, 'end', deadline)
                phase(sample, 'scenario' if name == 'setup' else 'cleanup', 'begin', deadline)
                entry['failure_phase'] = 'scenario' if name == 'setup' else 'flush'
                for c, request in zip(controls, requests):
                    reply = dict(request, type='ack', observation_id=f'{sample}:{name}:end')
                    c.sendall((json.dumps(reply) + '\n').encode())
            for process in children:
                process.wait(timeout=max(.001, deadline - time.monotonic()) + grace / 1000)
            if any(p.returncode != 0 for p in children):
                raise RuntimeError('endpoint returned failure; raw artifacts retained')
            entry.update(final_status='success', failure_phase='none')
        except (Exception, KeyboardInterrupt) as error:
            entry.update(final_status='timeout' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else 'error', reason=str(error))
        finally:
            cleanup_deadline = time.monotonic() + grace / 1000
            for c in controls: c.close()
            for process in children:
                try: process.wait(timeout=max(.001, cleanup_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try: process.wait(timeout=.25)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()
            for f in files: f.close()
            if network:
                for name, edge in (('setup', 'end'), ('scenario', 'begin'), ('scenario', 'end'), ('cleanup', 'begin'), ('cleanup', 'end')):
                    if f'{sample}:{name}:{edge}' not in network_ids:
                        try: phase(sample, name, edge, cleanup_deadline)
                        except Exception as error: entry['secondary_reasons'].append(str(error)); break
            connection_indices = set()
            for role in (('server', 'client', 'lookup', 'ca') if lookup else ('server', 'client')):
                raw = directory / f'{role}.jsonl'
                status = 'missing'
                try:
                    header = json.loads(raw.open().readline())
                    complete = header.get('valid', True)
                    if role in ('lookup', 'ca'):
                        footer = json.loads(raw.read_text().splitlines()[-1])
                        complete = footer.get('artifact_status') == 'complete'
                    status = 'complete' if complete else 'partial'
                    connection_indices.update(c['index'] for c in header.get('connections', []))
                    if not complete and entry['final_status'] == 'success':
                        entry.update(final_status='incomplete', reason=header['invalid_reason'])
                except (OSError, ValueError, KeyError):
                    counts['missing_artifacts'] += 1
                    counts['missing_artifact_rows'].append(dict(attempt_id=sample, artifact_name=role + '.jsonl'))
                entry['artifacts'][role + '.jsonl'] = status
            entry['connections'] = sorted(connection_indices)
            entry['artifact_status'] = list(entry['artifacts'].values())
            entry['network_observation_ids'] = list(network_ids)
            row('attempt_final', **entry)
            counts[entry['final_status']] += 1
            write_json(directory / 'execution.json', entry)
        if entry['final_status'] != 'success':
            print(f"attempt {sample}: {entry['reason']} (artifacts: {directory})", file=sys.stderr)
            if policy == 'fail-fast': break
    counts['not_attempted'] = args.samples - counts['started']
    row('run_summary', **counts)
    ledger.close()
    if network: network.close()
    return 0 if counts['success'] == args.samples else 1


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'local execution interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except Exception as error:
        print(f'turtle-local: {error}', file=sys.stderr)
        sys.exit(1)
