#!/usr/bin/env python3
"""소유한 이름공간에서 속도·초기 윈도 설정과 실제 TLS·커널 송신 관측을 확인합니다."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from profiles import experiment_profile, flatten_experiment
from pure_tls_netem import write_profile, check


runner, turtle, report, interpret, adapters, pki = (Path(p).resolve() for p in sys.argv[1:7])
with tempfile.TemporaryDirectory(prefix='turtle-shaping-') as temporary:
    root = Path(temporary)
    profile = root / 'profile.json'
    write_profile(profile, pki)
    value = flatten_experiment(json.loads(profile.read_text()))
    value['measurement'].update(mode='trace', tx_timestamps=True)
    value['tls'].update(client_application_bytes=65536, server_application_bytes=65536)
    profile.write_text(json.dumps(experiment_profile(**value)))
    network = root / 'network.json'
    network.write_text(json.dumps({
        'type': 'turtle-netem-profile', 'schema': 3, 'qdisc': 'netem', 'mtu': 1500,
        'offload': {'tso': False, 'gso': False, 'gro': False}, 'trace': True, 'loss_seed': None,
        'initial_cwnd': {'client': 4, 'server': 4},
        'kernel_events': False, 'targeted_drop': {'tls_c2s': None, 'tls_s2c': None},
        'paths': {path: {'delay_ms': 5, 'loss_percent': 0, 'limit_packets': 10000, 'rate_bps': 1000000}
                  for path in ('tls_c2s', 'tls_s2c')}}))
    output = root / 'run'
    result = subprocess.run([sys.executable, str(runner), 'run', '--build', str(turtle.parent),
                             '--profile', str(profile), '--net-profile', str(network),
                             '--samples', '2', '--output', str(output)], capture_output=True, text=True)
    check(result.returncode == 0, result.stdout + result.stderr)
    provenance = json.loads((output / 'network-provenance.json').read_text())
    actual = provenance['condition_identity']['actual']
    check(actual['initial_cwnd'] == {'client': 4, 'server': 4}, 'cwnd route condition differs')
    check(all(p['rate_bps'] == 1000000 for p in actual['paths'].values()), 'rate readback differs')
    check(provenance['host_network_identity']['unchanged'], 'host network identity changed')
    for raw in sorted(output.glob('sample-*/*.jsonl')):
        if raw.stem not in ('client', 'server'):
            continue
        header = json.loads(raw.read_text().splitlines()[0])
        check(header['valid'] and header['connections'][0]['application_verified'], 'TLS exchange failed')
        check(header['connections'][0]['tcp_start']['snd_cwnd'] == 4, 'TCP_INFO initial cwnd differs')
        subprocess.run([str(interpret), str(raw), str(raw.with_suffix('.decoded.json'))], check=True,
                       capture_output=True)
        correlate = runner.parent / 'tcp-correlate.py'
        mapped = raw.with_suffix('.tcp.json')
        subprocess.run([sys.executable, str(correlate), str(output / 'packets.jsonl'), str(raw), str(mapped)],
                       check=True, capture_output=True)
        tcp = json.loads(mapped.read_text())
        check(tcp['status'] == 'available', 'packet byte correspondence missing')
        check(tcp['connections'][0]['stream_bytes_verified'] > 65536, 'large application payload absent')
        finished = next(m for m in tcp['connections'][0]['messages'] if m['name'] == 'Finished')
        check(finished['kernel_cumulative_ack_status'] == 'observed', 'Finished kernel ACK missing')
    subprocess.run([str(report), str(output), str(output / 'report')], check=True, capture_output=True)
    print('Actual 1 Mbit/s, cwnd=4 TLS runs passed; TCP_INFO, packet bytes and kernel ACK verified')
