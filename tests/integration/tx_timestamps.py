#!/usr/bin/env python3
"""실제 TLS 소켓의 커널 송신·누적 ACK 시각과 스트림 마지막 바이트 ID를 대조합니다."""
import argparse
import json
from pathlib import Path
import tempfile

from prototype import check, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('turtle', 'report', 'interpret', 'adapters', 'pki'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix='turtle-tx-') if args.output is None else None
    root = args.output or Path(temporary.name)
    root.mkdir(parents=True, exist_ok=True)
    count = 0
    for library in ('openssl', 'wolfssl', 'mbedtls'):
        if not (args.adapters / (library + '.so')).exists():
            continue
        for scenario in ('handshake', 'server-ping', 'finished-ping', 'client-request'):
            destination = root / (library + '-' + scenario)
            verify(args.turtle, args.report, args.interpret, args.adapters, args.pki,
                   destination, library, library, scenario, 'native', True,
                   connections=2, tx_timestamps=True)
            summary = json.loads((destination / 'report/summary.json').read_text())
            for sample in summary['samples']:
                for conn in sample['connections']:
                    tx = conn['prototype']['kernel_transmit']
                    if tx['status'] == 'unsupported':
                        print('kernel SO_TIMESTAMPING unsupported:', tx)
                        return 77
                    check(tx['status'] == 'available', f'TX observation missing: {tx}')
                    check(tx['last_submission_acknowledged'], 'final TLS byte ACK was not observed')
                    check(tx['drain_system_error'] == 0, 'error queue ancillary data lost')
                    for event in tx['events']:
                        check(event['request_last_byte_end'] == event['timestamp_id'] + 1,
                              'TCP timestamp ID is not zero-based stream offset')
                        check(event['socket_submit_sequence'] is not None, 'submission not matched')
                        check(0 < event['request_last_byte_end'] <= tx['submitted_bytes'],
                              'kernel timestamp ID exceeds TLS stream')
                        check(event['raw_realtime_ns'] > event['collection_monotonic_ns'],
                              'raw real clock was replaced with collection time')
            count += 1
    print(f'{count} actual TLS runs with two connections: kernel SCHED/SND/ACK mapped to stream bytes')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
