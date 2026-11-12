#!/usr/bin/env python3
"""보존 패킷과 TLS 스트림의 바이트 일치로 메시지·레코드·TCP·누적 ACK를 연결합니다."""
import argparse
import json
from pathlib import Path
from raw_record import read_tls_records
import struct


def flow_key(row):
    flow = row['flow']
    return flow['source'], flow['source_port'], flow['destination'], flow['destination_port']


def overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def kernel_observations(packets_path):
    path = packets_path.parent / 'kernel-events.json'
    if not path.exists():
        provenance = packets_path.parent / 'network-provenance.json'
        requested = provenance.exists() and json.loads(provenance.read_text()).get(
            'condition_identity', {}).get('requested', {}).get('kernel_events', False)
        return {'status': 'missing' if requested else 'unsupported',
                'reason': 'kernel_event_artifact_absent', 'events': []}
    raw = json.loads(path.read_text())
    complete = (raw.get('status') == 'complete' and raw.get('buffer_lost') == 0 and
                raw.get('failures') and all(value == 0 for value in raw['failures'].values()) and
                raw.get('cleanup_errors') == [])
    return {'status': 'available' if complete else 'missing', 'source': str(path),
            'reason': raw.get('missing_reason'), 'clock': raw.get('clock'),
            'clock_pairs': raw.get('clock_pairs'), 'events': raw.get('events', [])}


def correlate(packets_path, raw_path):
    packet_rows = [json.loads(line) for line in packets_path.read_text().splitlines()]
    records = read_tls_records(raw_path)
    header, events = records[0], records[1:]
    capture = packets_path.with_suffix('.pcap')
    kernel = kernel_observations(packets_path)
    result = {'type': 'turtle-tcp-correlation', 'schema': 2, 'role': header['role'],
              'run_id': header['run_id'], 'context_id': header['context_id'],
              'packet_source': str(packets_path), 'tls_source': str(raw_path),
              'observation_point': 'sender-facing-router-interface-ingress; reverse ACK egress',
              'packet_unit': 'observed-software-frame-not-physical-NIC-frame',
              'timestamp_location': 'userspace_after_recvfrom',
              'connections': [], 'status': 'available',
              'kernel_observation': {key: value for key, value in kernel.items() if key != 'events'}}
    if not header.get('valid', False):
        return {**result, 'status': 'missing', 'reason': 'tls_execution_invalid'}
    if not capture.exists():
        return {**result, 'status': 'unsupported', 'reason': 'raw_packet_capture_absent'}
    decoded_path = raw_path.with_suffix('.decoded.json')
    decoded = json.loads(decoded_path.read_text()) if decoded_path.exists() else None
    if decoded is None:
        return {**result, 'status': 'missing', 'reason': 'decoded_tls_sidecar_absent'}
    if (decoded.get('schema') != 1 or
            any(decoded.get(field) != header[field] for field in ('run_id', 'context_id', 'sample', 'role'))):
        return {**result, 'status': 'missing', 'reason': 'decoded_tls_identity_mismatch'}
    if any(not c.get('decryption_complete', False) for c in decoded['connections']):
        return {**result, 'status': 'missing', 'reason': 'tls_decryption_incomplete'}
    path = 'tls_c2s' if header['role'] == 'client' else 'tls_s2c'
    interface = 'rctls' if header['role'] == 'client' else 'rstls'
    packets = [r for r in packet_rows if r.get('record_kind') == 'packet' and
               r['interface'] == interface]
    groups = {}
    for row in packets:
        if row['direction'] == 'ingress' and row['logical_path'] == path:
            groups.setdefault(flow_key(row), []).append(row)
    with capture.open('rb') as source:
        if source.read(24) != struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1):
            return {**result, 'status': 'unsupported', 'reason': 'capture_format_not_supported'}
        for connection in header['connections']:
            index = connection['index']
            sent = (raw_path.parent / f'{raw_path.stem}.conn-{index}.sent.bin').read_bytes()
            matches = []
            for key, rows in groups.items():
                syn = next((r for r in rows if r['tcp']['flags'] & 2), None)
                if syn is None:
                    continue
                base = (syn['tcp']['sequence'] + 1) & 0xffffffff
                image = bytearray(len(sent))
                covered = bytearray(len(sent))
                transmissions = []
                conflict = False
                for row in rows:
                    count = row['tcp']['payload_length']
                    if count == 0:
                        continue
                    begin = (row['tcp']['sequence'] - base) & 0xffffffff
                    end = begin + count
                    if begin >= len(sent):
                        continue
                    source.seek(row['pcap_offset'])
                    _, _, captured, original = struct.unpack('<IIII', source.read(16))
                    frame = source.read(captured)
                    if captured != original or len(frame) != captured:
                        conflict = True
                        break
                    payload = frame[row['payload_offset']:row['payload_offset'] + count]
                    if len(payload) != count:
                        conflict = True
                        break
                    clipped = min(end, len(sent))
                    repeated = sum(covered[begin:clipped])
                    for position in range(begin, clipped):
                        byte = payload[position - begin]
                        if covered[position] and image[position] != byte:
                            conflict = True
                        image[position] = byte
                        covered[position] = 1
                    transmissions.append({'packet_index': row['packet_index'],
                        'stream_begin': begin, 'stream_end': end,
                        'monotonic_ns': row['monotonic_ns'],
                        'overlap_with_previously_observed_bytes': repeated,
                        'ip_header_bytes': row['ip']['header_bytes'],
                        'tcp_header_bytes': row['tcp']['header_bytes'],
                        'payload_bytes': count, 'observed_frame_bytes': row['frame_length']})
                if not conflict and sent and all(covered) and bytes(image) == sent:
                    matches.append((key, base, transmissions))
            if len(matches) != 1:
                result['connections'].append({'connection': index, 'status': 'missing',
                    'reason': 'unique_complete_byte_matching_flow_not_found',
                    'matching_flows': len(matches)})
                result['status'] = 'missing'
                continue
            key, base, transmissions = matches[0]
            kernel_events = [{**event, 'kernel_event_index': i} for i, event in enumerate(kernel['events'])
                             if flow_key(event) == key and event.get('initial_data_sequence') == base]
            reverse = key[2], key[3], key[0], key[1]
            acks = [r for r in packets if r['direction'] == 'egress' and
                    flow_key(r) == reverse and r['tcp']['flags'] & 16]
            connection_events = [e for e in events if e['connection'] == index]
            socket_kernel = [e for e in connection_events if
                             e['kind'] in ('KERNEL_TX_SCHED', 'KERNEL_TX_SND', 'KERNEL_TX_ACK')]
            direction = decoded['connections'][index][header['role'] + '_sent']
            messages = []
            for message in direction['messages']:
                ranges = [(r['begin'], r['end']) for r in message.get('record_stream_ranges', [])]
                related = [t for t in transmissions if any(overlap(
                    (t['stream_begin'], t['stream_end']), span) for span in ranges)]
                boundary = max((span[1] for span in ranges), default=0)
                first = min((t['monotonic_ns'] for t in related), default=0)
                ack = next((r for r in acks if r['monotonic_ns'] >= first and
                            boundary <= ((r['tcp']['acknowledgement'] - base) & 0xffffffff) < 0x80000000), None)
                submissions = [e['sequence'] for e in connection_events if
                               e['kind'] == 'IO_SEND_RETURN' and e['transferred'] and
                               any(overlap((e['stream_begin'], e['stream_end']), span) for span in ranges)]
                kernel_ack = min((e for e in socket_kernel if e['kind'] == 'KERNEL_TX_ACK' and
                                  e['stream_end'] >= boundary and e['raw_timestamp_ns'] is not None),
                                 key=lambda e: e['raw_timestamp_ns'], default=None)
                messages.append({'name': message['name'], 'record_stream_ranges': message.get('record_stream_ranges', []),
                                 'packet_indices': [t['packet_index'] for t in related],
                                 'socket_submission_events': submissions,
                                 'kernel_event_indices': [e['kernel_event_index'] for e in kernel_events
                                     if e.get('stream_begin') is not None and any(overlap(
                                         (e['stream_begin'], e['stream_end']), span) for span in ranges)],
                                 'kernel_request_events': [e['sequence'] for e in socket_kernel
                                     if any(begin < e['stream_end'] <= end for begin, end in ranges)],
                                 'kernel_cumulative_ack_event': kernel_ack['sequence'] if kernel_ack else None,
                                 'kernel_cumulative_ack_realtime_ns': kernel_ack['raw_timestamp_ns'] if kernel_ack else None,
                                 'kernel_cumulative_ack_status': 'observed' if kernel_ack else
                                     'missing' if header.get('config', {}).get('tx_timestamps', False) else 'unsupported',
                                 'first_observed_transmission_ns': first or None,
                                 'cumulative_ack_packet': ack['packet_index'] if ack else None,
                                 'cumulative_ack_status': 'observed' if ack else 'missing',
                                 'cumulative_ack_monotonic_ns': ack['monotonic_ns'] if ack else None})
            result['connections'].append({'connection': index, 'status': 'available',
                'flow': dict(zip(('source', 'source_port', 'destination', 'destination_port'), key)),
                'initial_data_sequence': base, 'stream_bytes_verified': len(sent),
                'transmissions': transmissions, 'messages': messages,
                'kernel_events': kernel_events,
                'kernel_retransmission_count': sum(e['kind'] == 'tcp_retransmit_skb' for e in kernel_events)
                    if kernel['status'] == 'available' else None,
                'targeted_drop_count': sum(e['kind'] == 'targeted_drop' for e in kernel_events)
                    if kernel['status'] == 'available' else None,
                'qdisc_drop_count': sum(e['kind'] == 'qdisc_drop' for e in kernel_events)
                    if kernel['status'] == 'available' else None,
                'observed_retransmitted_payload_bytes': sum(t['overlap_with_previously_observed_bytes'] for t in transmissions),
                'ip_header_bytes': sum(t['ip_header_bytes'] for t in transmissions),
                'tcp_header_bytes': sum(t['tcp_header_bytes'] for t in transmissions),
                'payload_bytes_including_observed_retransmissions': sum(t['payload_bytes'] for t in transmissions)})
    footer = next((r for r in reversed(packet_rows) if r.get('record_kind') == 'footer'), None)
    stats = footer.get('capture_socket_statistics') if footer else None
    result['capture_socket_statistics'] = stats
    result['capture_complete'] = bool(stats) and all(v.get('drops') == 0 for v in stats.values())
    if not result['capture_complete']:
        result['status'] = 'missing'
        result['reason'] = 'capture_completion_or_no_drop_evidence_missing'
    if result['status'] == 'available' and kernel['status'] == 'missing':
        result.update(status='missing', reason='requested_kernel_observation_incomplete')
    result['limitations'] = ['재전송량은 같은 관측 위치에서 겹친 TCP 바이트 수입니다. 커널 재전송 사건은 아닙니다.',
                            '누적 ACK는 이 라우터 위치에서 본 시각이며 송신 소켓의 ACK 시각과 다릅니다.',
                            '메시지는 레코드 외곽 범위를 공유할 수 있습니다. 패킷 비용을 메시지별로 나누지 않습니다.',
                            'IP/TCP 헤더 합계는 이 방향의 TLS 데이터 패킷 대상입니다. ACK만 있는 패킷은 원본 캡처에 보존됩니다.']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packets', type=Path)
    parser.add_argument('raw', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = correlate(args.packets, args.raw)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(result['status'])


if __name__ == '__main__':
    main()
