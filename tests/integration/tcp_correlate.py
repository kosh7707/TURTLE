#!/usr/bin/env python3
"""관측 위치 중복, 부분 재전송, TCP 순번 순환을 확인하는 합성 분석 시험입니다."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))

spec = importlib.util.spec_from_file_location('correlation', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix='turtle-tcp-map-') as tmp:
    root = Path(tmp)
    raw = root / 'client.jsonl'
    raw.write_text(json.dumps({'type': 'sample', 'schema': 3, 'measurement_contract_revision': 3,
                               'role': 'client', 'valid': True, 'run_id': 'tcp-fixture', 'context_id': 'context', 'sample': 1,
                               'connections': [{'index': 0}]}) + '\n' + json.dumps({
        'connection': 0, 'kind': 'IO_SEND_RETURN', 'transferred': 6,
        'stream_begin': 0, 'stream_end': 6, 'sequence': 1}) + '\n')
    (root / 'client.conn-0.sent.bin').write_bytes(b'abcdef')
    raw.with_suffix('.decoded.json').write_text(json.dumps({'schema': 1, 'run_id': 'tcp-fixture', 'context_id': 'context', 'sample': 1, 'role': 'client', 'connections': [{
        'decryption_complete': True, 'client_sent': {'messages': [
            {'name': 'FixtureMessage', 'record_stream_ranges': [{'begin': 0, 'end': 6}]}]}}]}))
    flow = {'source': '10.0.0.1', 'destination': '10.0.0.2', 'source_port': 1234,
            'destination_port': 443, 'protocol': 'tcp'}
    reverse = {**flow, 'source': flow['destination'], 'destination': flow['source'],
               'source_port': 443, 'destination_port': 1234}
    rows = []
    with (root / 'packets.pcap').open('wb') as pcap:
        pcap.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        for i, (sequence, ack, flags, payload, direction) in enumerate([
                (0xfffffffc, 0, 2, b'', 'ingress'),
                (0xfffffffd, 0, 16, b'abcd', 'ingress'),
                (0xffffffff, 0, 16, b'cdef', 'ingress'),
                (100, 3, 16, b'', 'egress')]):
            frame = bytes(54) + payload
            offset = pcap.tell()
            pcap.write(struct.pack('<IIII', 1, i, len(frame), len(frame)))
            pcap.write(frame)
            rows.append({'record_kind': 'packet', 'interface': 'rctls', 'direction': direction,
                         'logical_path': 'tls_c2s' if direction == 'ingress' else 'tls_s2c',
                         'flow': flow if direction == 'ingress' else reverse,
                         'tcp': {'sequence': sequence, 'acknowledgement': ack, 'flags': flags,
                                 'payload_length': len(payload), 'header_bytes': 20},
                         'ip': {'header_bytes': 20}, 'payload_offset': 54,
                         'pcap_offset': offset, 'packet_index': i, 'monotonic_ns': i + 10,
                         'frame_length': len(frame)})
    # A second observation point must not be counted as a retransmission.
    rows.append({**rows[1], 'interface': 'rstls', 'direction': 'egress'})
    rows.append({'record_kind': 'footer', 'capture_socket_statistics': {'rctls': {'drops': 0}}})
    packets = root / 'packets.jsonl'
    packets.write_text(''.join(json.dumps(r) + '\n' for r in rows))
    result = module.correlate(packets, raw)
    assert result['status'] == 'available' and result['capture_complete']
    conn = result['connections'][0]
    assert conn['stream_bytes_verified'] == 6
    assert conn['observed_retransmitted_payload_bytes'] == 2
    assert conn['payload_bytes_including_observed_retransmissions'] == 8
    assert conn['messages'][0]['packet_indices'] == [1, 2]
    assert conn['messages'][0]['cumulative_ack_packet'] == 3
    assert conn['messages'][0]['socket_submission_events'] == [1]
    assert result['kernel_observation']['status'] == 'unsupported'
    assert conn['kernel_retransmission_count'] is None
    decoded_path = raw.with_suffix('.decoded.json')
    decoded = json.loads(decoded_path.read_text())
    decoded['run_id'] = 'different-execution'
    decoded_path.write_text(json.dumps(decoded))
    assert module.correlate(packets, raw)['reason'] == 'decoded_tls_identity_mismatch'
    decoded['run_id'] = 'tcp-fixture'
    decoded_path.write_text(json.dumps(decoded))
    kernel = {'status': 'complete' , 'buffer_lost': 0, 'failures': {'ring_lost': 0},
              'cleanup_errors': [], 'events': [
                  {'flow': flow, 'kind': 'targeted_drop', 'initial_data_sequence': 0xfffffffd,
                   'stream_begin': 0, 'stream_end': 4},
                  {'flow': flow, 'kind': 'tcp_retransmit_skb', 'initial_data_sequence': 0xfffffffd,
                   'stream_begin': 2, 'stream_end': 6}]}
    (root / 'kernel-events.json').write_text(json.dumps(kernel))
    mapped = module.correlate(packets, raw)
    assert mapped['status'] == 'available'
    conn = mapped['connections'][0]
    assert conn['targeted_drop_count'] == 1 and conn['kernel_retransmission_count'] == 1
    assert conn['qdisc_drop_count'] == 0
    assert conn['messages'][0]['kernel_event_indices'] == [0, 1]
    kernel['buffer_lost'] = 1
    (root / 'kernel-events.json').write_text(json.dumps(kernel))
    missing = module.correlate(packets, raw)
    assert missing['status'] == 'missing'
    assert missing['connections'][0]['kernel_retransmission_count'] is None
    print('PASS synthetic TCP byte overlap, wrap, observation point and cumulative ACK')
