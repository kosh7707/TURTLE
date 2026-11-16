#!/usr/bin/env python3
"""같은 실행의 TLS 스트림·레코드·메시지를 라우터 관측 패킷의 바이트에 연결합니다."""
import collections,json,pathlib
from report import endpoint,overlap


def analyze(root):
    root=pathlib.Path(root)
    rows=[json.loads(line) for line in (root/'packets.jsonl').read_text().splitlines()]
    if any(r.get('contract')!='turtle-message-packets/1' for r in rows):raise ValueError('unsupported packet contract')
    endpoints={r:endpoint(root/'run'/r) for r in ('client','server')}
    ids={};bases={};seen=collections.defaultdict(list);packets=[];mismatches=[]
    captured=(root/'packets.pcap').read_bytes()
    for p in rows:
        if p['record_kind']!='packet':continue
        f=p['flow'];t=p['tcp'];direction=p['logical_path']
        if direction not in ('tls_c2s','tls_s2c'):continue
        key=tuple(f[k] for k in ('source','source_port','destination','destination_port'))
        client_port=f['source_port'] if direction=='tls_c2s' else f['destination_port']
        if t['flags']&2:
            bases[key]=(t['sequence']+1)&0xffffffff
            if direction=='tls_c2s' and client_port not in ids:ids[client_port]=len(ids)+1
        if not t['payload_length']:continue
        role='client' if direction=='tls_c2s' else 'server';connection=ids.get(client_port)
        base=bases.get(key);offset=((t['sequence']-base)&0xffffffff) if base is not None else None
        result=dict(run_id=p["run_id"],context_id=endpoints[role]["manifest"]["context_id"],packet_index=p['packet_index'],pcap_offset=p['pcap_offset'],role=role,connection_id=connection,
                    observation=dict(interface=p['interface'],direction=p['direction'],monotonic_ns=p['monotonic_ns'],kernel_realtime_ns=p.get('kernel_realtime_ns'),timestamp_location=p.get('timestamp_location')),
                    stream_offset=offset,bytes=t['payload_length'],records=[],messages=[],byte_match=None,same_location_repeated_bytes=None)
        if connection and offset is not None:
            e=endpoints[role];conn=e['connections'][connection-1]
            records=[r for r in conn['records'] if r['outgoing'] and overlap(offset,t['payload_length'],r['stream_offset'],r['bytes'])]
            result['records']=[r['id'] for r in records];result['messages']=sorted(set(m for r in records for m in r['messages']))
            stream=(root/'run'/role/f'{connection}.tx.bin').read_bytes()
            begin=p['pcap_offset']+16+p['payload_offset'];data=captured[begin:begin+t['payload_length']]
            result['byte_match']=data==stream[offset:offset+len(data)]
            if not result['byte_match']:mismatches.append(p['packet_index'])
            locus=(key,p['interface'],p['direction']);ranges=seen[locus]
            # Merge previous observed byte intervals; duplicates at the other veth are separate observations.
            result['same_location_repeated_bytes']=sum(max(0,min(offset+len(data),b)-max(offset,a)) for a,b in ranges)
            merged=[]
            for a,b in sorted(ranges+[(offset,offset+len(data))]):
                if merged and a<=merged[-1][1]:merged[-1]=(merged[-1][0],max(b,merged[-1][1]))
                else:merged.append((a,b))
            seen[locus]=merged
        packets.append(result)
    footer=next((r for r in reversed(rows) if r['record_kind']=='footer'),None)
    kernel=json.loads((root/'kernel-events.json').read_text()) if (root/'kernel-events.json').exists() else dict(status='not-collected')
    counts=collections.Counter(e['kind'] for e in kernel.get('events',[]))
    for event in kernel.get('events',[]):
        direction='tls_c2s' if event['flow']['destination_port']==44330 else 'tls_s2c';role='client' if direction=='tls_c2s' else 'server'
        port=event['flow']['source_port'] if role=='client' else event['flow']['destination_port'];connection=ids.get(port)
        event['connection_id']=connection;event['role']=role;event['records']=[]
        if connection and event['stream_begin'] is not None:
            event['records']=[r['id'] for r in endpoints[role]['connections'][connection-1]['records'] if r['outgoing'] and overlap(event['stream_begin'],event['stream_end']-event['stream_begin'],r['stream_offset'],r['bytes'])]
    coverage=[]
    for role,endpoint_data in endpoints.items():
        for connection in endpoint_data['connections']:
            size=(root/'run'/role/f'{connection["connection_id"]}.tx.bin').stat().st_size
            intervals=[]
            for packet in packets:
                if packet['role']==role and packet['connection_id']==connection['connection_id'] and packet['observation']['direction']=='ingress' and packet['stream_offset'] is not None:
                    intervals.append((packet['stream_offset'],packet['stream_offset']+packet['bytes']))
            end=0
            for first,last in sorted(intervals):
                if first>end:break
                end=max(end,last)
            coverage.append(dict(role=role,connection_id=connection['connection_id'],stream_bytes=size,contiguous_observed_bytes=end,complete=end==size))
    complete=bool(coverage) and all(c["complete"] for c in coverage) and footer is not None and all(v['drops']==0 for v in footer['capture_socket_statistics'].values()) and not mismatches and all(p['byte_match'] is True for p in packets)
    return dict(contract='turtle-message-packet-report/1',status='available' if complete else 'missing',packets=packets,stream_coverage=coverage,byte_mismatches=mismatches,
                capture=footer,kernel=kernel,kernel_counts=dict(counts),flow_counts=dict(collections.Counter(p['logical_path'] for p in rows if p['record_kind']=='packet')),
                semantics='AF_PACKET skb observations at router ingress/egress; repeated byte observations are not kernel retransmission events; targeted_drop, qdisc_drop and tcp_retransmit_skb remain distinct')
