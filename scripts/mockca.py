#!/usr/bin/env python3
"""합성 객체를 반환하는 독립 MockCA 엔드포인트입니다. 인증서를 발급하지 않습니다."""
import argparse
import hashlib
import json
import pathlib
import signal
import socket
import struct
import time
import uuid
import os


def serve(obj, output, address, port):
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=False)
    setup_begin,setup_cpu=time.monotonic_ns(),time.thread_time_ns()
    data = pathlib.Path(obj).read_bytes()
    setup_end,setup_cpu_end=time.monotonic_ns(),time.thread_time_ns()
    context=str(uuid.uuid4())
    events = []
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    manifest = dict(contract='turtle-mockca-manifest/1', role='mockca',
                    object_sha256=hashlib.sha256(data).hexdigest(), object_bytes=len(data),
                    semantics='synthetic object lookup; not certificate issuance or TLS certificate replacement',
                    clock_domain=context, context_id=context, pid=os.getpid(), preparation_ns=setup_end-setup_begin,preparation_cpu_ns=setup_cpu_end-setup_cpu, source=str(pathlib.Path(obj).resolve()))
    try:
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, port))
            server.listen()
            server.settimeout(.2)
            (output / 'ready').write_text('listening\n')
            while running:
                try:
                    conn, peer = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(5)
                    begin, cpu = time.monotonic_ns(), time.thread_time_ns()
                    request = b''
                    while len(request) < 16:
                        part = conn.recv(16-len(request))
                        if not part:
                            raise RuntimeError('incomplete MockCA request')
                        request += part
                    if request != b'TURTLE-MockCA/1\n':
                        # The wire request is 16 bytes including newline.
                        raise RuntimeError('unsupported MockCA contract')
                    def exact(n):
                        result=b''
                        while len(result)<n:
                            part=conn.recv(n-len(result))
                            if not part:raise RuntimeError('incomplete MockCA run identity')
                            result+=part
                        return result
                    size=struct.unpack('!I',exact(4))[0]
                    if not 1<=size<=256:raise ValueError('run identity length')
                    run_id=exact(size).decode();requester='client' if exact(1)==b'C' else 'server'
                    conn.sendall(struct.pack('!Q', len(data)) + data)
                    events.append(dict(contract='turtle-message-events/1', role='mockca',
                                       sequence=len(events)+1, context_id=context, run_id=run_id, requester_role=requester,
                                       connection_id=len(events)+1, kind='lookup-service', peer=peer,
                                       begin=dict(monotonic_ns=begin, thread_cpu_ns=cpu),
                                       end=dict(monotonic_ns=time.monotonic_ns(), thread_cpu_ns=time.thread_time_ns()),
                                       bytes=len(data)))
    finally:
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        (output / 'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('object')
    p.add_argument('output')
    p.add_argument('--address', default='127.0.0.1')
    p.add_argument('--port', type=int, default=44332)
    a = p.parse_args()
    serve(a.object, a.output, a.address, a.port)
