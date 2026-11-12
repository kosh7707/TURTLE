#!/usr/bin/env python3
"""권한 있는 환경에서 tc 프로그램의 정상 TCP 포트 중첩을 확인합니다. 부착은 하지 않습니다."""
import argparse
import ctypes as C
import json
from pathlib import Path
import socket
import struct
import sys

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root/'scripts'))
from kernel_observer import Collector, Config, Flow, FlowState

class TestRun(C.Structure):
    _fields_ = [('sz', C.c_size_t), ('data_in', C.c_void_p), ('data_out', C.c_void_p),
                ('data_size_in', C.c_uint32), ('data_size_out', C.c_uint32),
                ('ctx_in', C.c_void_p), ('ctx_out', C.c_void_p),
                ('ctx_size_in', C.c_uint32), ('ctx_size_out', C.c_uint32),
                ('retval', C.c_uint32), ('repeat', C.c_int),
                ('duration', C.c_uint32), ('flags', C.c_uint32),
                ('cpu', C.c_uint32), ('batch_size', C.c_uint32)]

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--object', type=Path, required=True)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
collector = Collector(args.object.resolve(), Config(c2s_ifindex=1, s2c_ifindex=1))
lib = collector.lib
lib.bpf_prog_test_run_opts.argtypes = [C.c_int, C.POINTER(TestRun)]
lib.bpf_prog_test_run_opts.restype = C.c_int
collector.obj = collector.pointer(lib.bpf_object__open_file(bytes(collector.obj_path), None), 'open')
try:
    collector.check(lib.bpf_object__load(collector.obj), 'load')
    zero = C.c_uint32(0)
    collector.check(lib.bpf_map_update_elem(collector.map_fd('settings'), C.byref(zero), C.byref(collector.config), 0), 'config')
    program = collector.pointer(lib.bpf_object__find_program_by_name(collector.obj, b'targeted_drop'), 'program')
    fd = collector.check(lib.bpf_program__fd(program), 'fd')
    cases = []
    for service in (44330, 44331):
        for client in (44330, 44331, 55000):
            for c2s in (True, False):
                src, dst = ('10.203.1.2','10.203.2.2') if c2s else ('10.203.2.2','10.203.1.2')
                sport, dport = (client, service) if c2s else (service, client)
                base = 1000 + len(cases)*100
                actions = []
                for flags, seq, payload in ((2,base,b''),(24,base+1,b'abc'),(24,base+1,b'abc')):
                    frame = bytearray(54+len(payload))
                    struct.pack_into('!H',frame,12,0x0800)
                    frame[14],frame[23] = 0x45,6
                    struct.pack_into('!H',frame,16,40+len(payload))
                    frame[26:30],frame[30:34] = socket.inet_aton(src),socket.inet_aton(dst)
                    struct.pack_into('!HHII',frame,34,sport,dport,seq,0)
                    frame[46],frame[47],frame[54:] = 0x50,flags,payload
                    data = C.create_string_buffer(bytes(frame))
                    opts = TestRun(sz=C.sizeof(TestRun),data_in=C.cast(data,C.c_void_p),data_size_in=len(frame),repeat=1)
                    collector.check(lib.bpf_prog_test_run_opts(fd,C.byref(opts)), 'test run')
                    actions.append(opts.retval)
                assert actions == ([0,2,0] if service == 44330 else [0,0,0]), (src,sport,dst,dport,actions)
                flow = Flow(saddr=int.from_bytes(socket.inet_aton(src),sys.byteorder),daddr=int.from_bytes(socket.inet_aton(dst),sys.byteorder),sport=sport,dport=dport)
                state = FlowState()
                result = lib.bpf_map_lookup_elem(collector.map_fd('flows'),C.byref(flow),C.byref(state))
                assert (result == 0) == (service == 44330), (service,result)
                cases.append(dict(client_port=client,service_port=service,direction='c2s' if c2s else 's2c',actions=actions))
    result = dict(status='passed',cases=cases,program='targeted_drop',attached=False,method='BPF_PROG_TEST_RUN',data_first_packet_drop=True,control_untouched=True)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS actual BPF: 12 bidirectional service/ephemeral-port cases; control untracked; data first drop then retry passes')
finally:
    lib.bpf_object__close(collector.obj)
