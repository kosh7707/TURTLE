#!/usr/bin/env python3
"""실행 소유 tc 프로그램·커널 링크와 고정 크기 사건 버퍼를 관리합니다."""
from __future__ import annotations

import argparse
import ctypes as C
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import time


class Config(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in
                ('client_ns', 'server_ns', 'router_ns', 'c2s_ifindex', 's2c_ifindex', 'reserved')] + [
                    ('c2s_target', C.c_uint64), ('s2c_target', C.c_uint64)]


class TcHook(C.Structure):
    _fields_ = [('sz', C.c_size_t), ('ifindex', C.c_int), ('attach_point', C.c_int),
                ('parent', C.c_uint32), ('handle', C.c_uint32), ('qdisc', C.c_char_p)]


class TcOptions(C.Structure):
    _fields_ = [('sz', C.c_size_t), ('prog_fd', C.c_int), ('flags', C.c_uint32),
                ('prog_id', C.c_uint32), ('handle', C.c_uint32), ('priority', C.c_uint32)]


class Event(C.Structure):
    _fields_ = [('monotonic_ns', C.c_uint64), ('saddr', C.c_uint32), ('daddr', C.c_uint32),
                ('sport', C.c_uint16), ('dport', C.c_uint16)] + [
                    (name, C.c_uint32) for name in
                    ('kind', 'netns', 'ifindex', 'seq', 'end_seq', 'base', 'flags')] + [
                        ('result', C.c_int32), ('base_known', C.c_uint32)]


class Flow(C.Structure):
    _fields_ = [('saddr', C.c_uint32), ('daddr', C.c_uint32),
                ('sport', C.c_uint16), ('dport', C.c_uint16)]


class FlowState(C.Structure):
    _fields_ = [('base', C.c_uint32), ('dropped', C.c_uint32)]


CAPACITY = 65536
NO_TARGET = 2**64 - 1
CALLBACK = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)


def event_document(event):
    def address(value):
        return socket.inet_ntoa(bytes(C.c_uint32(value)))
    data_begin = (event.seq + bool(event.flags & 2)) & 0xffffffff
    data_end = (event.end_seq - bool(event.flags & 1)) & 0xffffffff
    return {'kind': {1: 'targeted_drop', 2: 'tcp_retransmit_skb', 3: 'qdisc_drop'}[event.kind],
            'monotonic_ns': event.monotonic_ns, 'network_namespace_inode': event.netns,
            'ifindex': event.ifindex or None,
            'flow': {'source': address(event.saddr), 'destination': address(event.daddr),
                     'source_port': event.sport, 'destination_port': event.dport},
            'sequence': event.seq, 'end_sequence': event.end_seq, 'tcp_flags': event.flags,
            'initial_data_sequence': event.base if event.base_known else None,
            'stream_begin': ((data_begin - event.base) & 0xffffffff) if event.base_known else None,
            'stream_end': ((data_end - event.base) & 0xffffffff) if event.base_known else None,
            'result': event.result, 'tc_action': 2 if event.kind == 1 else None,
            'drop_reason': 'SKB_DROP_REASON_QDISC_DROP' if event.kind == 3 else None}


def clock_pair():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return {'monotonic_before_ns': before, 'realtime_ns': realtime, 'monotonic_after_ns': after,
            'bracket_ns': after - before}


def enter_network_namespace(fd):
    # Python 3.10/3.11에도 같은 Linux setns 경로를 사용합니다.
    libc = C.CDLL(None, use_errno=True)
    if libc.setns(fd, 0x40000000) != 0:
        error = C.get_errno()
        raise OSError(error, os.strerror(error))


class Collector:
    def __init__(self, obj: Path, config: Config):
        self.obj_path, self.config = obj, config
        self.lib = C.CDLL('libbpf.so.1', use_errno=True)
        definitions = {
            'bpf_object__open_file': (C.c_void_p, [C.c_char_p, C.c_void_p]),
            'libbpf_get_error': (C.c_long, [C.c_void_p]),
            'libbpf_version_string': (C.c_char_p, []),
            'bpf_object__load': (C.c_int, [C.c_void_p]),
            'bpf_object__close': (None, [C.c_void_p]),
            'bpf_object__find_map_fd_by_name': (C.c_int, [C.c_void_p, C.c_char_p]),
            'bpf_map_update_elem': (C.c_int, [C.c_int, C.c_void_p, C.c_void_p, C.c_uint64]),
            'bpf_map_lookup_elem': (C.c_int, [C.c_int, C.c_void_p, C.c_void_p]),
            'bpf_map_get_next_key': (C.c_int, [C.c_int, C.c_void_p, C.c_void_p]),
            'bpf_object__find_program_by_name': (C.c_void_p, [C.c_void_p, C.c_char_p]),
            'bpf_program__fd': (C.c_int, [C.c_void_p]),
            'bpf_program__attach': (C.c_void_p, [C.c_void_p]),
            'bpf_link__destroy': (C.c_int, [C.c_void_p]),
            'bpf_tc_hook_create': (C.c_int, [C.POINTER(TcHook)]),
            'bpf_tc_hook_destroy': (C.c_int, [C.POINTER(TcHook)]),
            'bpf_tc_attach': (C.c_int, [C.POINTER(TcHook), C.POINTER(TcOptions)]),
            'bpf_tc_detach': (C.c_int, [C.POINTER(TcHook), C.POINTER(TcOptions)]),
            'ring_buffer__new': (C.c_void_p, [C.c_int, CALLBACK, C.c_void_p, C.c_void_p]),
            'ring_buffer__poll': (C.c_int, [C.c_void_p, C.c_int]),
            'ring_buffer__consume': (C.c_int, [C.c_void_p]),
            'ring_buffer__free': (None, [C.c_void_p]),
        }
        for name, (result, arguments) in definitions.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, arguments
        self.obj = self.ring = None
        self.links, self.hooks = [], []
        self.buffer = (Event * CAPACITY)()
        self.count, self.buffer_lost = 0, 0
        self.callback = CALLBACK(self.receive)
        self.cleanup_errors = []
        self.flow_states = []

    def check(self, result, operation):
        if result < 0:
            raise RuntimeError(f'{operation}: {os.strerror(-result)} ({result})')
        return result

    def pointer(self, result, operation):
        error = self.lib.libbpf_get_error(result)
        self.check(error, operation)
        if not result:
            raise RuntimeError(f'{operation}: null result; errno={C.get_errno()}')
        return result

    def map_fd(self, name):
        return self.check(self.lib.bpf_object__find_map_fd_by_name(self.obj, name.encode()), name)

    def receive(self, _context, data, length):
        # 측정 중 문자열·파일 출력 없이 준비된 고정 버퍼로 복사합니다.
        if length != C.sizeof(Event) or self.count == CAPACITY:
            self.buffer_lost += 1
        else:
            C.memmove(C.byref(self.buffer, self.count * C.sizeof(Event)), data, length)
            self.count += 1
        return 0

    def start(self):
        self.obj = self.pointer(self.lib.bpf_object__open_file(os.fsencode(self.obj_path), None), 'open object')
        self.check(self.lib.bpf_object__load(self.obj), 'load CO-RE object')
        zero = C.c_uint32(0)
        self.check(self.lib.bpf_map_update_elem(self.map_fd('settings'), C.byref(zero), C.byref(self.config), 0), 'settings')
        self.ring = self.pointer(self.lib.ring_buffer__new(self.map_fd('events'), self.callback, None, None), 'ring')
        program = self.pointer(self.lib.bpf_object__find_program_by_name(self.obj, b'targeted_drop'), 'tc program')
        program_fd = self.check(self.lib.bpf_program__fd(program), 'tc program fd')
        for ifindex in (self.config.c2s_ifindex, self.config.s2c_ifindex):
            hook = TcHook(sz=C.sizeof(TcHook), ifindex=ifindex, attach_point=2)
            self.check(self.lib.bpf_tc_hook_create(C.byref(hook)), 'create owned clsact')
            self.hooks.append((hook, None))
            options = TcOptions(sz=C.sizeof(TcOptions), prog_fd=program_fd, handle=1, priority=1)
            self.check(self.lib.bpf_tc_attach(C.byref(hook), C.byref(options)), 'attach owned tc')
            self.hooks[-1] = (hook, options)
        for name in (b'retransmit', b'qdisc_drop'):
            program = self.pointer(self.lib.bpf_object__find_program_by_name(self.obj, name), str(name))
            self.links.append(self.pointer(self.lib.bpf_program__attach(program), f'attach {name!r}'))

    def poll(self):
        self.check(self.lib.ring_buffer__poll(self.ring, 50), 'ring poll')

    def stop(self):
        for link in self.links:
            error = self.lib.bpf_link__destroy(link)
            if error:
                self.cleanup_errors.append(f'link destroy: {error}')
        self.links.clear()
        for hook, options in reversed(self.hooks):
            if options is not None:
                # detach requires prog_fd/prog_id to be zero, preserving handle/priority.
                detach = TcOptions(sz=C.sizeof(TcOptions), handle=options.handle, priority=options.priority)
                error = self.lib.bpf_tc_detach(C.byref(hook), C.byref(detach))
                if error:
                    self.cleanup_errors.append(f'tc detach: {error}')
            hook.attach_point = 3  # delete both sides of our own clsact only
            error = self.lib.bpf_tc_hook_destroy(C.byref(hook))
            if error:
                self.cleanup_errors.append(f'clsact destroy: {error}')
        self.hooks.clear()
        failures = None
        if self.ring:
            error = self.lib.ring_buffer__consume(self.ring)
            if error < 0:
                self.cleanup_errors.append(f'ring consume: {error}')
            self.lib.ring_buffer__free(self.ring)
            self.ring = None
        if self.obj:
            fd = self.lib.bpf_object__find_map_fd_by_name(self.obj, b'flows')
            previous = None
            if fd >= 0:
                for _ in range(8193):
                    key, state = Flow(), FlowState()
                    if self.lib.bpf_map_get_next_key(fd, C.byref(previous) if previous else None, C.byref(key)):
                        if C.get_errno() != errno.ENOENT:
                            self.cleanup_errors.append('flow inventory unavailable')
                        break
                    if self.lib.bpf_map_lookup_elem(fd, C.byref(key), C.byref(state)):
                        self.cleanup_errors.append('flow state unavailable')
                        break
                    source = socket.inet_ntoa(bytes(C.c_uint32(key.saddr)))
                    target = self.config.c2s_target if source == '10.203.1.2' else self.config.s2c_target
                    self.flow_states.append({'flow': {'source': source,
                        'destination': socket.inet_ntoa(bytes(C.c_uint32(key.daddr))),
                        'source_port': key.sport, 'destination_port': key.dport},
                        'initial_data_sequence': state.base,
                        'target_byte': target if target != NO_TARGET else None,
                        'dropped': bool(state.dropped)})
                    previous = key
                else:
                    self.cleanup_errors.append('flow inventory exceeds capacity')
            fd = self.lib.bpf_object__find_map_fd_by_name(self.obj, b'failures')
            if fd >= 0:
                failures = {}
                for index, name in enumerate(('ring_lost', 'flow_state_missing', 'packet_read_failed')):
                    key, value = C.c_uint32(index), C.c_uint64()
                    code = self.lib.bpf_map_lookup_elem(fd, C.byref(key), C.byref(value))
                    failures[name] = value.value if code == 0 else None
            self.lib.bpf_object__close(self.obj)
            self.obj = None
        return failures


def run(args):
    metadata = {'type': 'turtle-kernel-events', 'schema': 1, 'status': 'initializing',
                'clock': 'CLOCK_MONOTONIC (bpf_ktime_get_ns)', 'clock_pairs': [clock_pair()],
                'kernel_release': os.uname().release, 'uid': os.geteuid(),
                'buffer_capacity': CAPACITY, 'event_struct_size': C.sizeof(Event),
                'object_sha256': hashlib.sha256(args.object.read_bytes()).hexdigest(),
                'btf_sha256': hashlib.sha256(Path('/sys/kernel/btf/vmlinux').read_bytes()).hexdigest(),
                'events': [], 'cleanup_errors': [], 'missing_reason': None}
    config = Config(client_ns=os.fstat(args.client_fd).st_ino, server_ns=os.fstat(args.server_fd).st_ino,
                    router_ns=os.fstat(args.router_fd).st_ino,
                    c2s_target=args.c2s_target if args.c2s_target is not None else NO_TARGET,
                    s2c_target=args.s2c_target if args.s2c_target is not None else NO_TARGET)
    control = socket.socket(fileno=args.control_fd)
    collector = None
    try:
        # 전달받은 실행 소유 라우터에만 tc를 붙입니다.
        enter_network_namespace(args.router_fd)
        config.c2s_ifindex, config.s2c_ifindex = socket.if_nametoindex('rstls'), socket.if_nametoindex('rctls')
        metadata['configuration'] = {name: getattr(config, name) for name, _ in Config._fields_}
        collector = Collector(args.object, config)
        metadata['libbpf_version'] = collector.lib.libbpf_version_string().decode()
        collector.start()
        control.sendall(b'R')
        while not select.select([control], [], [], 0)[0]:
            collector.poll()
        command = control.recv(1)
        if command != b'S':
            raise RuntimeError('coordinator ended without stop command')
        metadata['status'] = 'complete'
    except Exception as error:
        metadata.update(status='missing', missing_reason=str(error))
        try:
            control.sendall(b'E')
        except OSError:
            pass
    finally:
        if collector:
            metadata['failures'] = collector.stop()
            metadata['buffer_lost'] = collector.buffer_lost
            metadata['cleanup_errors'] = collector.cleanup_errors
            metadata['events'] = [event_document(collector.buffer[i]) for i in range(collector.count)]
            metadata['flows'] = collector.flow_states
            requested = [f for f in collector.flow_states if f['target_byte'] is not None]
            has_targets = config.c2s_target != NO_TARGET or config.s2c_target != NO_TARGET
            metadata['targeted_loss_complete'] = (
                not has_targets or bool(requested) and all(f['dropped'] for f in requested))
            if not metadata['targeted_loss_complete']:
                metadata.update(status='missing', missing_reason=metadata['missing_reason'] or 'requested_target_byte_not_reached')
            collection_complete = (not collector.cleanup_errors and not collector.buffer_lost and
                                   metadata['failures'] and
                                   all(value == 0 for value in metadata['failures'].values()))
            if not collection_complete:
                metadata.update(status='missing', missing_reason=metadata['missing_reason'] or 'collection_or_cleanup_incomplete')
        metadata['clock_pairs'].append(clock_pair())
        args.output.write_text(json.dumps(metadata, indent=2) + '\n')
        control.close()
    return 0 if metadata['status'] == 'complete' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('client', 'server', 'router', 'control'):
        parser.add_argument(f'--{name}-fd', type=int, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--c2s-target', type=int)
    parser.add_argument('--s2c-target', type=int)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
