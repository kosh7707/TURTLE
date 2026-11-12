#!/usr/bin/env python3
"""커널 순번 순환·SYN/FIN 소비와 미관측 기준 순번을 구별합니다."""
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('kernel_observer', Path(sys.argv[1]))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

event = module.Event(kind=2, seq=0xffffffff, end_seq=3, base=0xfffffffd,
                     base_known=1, flags=17)
row = module.event_document(event)
assert row['stream_begin'] == 2 and row['stream_end'] == 5  # FIN is not a TLS byte
event.kind = 1
assert module.event_document(event)['tc_action'] == 2
event.flags, event.seq, event.end_seq = 2, 0xfffffffc, 0xfffffffd
row = module.event_document(event)
assert row['stream_begin'] == row['stream_end'] == 0  # SYN is not a TLS byte
event.base_known = 0
row = module.event_document(event)
assert row['stream_begin'] is None and row['initial_data_sequence'] is None
event.base_known, event.base, event.seq, event.end_seq, event.flags = 1, 0, 0, 3, 16
row = module.event_document(event)
assert row['initial_data_sequence'] == 0 and row['stream_end'] == 3  # observed zero
print('PASS kernel event sequence wrap, SYN/FIN and missing versus zero')
