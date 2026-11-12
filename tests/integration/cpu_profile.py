#!/usr/bin/env python3
"""표본 수·period 가중치·누락 구간이 총 CPU 시간과 혼동되지 않는지 확인합니다."""
import importlib.util
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))

spec = importlib.util.spec_from_file_location('cpu_profile', Path(sys.argv[1]))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
samples, other = module.parse_samples(''' 10/10 12.000000001: 100 cycles:u: abc hello(int) (/tmp/module.so)
 10/10 12.000000009: 25 cycles:u: def [unknown] ([unknown])
''')
assert not other and samples[0]['monotonic_ns'] == 12000000001
result = module.distribution(samples)
assert result['sample_count'] == 2 and result['sample_period_sum'] == 125
assert result['unknown_symbol_samples'] == 1
assert result['functions'][0]['period_fraction'] == .8
assert module.distribution([])['status'] == 'missing'
assert module.distribution([])['sample_period_sum'] is None
assert module.parse_samples('PERF_RECORD_LOST unknown-format')[1]
with tempfile.TemporaryDirectory(prefix='turtle-perf-symbols-') as temporary:
    root = Path(temporary)
    live = root / 'live-binary'
    shutil.copyfile(sys.argv[2], live)
    build_id = module.elf_build_id(live)
    assert build_id
    binaries = module.copy_binaries(root, {str(live): build_id})
    assert binaries[0]['status'] == 'available'
    (root / 'perf.data').write_bytes(b'fixture recording identity')
    manifest = {'buildid_list_returncode': 0, 'unparsed': [], 'binaries': binaries,
                'perf_data_sha256': hashlib.sha256((root / 'perf.data').read_bytes()).hexdigest()}
    live.write_bytes(b'rebuilt program has replaced the original')
    assert module.verify_binaries(root, manifest)['status'] == 'available'
    manifest['unparsed'] = ['                                         /tmp/perf-vdso.so-AbC123']
    verified = module.verify_binaries(root, manifest)
    assert verified['status'] == 'available' and len(verified['unsupported_virtual_objects']) == 1
    vdso_samples = [{'module': '[vdso]', 'symbol': 'a_current_machine_symbol', 'period': 7}]
    module.preserve_unresolved_symbols(vdso_samples, verified)
    assert module.distribution(vdso_samples)['unknown_symbol_samples'] == 1
    assert module.distribution(vdso_samples)['sample_period_sum'] == 7
    manifest['unparsed'] = ['                                         /tmp/ordinary-library.so']
    assert module.verify_binaries(root, manifest)['status'] == 'missing'
    manifest['unparsed'] = []
    # An old recording cannot be recovered from a later, different executable.
    assert module.copy_binaries(root / 'old-run', {str(live): build_id})[0]['status'] == 'missing'
    (root / binaries[0]['path']).unlink()
    assert module.verify_binaries(root, manifest)['status'] == 'missing'
print('sample weighting, missing observations and binary preservation across rebuilds verified')

# Builtin adapters have no measured module load. Only their setup boundary can start this span.
from raw_record import lifetime_span, require_tls_sample
fixture_events = [
    {'kind': 'MODULE_BEGIN', 'monotonic_ns': 1},
    {'kind': 'SETUP_BEGIN', 'call': 'setup', 'monotonic_ns': 2},
    {'kind': 'CALL_END', 'call': 'teardown', 'monotonic_ns': 5},
]
for mode, expected, start in (('builtin', 'context-setup-to-teardown', 2),
                              ('module', 'module-to-teardown', 1)):
    name, begin, end = lifetime_span({'adapter_connection': {'mode': mode}}, fixture_events)
    assert name == expected and begin['monotonic_ns'] == start and end['monotonic_ns'] == 5
for old in (1, 2):
    try:
        require_tls_sample({'type': 'sample', 'schema': old, 'measurement_contract_revision': 3})
    except ValueError as error:
        assert 'requires schema 3' in str(error)
    else:
        raise AssertionError('old TLS schema was accepted')
