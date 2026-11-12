#!/usr/bin/env python3
"""ML-KEM 두 소스 파일 이외의 오브젝트가 같은지 확인하고 해시를 보존합니다."""
import hashlib
import json
from pathlib import Path
import sys


def verify(root):
    variants = {}
    for variant in ('c', 'avx2'):
        build = root / 'build' / ('mlkem-' + variant) / 'CMakeFiles/wolfssl.dir'
        variants[variant] = {str(p.relative_to(build)): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(build.rglob('*.o'))}
    assert variants['c'] and variants['c'].keys() == variants['avx2'].keys(), 'object sets differ'
    changed = [name for name in variants['c'] if variants['c'][name] != variants['avx2'][name]]
    expected = {'wolfcrypt/src/wc_mlkem.c.o', 'wolfcrypt/src/wc_mlkem_poly.c.o'}
    assert set(changed) == expected, f'unexpected compiled differences: {changed}'
    report = {'schema': 1, 'status': 'verified', 'changed_objects': changed,
              'identical_other_objects': len(variants['c']) - len(changed), 'objects': variants}
    (root / 'manifests/mlkem-object-comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'ML-KEM pair: {len(changed)} changed objects, {report["identical_other_objects"]} identical')


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
