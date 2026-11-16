#!/usr/bin/env python3
"""두 ML-KEM 빌드에서 디버그 정보 이외의 오브젝트 차이가 두 연산 파일에만 있는지 확인합니다."""
import argparse,hashlib,json,pathlib,subprocess,tempfile

def verify(deps):
    deps=pathlib.Path(deps);objects={}
    with tempfile.TemporaryDirectory() as tmp:
        target=pathlib.Path(tmp)/'object.o'
        for variant in ('c','avx2'):
            root=deps/f'message-build/mlkem-{variant}/CMakeFiles/wolfssl.dir';objects[variant]={}
            for p in root.rglob('*.o'):
                subprocess.run(['objcopy','--strip-debug',str(p),str(target)],check=True)
                objects[variant][str(p.relative_to(root))]=hashlib.sha256(target.read_bytes()).hexdigest()
    if not objects['c'] or objects['c'].keys()!=objects['avx2'].keys():raise ValueError('ML-KEM object inventory mismatch')
    changed=[name for name in objects['c'] if objects['c'][name]!=objects['avx2'][name]]
    allowed={'wolfcrypt/src/wc_mlkem.c.o','wolfcrypt/src/wc_mlkem_poly.c.o'}
    result=dict(contract='turtle-message-mlkem-objects/1',status='available' if set(changed)==allowed else 'mismatch',changed=changed,objects=objects,normalization='objcopy --strip-debug; code and data retained')
    if result['status']!='available':raise ValueError(json.dumps(result))
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--deps',default='.deps-message');p.add_argument('--output',required=True);a=p.parse_args();pathlib.Path(a.output).write_text(json.dumps(verify(a.deps),indent=2)+'\n')
