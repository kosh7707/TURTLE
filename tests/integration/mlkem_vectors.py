#!/usr/bin/env python3
"""고정 upstream 정상 벡터와 C/AVX2의 동일 입력 출력을 확인합니다."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

fixture = json.loads(Path(sys.argv[3]).read_text())
results = []
for executable in sys.argv[1:3]:
    def run(action, *inputs):
        result = subprocess.run([executable, action], input='\n'.join(inputs) + '\n',
                                capture_output=True, text=True, check=True, timeout=20)
        return result.stdout.splitlines()
    key = fixture['keygen']
    enc = fixture['encapsulate']
    generated = run('keygen-roundtrip', key['seed'], enc['seed'])
    for value, expected in zip(generated[:2], (key['public_sha256'], key['private_sha256'])):
        assert hashlib.sha256(bytes.fromhex(value)).hexdigest() == expected
    encapsulated = run('encapsulate', enc['seed'], enc['public'])
    assert hashlib.sha256(bytes.fromhex(encapsulated[0])).hexdigest() == enc['ciphertext_sha256']
    assert encapsulated[1] == enc['secret']
    results.append((generated, encapsulated))
assert results[0] == results[1], 'C and AVX2 outputs differ for identical inputs'
print('ML-KEM-768 upstream keygen/encapsulation vectors and normal decapsulation passed for both builds')
