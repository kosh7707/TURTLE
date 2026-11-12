#!/usr/bin/env python3
"""고정 libbpf 헤더와 현재 Clang으로 CO-RE 커널 관측기를 빌드합니다."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.request import urlopen

HEADERS = {
    'bpf_helpers.h': '48a427f30cce7458f56340c2c2085063b05ed0b227186ac1480c2025c135e2a6',
    'bpf_helper_defs.h': '4dce471e2406e0e9ce3f9d838b2d774f36279d3afc4b457db7253ddb232a6ba1',
    'bpf_core_read.h': 'ffd0d663cb7f3a5c243c7dfc13313438bb83c73d6646da92ef1e912a8d5d9e35',
    'bpf_endian.h': '64b77c97b089ca06203d0451407844fe93933b4e36e7315a294745fa29d058fb',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch-headers', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('build/kernel-observer.bpf.o'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    headers = root / '.deps/src/libbpf-headers-1.6.3'
    for name, digest in HEADERS.items():
        path = headers / 'bpf' / name
        if not path.exists() and args.fetch_headers:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(urlopen(f'https://raw.githubusercontent.com/libbpf/libbpf/v1.6.3/src/{name}', timeout=30).read())
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f'{path}: pinned header unavailable; use --fetch-headers during dependency setup')
    source = root / 'scripts/kernel-observer.bpf.c'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    multiarch = subprocess.check_output(['cc', '-print-multiarch'], text=True).strip()
    command = ['clang', '-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-I', str(headers), '-I', f'/usr/include/{multiarch}', '-c', str(source), '-o', str(args.output)]
    subprocess.run(command, check=True)
    manifest = {'type': 'turtle-kernel-observer-build', 'schema': 1,
                'libbpf_headers_version': '1.6.3', 'headers_sha256': HEADERS,
                'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'object_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                'compiler': subprocess.check_output(['clang', '--version'], text=True), 'command': command}
    args.output.with_suffix('.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
