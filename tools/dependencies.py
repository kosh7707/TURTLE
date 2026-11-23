#!/usr/bin/env python3
"""선택적 의존성 준비 도구. fetch 이후의 준비·빌드에는 네트워크를 쓰지 않는다."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).resolve().with_name('dependencies.json')


def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def entries(component):
    data = json.loads(MANIFEST.read_text())
    return [row for row in data['sources'] if component == 'all' or row['component'] == component]


def verified(cache, entry):
    path = Path(cache) / entry['archive']
    if not path.is_file() or digest(path) != entry['sha256']:
        raise ValueError('verified archive required: ' + str(path))
    return path


def fetch(cache, component):
    cache.mkdir(parents=True, exist_ok=True)
    for entry in entries(component):
        destination = cache / entry['archive']
        if not destination.exists():
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as file:
                temporary = Path(file.name)
                try:
                    with urlopen(entry['url'], timeout=60) as response:
                        shutil.copyfileobj(response, file)
                    file.flush()
                    if digest(temporary) != entry['sha256']:
                        raise ValueError('SHA-256 mismatch: ' + entry['url'])
                    temporary.replace(destination)
                finally:
                    temporary.unlink(missing_ok=True)
        verified(cache, entry)
        print('verified:', entry['archive'], flush=True)


def prepare(cache, workspace, component, jobs, target, toolchain):
    workspace.mkdir(parents=True, exist_ok=True)
    for entry in entries(component):
        archive = verified(cache, entry)
        root = workspace / (entry['name'] + '-' + entry['version'])
        source, build, install = (root / name for name in ('source', 'build', 'install'))
        root.mkdir(parents=True, exist_ok=True)
        if not source.exists():
            with tempfile.TemporaryDirectory(dir=root) as temporary:
                with tarfile.open(archive) as tar:
                    tar.extractall(temporary, filter='data')
                roots = list(Path(temporary).iterdir())
                if len(roots) != 1 or not roots[0].is_dir():
                    raise ValueError('single source directory required')
                roots[0].rename(source)
        build.mkdir(exist_ok=True)
        evidence = {'source': entry, 'target': target, 'toolchain': str(toolchain) if toolchain else None,
                    'network_during_build': False, 'commands': []}

        def run(args, cwd=None):
            args = list(map(str, args))
            evidence['commands'].append({'argv': args, 'cwd': str(cwd or Path.cwd())})
            (root / 'provenance.json').write_text(json.dumps(evidence, indent=2) + '\n')
            subprocess.run(args, cwd=cwd, check=True)

        if entry['component'] == 'perf':
            options = entry['build_options'][:]
            if target:
                options += ['ARCH=arm64', 'CROSS_COMPILE=aarch64-linux-gnu-']
            run(['make', '-C', source / 'tools/perf', '-j', jobs, 'O=' + str(build) + '/', *options])
            (install / 'bin').mkdir(parents=True, exist_ok=True)
            shutil.copy2(build / 'perf', install / 'bin/perf')
            if not target:
                linked = subprocess.check_output(['ldd', install / 'bin/perf'], text=True)
                if 'libpython' in linked:
                    raise ValueError('perf still links Python')
                evidence['dynamic_libraries'] = linked
                evidence['version'] = subprocess.check_output([install / 'bin/perf', '--version'], text=True).strip()
        elif entry['name'] == 'openssl':
            options = entry['build_options'][:]
            if target:
                options = ['linux-aarch64', '--cross-compile-prefix=aarch64-linux-gnu-', *options]
            run([source / 'Configure', *options, '--prefix=' + str(install)], build)
            run(['make', '-j', jobs], build)
            run(['make', 'install_sw'], build)
        else:
            options = ['-DCMAKE_INSTALL_PREFIX=' + str(install), *entry['build_options']]
            if target and entry['name'] == 'wolfssl':
                options.append('-DCMAKE_C_FLAGS=-Wno-error=stringop-overflow')
            if toolchain:
                options.append('-DCMAKE_TOOLCHAIN_FILE=' + str(toolchain))
            run(['cmake', '-S', source, '-B', build, '-G', 'Ninja', *options])
            run(['cmake', '--build', build, '--parallel', jobs])
            run(['cmake', '--install', build])
        evidence['status'] = 'built'
        (root / 'provenance.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print('prepared:', install, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fetch', 'prepare'))
    parser.add_argument('component', choices=('framework', 'tls', 'perf', 'all'))
    parser.add_argument('--cache', type=Path, default=ROOT / '.deps/cache')
    parser.add_argument('--workspace', type=Path, default=ROOT / '.deps/prepared')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--target', choices=('arm64',))
    parser.add_argument('--toolchain', type=Path)
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch(args.cache.resolve(), args.component)
    else:
        toolchain = args.toolchain.resolve() if args.toolchain else (ROOT / 'cmake/linux-arm64.cmake' if args.target else None)
        prepare(args.cache.resolve(), args.workspace.resolve(), args.component, args.jobs, args.target, toolchain)


if __name__ == '__main__':
    main()
