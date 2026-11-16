#!/usr/bin/env python3
"""빌드 직후 소스·컴파일 명령·정적 라이브러리·바이너리의 출처를 고정합니다."""
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parent.parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def save(build,deps):
    build=pathlib.Path(build);deps=pathlib.Path(deps)
    sources={str(p.relative_to(root)):sha(p) for folder in ('include','src','implementations','cmake','scripts','tests','third_party') for p in (root/folder).rglob('*') if p.is_file() and p.suffix in ('.c','.cpp','.hpp','.h','.cmake','.txt','.patch','.py','.sh')}
    sources['CMakeLists.txt']=sha(root/'CMakeLists.txt')
    dependencies={p.name:json.loads(p.read_text()) for p in deps.glob('*-manifest.json')}
    result=dict(contract='turtle-message-build/1',sources=sources,dependencies=dependencies,
                third_party={'nlohmann-json':dict(version='3.11.3',header_sha256=sha(root/'third_party/nlohmann/json.hpp'),license_sha256=sha(root/'third_party/nlohmann/LICENSE.MIT'))},
                commands=json.loads((build/'compile_commands.json').read_text()),
                binaries={p.name:sha(p) for p in build.glob('turtle-*') if p.is_file()},
                compiler=subprocess.check_output(['c++','--version'],text=True),cmake_cache=(build/'CMakeCache.txt').read_text())
    (build/'build-manifest.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':save(*sys.argv[1:])
