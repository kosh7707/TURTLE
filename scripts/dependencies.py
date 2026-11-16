#!/usr/bin/env python3
"""고정 원본과 경계 패치를 오프라인으로 빌드합니다. 다운로드는 --fetch에서만 합니다."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parent.parent
TARBALLS={
 'openssl':('openssl-3.5.4.tar.gz','967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99','https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz'),
 'mbedtls':('mbedtls-3.6.4.tar.bz2','ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110','https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.4/mbedtls-3.6.4.tar.bz2')}
GIT={
 'wolfssl':('wolfssl-5.8.2-stable','decea12e223869c8f8f3ab5a53dc90b69f436eb2','https://github.com/wolfSSL/wolfssl.git'),
 'bithac':('bithac','68ad825a37ef72cc1db4a67eb6d13275cc61f8aa','https://github.com/RWTH-SPICe/BiTHaC.git')}


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def call(argv,log,cwd=None):
    print(' '.join(map(str,argv)),flush=True)
    subprocess.run(list(map(str,argv)),cwd=cwd,stdout=log,stderr=subprocess.STDOUT,check=True)


def build(name,deps,cache,jobs,fetch):
    origin='wolfssl' if name=='mlkem' else name
    patches=[ROOT/f'implementations/{"wolfssl" if name=="mlkem" else name}/boundary.patch']
    if name=='mlkem':patches.append(ROOT/'implementations/mlkem/technique.patch')
    identity=dict(contract='turtle-message-dependency/1',name=name,patches={str(p.relative_to(ROOT)):sha(p) for p in patches})
    if origin in TARBALLS:
        filename,digest,url=TARBALLS[origin]
        archive=cache/'downloads'/filename
        if not archive.exists() and fetch:
            archive.parent.mkdir(parents=True,exist_ok=True)
            with urllib.request.urlopen(url,timeout=60) as response:archive.write_bytes(response.read())
        if not archive.is_file() or sha(archive)!=digest:raise RuntimeError(f'fixed archive unavailable: {archive}')
        identity.update(origin=url,archive_sha256=digest)
    else:
        dirname,commit,url=GIT[origin]
        repository=cache/'src'/dirname
        if not repository.exists() and fetch:
            subprocess.run(['git','clone','--no-checkout',url,str(repository)],check=True)
        observed=subprocess.check_output(['git','-C',str(repository),'rev-parse',commit+'^{commit}'],text=True).strip()
        if observed!=commit:raise RuntimeError('source commit mismatch')
        archive=deps/'archives'/(origin+'-'+commit+'.tar')
        archive.parent.mkdir(parents=True,exist_ok=True)
        if not archive.exists():subprocess.run(['git','-C',str(repository),'archive','--format=tar','--prefix=upstream/',commit,'-o',str(archive)],check=True)
        identity.update(origin=url,commit=commit,archive_sha256=sha(archive))
    source=deps/'message-src'/name
    stamp=source/'turtle-source.json'
    if not stamp.exists():
        if source.exists():raise RuntimeError(f'unowned source directory: {source}; choose a clean --deps directory')
        source.mkdir(parents=True)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                parts=Path(member.name).parts
                if len(parts)<2:continue
                member.name=str(Path(*parts[1:]))
                tar.extract(member,source,filter='data')
        for patch in patches:
            with patch.open('rb') as data:subprocess.run(['patch','-p1','--batch'],cwd=source,stdin=data,check=True,stdout=subprocess.DEVNULL)
        if name=='mbedtls':shutil.copyfile(ROOT/'implementations/mbedtls/boundary.h',source/'library/turtle_boundary.h')
        stamp.write_text(json.dumps(identity,indent=2)+'\n')
    elif json.loads(stamp.read_text())!=identity:raise RuntimeError('source or patch changed; choose a clean dependency directory')
    if name=='mbedtls':shutil.copyfile(ROOT/'implementations/mbedtls/boundary.h',source/'library/turtle_boundary.h')
    logs=deps/'logs';logs.mkdir(exist_ok=True)
    with (logs/(name+'.log')).open('w') as log:
        if name=='openssl':
            if not (source/'Makefile').exists():call(['./Configure','no-shared','no-tests','--libdir=lib','-g'],log,source)
            call(['make',f'-j{jobs}'],log,source)
        else:
            variants=['c','avx2'] if name=='mlkem' else ['baseline','cached'] if name=='bithac' else ['']
            for variant in variants:
                builddir=deps/'message-build'/(name+('-'+variant if variant else ''))
                args=['cmake','-S',source,'-B',builddir,'-G','Ninja','-DCMAKE_BUILD_TYPE=RelWithDebInfo','-DBUILD_SHARED_LIBS=OFF']
                if name=='mbedtls':args+=['-DENABLE_TESTING=OFF','-DENABLE_PROGRAMS=OFF','-DUSE_SHARED_MBEDTLS_LIBRARY=OFF']
                else:
                    flags='-DWOLFSSL_GETRANDOM -Wno-error=stringop-overflow'
                    if variant=='cached':flags+=' -DWOLFSSL_CACHED_INFO -DWOLFSSL_SSC'
                    args+=['-DWOLFSSL_EXAMPLES=no','-DWOLFSSL_CRYPT_TESTS=no','-DWOLFSSL_TLS13=yes','-DWOLFSSL_ECC=yes','-DWOLFSSL_OPENSSLEXTRA=yes','-DWOLFSSL_SNI=yes','-DWOLFSSL_SESSION_TICKET=yes','-DCMAKE_C_FLAGS='+flags]
                    if name=='mlkem':args+=['-DWOLFSSL_EXPERIMENTAL=yes','-DWOLFSSL_MLKEM=yes','-DTURTLE_MLKEM_AVX2='+('ON' if variant=='avx2' else 'OFF')]
                call(args,log)
                call(['cmake','--build',builddir,'-j',str(jobs)],log)
    libraries={str(p.relative_to(deps)):sha(p) for p in (list(source.glob('*.a')) if name=='openssl' else list((deps/'message-build').glob(name+'*/**/*.a')))}
    identity['auxiliary_headers']={'implementations/mbedtls/boundary.h':sha(ROOT/'implementations/mbedtls/boundary.h')} if name=='mbedtls' else {}
    identity.update(libraries=libraries,compiler=subprocess.check_output(['cc','--version'],text=True),source_manifest=str(stamp),build_log=str(logs/(name+'.log')))
    (deps/(name+'-manifest.json')).write_text(json.dumps(identity,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('names',nargs='*',default=['openssl','mbedtls','wolfssl','mlkem','bithac']);p.add_argument('--deps',type=Path,default=ROOT/'.deps-message');p.add_argument('--cache',type=Path,default=ROOT/'.deps');p.add_argument('--jobs',type=int,default=4);p.add_argument('--fetch',action='store_true');a=p.parse_args()
    a.deps=a.deps.resolve();a.cache=a.cache.resolve();a.deps.mkdir(parents=True,exist_ok=True)
    for n in a.names:build(n,a.deps,a.cache,a.jobs,a.fetch)
