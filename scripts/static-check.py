#!/usr/bin/env python3
"""공개 계약, 부품 의존 방향과 실행 경로의 금지된 전체 핸드셰이크 호출을 검사합니다."""
import argparse,json,pathlib,re,subprocess,sys,tempfile,shlex
ROOT=pathlib.Path(__file__).resolve().parents[1]

def check():
    public=list((ROOT/'include/turtle').glob('*'))
    assert [p.name for p in public if p.is_file()]==['implementation.h'],'implementer surface contains legacy files'
    for p in (ROOT/'implementations').rglob('*'):
        if p.suffix not in ('.c','.h','.cpp','.hpp'):continue
        text=p.read_text()
        assert not re.search(r'#include\s*[<"](?:\.\./.*src/|(?:execution|socket|observation|journal|spec|allocation)/)',text),str(p)
        assert not re.search(r'\b(?:SSL_do_handshake|SSL_connect|SSL_accept|SSL_read|SSL_write|wolfSSL_connect|wolfSSL_accept|wolfSSL_read|wolfSSL_write|mbedtls_ssl_handshake(?:_step)?|mbedtls_ssl_read|mbedtls_ssl_write|send|recv|connect|accept|socket)\s*\(',text),str(p)
    graph={}
    for p in (ROOT/'src').rglob('*'):
        if p.suffix not in ('.cpp','.hpp'):continue
        name=p.relative_to(ROOT/'src').parts[0];graph.setdefault(name,set())
        for dependency in re.findall(r'#include\s*"([^"/]+)/[^"/]+"',p.read_text()):
            if dependency!=name:graph[name].add(dependency)
        assert not re.search(r'\b(?:SSL_|wolfSSL_|mbedtls_)\w*',p.read_text()),str(p)
        assert not re.search(r'\b(?:dlopen|dlsym)\s*\(',p.read_text()),str(p)
    def visit(name,path):
        assert name not in path,'component cycle: '+str(path+[name])
        for other in graph.get(name,[]):visit(other,path+[name])
    for name in graph:visit(name,[])
    for p in (ROOT/'scripts').glob('*.py'):compile(p.read_text(),str(p),'exec')
    return dict(contract='turtle-message-static-check/1',status='passed',dependencies={k:sorted(v) for k,v in graph.items()})

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build');p.add_argument('--output');a=p.parse_args();result=check()
    if a.build:
        commands=json.loads((pathlib.Path(a.build)/'compile_commands.json').read_text())
        selected={}
        for command in commands:
            if not command['file'].endswith(('.cpp','.c')):continue
            args=shlex.split(command['command']) if 'command' in command else command['arguments']
            # The endpoint translation unit is compiled for two roles, not once per linked backend.
            identity=(command['file'],tuple(arg for arg in args if arg.startswith(('-D','-I','-isystem'))))
            selected.setdefault(identity,command)
        checked=[]
        for command in selected.values():
            # clang-tidy 21 can crash when one file has many compile commands in the same invocation.
            # A one-command database preserves every actual configuration in a fresh process.
            with tempfile.TemporaryDirectory(prefix='turtle-tidy-') as directory:
                pathlib.Path(directory,'compile_commands.json').write_text(json.dumps([command]))
                subprocess.run(['clang-tidy','-p',directory,command['file'],'--quiet'],check=True)
            checked.append(command)
        result['clang_tidy_commands']=checked
    if a.output:pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
    print('component/source contract checks passed')
