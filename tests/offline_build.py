#!/usr/bin/env python3
"""외부 네트워크가 없는 소유 네임스페이스에서 의존성부터 새로 빌드·시험·분석합니다."""
import argparse,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',required=True);p.add_argument('--parent-inode',required=True,type=int);p.add_argument('--cache',default=str(ROOT/'.deps'));p.add_argument('--pki',default=str(ROOT/'pki/default'));a=p.parse_args()
    if os.stat('/proc/self/ns/net').st_ino==a.parent_inode:raise RuntimeError('an owned, separate network namespace is required')
    links=json.loads(subprocess.check_output(['ip','-j','link','show'],text=True))
    if len(links)!=1 or links[0]['ifname']!='lo':raise RuntimeError('external interfaces must be absent')
    subprocess.run(['ip','link','set','lo','up'],check=True)
    work=pathlib.Path(a.work).resolve();work.mkdir(parents=True,exist_ok=False)
    build=work/'source';deps=work/'deps';tests=work/'tests'
    evidence=dict(contract='turtle-message-offline-verification/1',network_namespace_inode=os.stat('/proc/self/ns/net').st_ino,parent_namespace_inode=a.parent_inode,initial_links=links,network_fetch=False,steps=[],status='running')
    def save():(work/'verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
    def execute(name,argv,env=None):
        row=dict(name=name,argv=list(map(str,argv)),begin_ns=time.monotonic_ns());evidence['steps'].append(row);save()
        with (work/(name+'.log')).open('w') as log:
            result=subprocess.run(list(map(str,argv)),cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env=env)
        row.update(returncode=result.returncode,end_ns=time.monotonic_ns());save()
        if result.returncode:raise RuntimeError(name+' failed; see '+str(work/(name+'.log')))
        print(name,'passed',flush=True)
    try:
        execute('dependencies',[sys.executable,ROOT/'scripts/dependencies.py','--deps',deps,'--cache',a.cache])
        execute('source-build',[ROOT/'scripts/build.sh'],dict(os.environ,TURTLE_BUILD_DIR=str(build),TURTLE_DEPS_ROOT=str(deps)))
        execute('test-configure',['cmake','-S',ROOT/'tests','-B',tests,'-G','Ninja','-DTURTLE_SOURCE_BUILD='+str(build),'-DTURTLE_PKI='+str(pathlib.Path(a.pki).resolve())])
        execute('test-build',['cmake','--build',tests,'-j','4'])
        execute('ctest',['ctest','--test-dir',tests,'--output-on-failure'])
        execute('static',[sys.executable,ROOT/'scripts/static-check.py','--build',build,'--output',work/'static.json'])
        execute('objects',[sys.executable,ROOT/'scripts/verify-mlkem-build.py','--deps',deps,'--output',work/'mlkem-objects.json'])
        execute('run',[sys.executable,ROOT/'scripts/run.py','--build',build,'--pki',a.pki,'--output',work/'run'])
        execute('analysis',[sys.executable,ROOT/'scripts/report.py',work/'run',work/'report'])
        evidence['status']='passed'
    except Exception as error:evidence.update(status='failed',reason=str(error));raise
    finally:save()

if __name__=='__main__':main()
