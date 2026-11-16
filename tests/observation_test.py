#!/usr/bin/env python3
"""합성 객체 서비스·고정 저장본과 컨텍스트 준비 비용을 실제 TLS로 검증합니다."""
import argparse,hashlib,json,pathlib,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from run import run,port
from report import summarize

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',required=True);p.add_argument('--pki',required=True);p.add_argument('--output',required=True);a=p.parse_args();pathlib.Path(a.output).mkdir(parents=True,exist_ok=True);root=pathlib.Path(tempfile.mkdtemp(prefix='observations-',dir=a.output)).resolve()
    obj=root/'object.bin';obj.write_bytes(bytes(range(256))*64);number=port();digest=hashlib.sha256(obj.read_bytes()).hexdigest()
    service=subprocess.Popen([sys.executable,str(ROOT/'scripts/mockca.py'),str(obj),str(root/'service'),'--port',str(number)])
    try:
        deadline=time.monotonic()+5
        while not (root/'service/ready').exists():
            if service.poll() is not None or time.monotonic()>deadline:raise RuntimeError('service startup')
            time.sleep(.01)
        for mode in ('query','snapshot'):
            options=dict(lookup_port=number,lookup_size=obj.stat().st_size,lookup_sha256=digest,connections=2,warmups=1,depth='white-box',allocations=True,perf_counters=True)
            if mode=='snapshot':options['lookup_snapshot']=str(obj)
            run(a.build,a.pki,root/mode,client='wolfssl',server='mbedtls',**options)
            report=summarize(root/mode,root/mode/'report')
            for endpoint in report['endpoints']:
                assert endpoint['lookup_preparation_ns']>0
                assert endpoint['connections'][0]['first_use_ns'] is not None
                assert all(c['first_use_ns'] is None for c in endpoint['connections'][1:])
                assert endpoint['connections'][0]['warmup']
                assert all(c['valid'] for c in endpoint['connections'])
                assert endpoint['manifest']['observation']['allocation']=='available'
            assert all(g['statistics']['count']==1 for g in report['distributions'])
    finally:
        service.terminate();service.wait(timeout=6)
    events=[json.loads(line) for line in (root/'service/events.jsonl').read_text().splitlines()]
    manifest=json.loads((root/'query/client/manifest.json').read_text())
    assert len(events)==2 and all(e['run_id']==manifest['run_id'] for e in events)
    assert {e['requester_role'] for e in events}=={'client','server'}
    (root/'verification.json').write_text(json.dumps(dict(contract='turtle-message-verification/1',query=True,snapshot=True,service_requests=len(events)),indent=2)+'\n')
    print(root)
