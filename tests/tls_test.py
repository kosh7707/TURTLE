#!/usr/bin/env python3
"""실제 TLS 엔드포인트의 정상 실행과 새 사건 대응을 검증합니다."""
import shutil
import argparse,hashlib,itertools,json,pathlib,socket,ssl,subprocess,sys,tempfile,threading,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from run import run,port
from report import summarize
LIBS=['openssl','mbedtls','wolfssl']
SCENARIOS=['handshake','server-ping','finished-ping','client-request']

def check(path,scenario):
    report=summarize(path,path/'report')
    for e in report['endpoints']:
        assert e['manifest']['success']
        assert e['listener_preparation_ns'] is not None
        assert e['listener_preparation_ns']==0 if e['manifest']['role']=='client' else e['listener_preparation_ns']>=0
        for c in e['connections']:
            assert c['valid']
            assert (c['first_use_ns'] is not None)==(c['connection_id']==1)
            r=json.loads((path/e['manifest']['role']/f'{c["connection_id"]}.result.json').read_text())
            assert r['full_handshake']
            if e['manifest']['role']=='client' or e['manifest']['mutual_auth']:assert r['peer_verified'] and r['peer_certificate']
            if e['manifest']['depth']=='white-box':
                assert c['breakdown']['framework_remaining']>=0
                assert all(m['records'] for m in c['messages'])
                if e['manifest']['role']=='server' and scenario in ('finished-ping','server-ping'):
                    finished=next(m for m in c['messages'] if m['outgoing'] and m['type']==20)
                    ping=next(m for m in c['messages'] if m['outgoing'] and m['type']==256)
                    batches={r['id']:r['batch_id'] for r in c['records'] if r['outgoing']}
                    assert (batches[finished['records'][-1]]==batches[ping['records'][0]])==(scenario=='finished-ping')
    for c in report['endpoints'][0]['connections']:
        n=c['connection_id']
        assert (path/'client'/f'{n}.tx.plain.bin').read_bytes()==(path/'server'/f'{n}.rx.plain.bin').read_bytes()
        assert (path/'server'/f'{n}.tx.plain.bin').read_bytes()==(path/'client'/f'{n}.rx.plain.bin').read_bytes()
        assert (path/'client'/f'{n}.tx.bin').read_bytes()==(path/'server'/f'{n}.rx.bin').read_bytes()
        assert (path/'server'/f'{n}.tx.bin').read_bytes()==(path/'client'/f'{n}.rx.bin').read_bytes()
    return report


def matrix(a,root):
    total=0
    for client,server,scenario,auth,depth,records,send in itertools.product(LIBS,LIBS,SCENARIOS,[False,True],['black-box','white-box'],['preserve','bundle'],['flight','server-hello-first']):
        path=run(a.build,a.pki,root/f'{total:04d}',client,server,scenario=scenario,mutual_auth=auth,depth=depth,records=records,send=send,record_size=237,io_chunk=137,stream=True)
        check(path,scenario);total+=1
    padded=run(a.build,a.pki,root/'clienthello-override','openssl-padded','mbedtls',stream=True,depth='white-box',mutual_auth=True)
    check(padded,'client-request')
    tx=(padded/'client/1.tx.bin').read_bytes();assert b'\x00\x15\x00\x10'+bytes(16) in tx
    large=root/'large-pki'
    import os
    subprocess.run([str(ROOT/'scripts/make-pki.sh'),str(large),'ecdsa','3'],env=dict(os.environ,CERT_PADDING='32768'),check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for client,server in [('openssl','mbedtls'),('mbedtls','wolfssl'),('wolfssl','openssl')]:
        path=run(a.build,large,root/f'large-{client}',client,server,stream=True,depth='white-box',mutual_auth=True,allocations=True,client_bytes=62003,server_bytes=64007,record_size=127,io_chunk=257,records='bundle')
        report=check(path,'client-request')
        assert all(any(m['type']==11 and m['plain_bytes']>32768 for m in e['connections'][0]['messages']) for e in report['endpoints'])
    for client,server in [('openssl','mbedtls'),('mbedtls','wolfssl'),('wolfssl','openssl')]:
        p=run(a.build,large,root/f'full-record-{client}',client,server,stream=True,depth='white-box',mutual_auth=True,client_bytes=62003,server_bytes=64007,records='bundle')
        check(p,'client-request')
    for lib in ('mlkem-c','mlkem-avx2','bithac-baseline','bithac-cached'):
        p=run(a.build,large,root/f'large-{lib}',lib,lib,stream=True,depth='white-box',mutual_auth=True,connections=3,records='bundle',group='ML-KEM-768' if lib.startswith('mlkem') else 'P-256')
        check(p,'client-request')
    credentials=root/'role-credentials';(credentials/'client').mkdir(parents=True);(credentials/'server').mkdir()
    shutil.copyfile(pathlib.Path(a.pki)/'ca.pem',credentials/'client/ca.pem')
    for name in ('server-chain.pem','server.key'):shutil.copyfile(pathlib.Path(a.pki)/name,credentials/'server'/name)
    for lib in LIBS:
        p=run(a.build,a.pki,root/f'required-credentials-{lib}',lib,lib,stream=True,role_options={r:dict(pki=str(credentials/r)) for r in ('client','server')})
        report=check(p,'client-request')
        assert [e['manifest']['credential_preparation'] for e in report['endpoints']]==['trust-only','local-identity-only']
        assert report['endpoints'][0]['manifest']['credentials']['client-chain.pem']==dict(status='missing',bytes=None,sha256=None)
        assert report['endpoints'][1]['manifest']['credentials']['ca.pem']==dict(status='missing',bytes=None,sha256=None)
    return dict(normal_matrix=total,clienthello_override=1,large_message_cross_pairs=6,large_message_research=4,role_specific_credentials=3)


def research(a,root):
    rows=[]
    for lib in ['mlkem-c','mlkem-avx2','bithac-baseline','bithac-cached']:
        for scenario,auth,depth in itertools.product(SCENARIOS,[False,True],['black-box','white-box']):
            path=run(a.build,a.pki,root/f'{len(rows):04d}',lib,lib,scenario=scenario,mutual_auth=auth,depth=depth,stream=True,connections=3,group='ML-KEM-768' if lib.startswith('mlkem') else 'P-256')
            check(path,scenario)
            for role in ('client','server'):
                results=[json.loads((path/role/f'{n}.result.json').read_text()) for n in (1,2,3)]
                if lib.startswith('mlkem'):
                    for r in results:
                        assert r['keygen']==(1 if role=='client' else 0) and r['encapsulate']==(1 if role=='server' else 0) and r['decapsulate']==(1 if role=='client' else 0)
                        assert (r['optimized']>0)==(lib=='mlkem-avx2')
                if lib=='bithac-cached':assert [r['technique_used']!=0 for r in results]==[False,True,True]
            rows.append(str(path))
    # Same code base, opposite dispatch variants interoperate.
    for client,server in [('mlkem-c','mlkem-avx2'),('mlkem-avx2','mlkem-c')]:
        p=run(a.build,a.pki,root/client,client,server,group='ML-KEM-768',stream=True,depth='white-box',mutual_auth=True);check(p,'client-request')
    cross_cache=0
    for client,server,auth,depth in itertools.product(['bithac-baseline','bithac-cached'],['bithac-baseline','bithac-cached'],[False,True],['black-box','white-box']):
        if client==server:continue
        p=run(a.build,a.pki,root/f'cross-cache-{cross_cache}',client,server,connections=4,stream=True,depth=depth,mutual_auth=auth,timeout_ms=5000)
        check(p,'client-request')
        for role in ('client','server'):
            assert all(json.loads((p/role/f'{n}.result.json').read_text())['technique_used']==0 for n in range(1,5))
        cross_cache+=1
    return dict(research_runs=len(rows),cross_dispatch=2,cross_cache=cross_cache)


def payload(n,role):return bytes((i*17+(0x43 if role=='client' else 0x53))&255 for i in range(n))
def receive(s,n):
    b=b''
    while len(b)<n:
        part=s.recv(n-len(b))
        if not part:raise RuntimeError('external TLS closed early')
        b+=part
    return b


def external(a,root):
    tests=[]
    for lib,role,mutual in itertools.product(LIBS,['client','server'],[False,True]):
        p=root/f'{lib}-{role}-{mutual}';p.mkdir();number=port();ready=threading.Event();errors=[]
        other='server' if role=='client' else 'client'
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if other=='server' else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3;ctx.set_ecdh_curve('prime256v1');ctx.load_verify_locations(str(pathlib.Path(a.pki)/'ca.pem'))
        ctx.load_cert_chain(str(pathlib.Path(a.pki)/f'{other}-chain.pem'),str(pathlib.Path(a.pki)/f'{other}.key'))
        if other=='server':ctx.verify_mode=ssl.CERT_REQUIRED if mutual else ssl.CERT_NONE;ctx.num_tickets=0
        def peer():
            try:
                if other=='server':
                    with socket.socket() as listener:
                        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',number));listener.listen();ready.set();raw,_=listener.accept()
                else:
                    ready.wait(5);raw=socket.create_connection(('127.0.0.1',number),timeout=5)
                with ctx.wrap_socket(raw,server_side=other=='server',server_hostname='localhost' if other=='client' else None) as tls:
                    tls.settimeout(5);assert tls.version()=='TLSv1.3'
                    if other=='server':assert receive(tls,67)==payload(67,'client');tls.sendall(payload(79,'server'))
                    else:tls.sendall(payload(67,'client'));assert receive(tls,79)==payload(79,'server')
            except BaseException as error:errors.append(str(error));ready.set()
        thread=threading.Thread(target=peer);thread.start()
        config=dict(contract='turtle-message-run/1',run_id=str(uuid.uuid4()),output=str(p/'endpoint'),pki=str(pathlib.Path(a.pki).resolve()),port=number,external_peer=True,scenario='client-request',depth='white-box',mutual_auth=mutual,client_bytes=67,server_bytes=79)
        (p/'run.json').write_text(json.dumps(config));
        if other=='server':ready.wait(5)
        with (p/'endpoint.log').open('w') as log:
            process=subprocess.Popen([str(pathlib.Path(a.build)/f'turtle-{lib}-{role}'),str(p/'run.json')],stdout=log,stderr=subprocess.STDOUT)
            if other=='client':
                end=time.monotonic()+5
                while not (p/'endpoint/ready').exists() and process.poll() is None and time.monotonic()<end:time.sleep(.005)
                ready.set()
            code=process.wait(timeout=15)
        thread.join(timeout=10);assert not thread.is_alive() and not errors and code==0,(p,errors,(p/'endpoint.log').read_text())
        tests.append(dict(implementation=lib,role=role,mutual_auth=mutual))
    return dict(external_library=ssl.OPENSSL_VERSION,cases=tests)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('suite',choices=['matrix','research','external']);p.add_argument('--build',required=True);p.add_argument('--pki',required=True);p.add_argument('--output',required=True);a=p.parse_args();a.build=str(pathlib.Path(a.build).resolve());a.pki=str(pathlib.Path(a.pki).resolve())
    pathlib.Path(a.output).mkdir(parents=True,exist_ok=True);root=pathlib.Path(tempfile.mkdtemp(prefix=a.suite+'-',dir=a.output)).resolve()
    result=globals()[a.suite](a,root);(root/'verification.json').write_text(json.dumps(dict(contract='turtle-message-verification/1',suite=a.suite,**result),indent=2)+'\n');print(root,result)
