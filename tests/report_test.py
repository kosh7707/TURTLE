import json,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from report import delta,stq,endpoint,summarize

class Contract(unittest.TestCase):
    def test_integer_and_unavailable(self):
        huge=2**63+1234
        self.assertEqual(delta(dict(begin=dict(monotonic_ns=huge),end=dict(monotonic_ns=huge+17))),17)
        self.assertIsNone(delta(dict(begin=dict(monotonic_ns=None),end=dict(monotonic_ns=None))))
        self.assertEqual(delta(dict(begin=dict(monotonic_ns=huge),end=dict(monotonic_ns=huge))),0)
    def test_stq_weights(self):
        self.assertEqual(stq([8,7,6,5,4,3,2,1]),dict(count=8,minimum=1,maximum=8,stq1=2.5,stq2=4.5,stq3=6.5))
        self.assertEqual(stq([19])['stq2'],19)
    def test_shared_record_and_exact_costs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            manifest=dict(contract='turtle-message-manifest/1',run_id='run',context_id='context',role='client',connections=1,warmups=0,success=True,depth='white-box',lookup=dict(enabled=False))
            (root/'manifest.json').write_text(json.dumps(manifest))
            events=[]
            def event(kind,start,end,**kw):
                e=dict(contract='turtle-message-events/1',run_id='run',context_id='context',role='client',sequence=len(events)+1,kind=kind,connection_id=1,begin=None if start is None else dict(monotonic_ns=2**63+start),end=None if end is None else dict(monotonic_ns=2**63+end),detail=0,message_id=0,record_id=0,batch_id=1,type=11,outgoing=True,plain_offset=0,plain_bytes=0,stream_offset=0,bytes=0);e.update(kw);events.append(e)
            event('framework-preparation',0,0,connection_id=0);event('context',0,10,connection_id=0);event('connection',10,15);event('transport',15,17);event('scenario',20,100);event('protect',21,30,record_id=1);event('send',30,40);event('batch',30,40,bytes=27)
            event('message',None,None,message_id=1,plain_bytes=8);event('message',None,None,message_id=2,plain_offset=8,plain_bytes=12)
            event('record',None,None,record_id=1,plain_bytes=20,bytes=27)
            (root/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
            r=endpoint(root);c=r['connections'][0]
            self.assertEqual(c['first_use_ns'],97)
            self.assertEqual(c['breakdown'],dict(protect=9,send=10,framework_remaining=61))
            self.assertEqual(c['records'][0]['messages'],[1,2]);self.assertTrue(all(m['records']==[1] for m in c['messages']))
            self.assertEqual(c['protocol_ns'],80)
            self.assertEqual(c['records'][0]['operation_ns'],9)
            self.assertTrue(all(m['direct_stage_costs']=={} for m in c['messages']))
    def test_preparation_and_missing_are_not_zero(self):
        for role in ('client','server'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                root=pathlib.Path(tmp)
                manifest=dict(contract='turtle-message-manifest/1',run_id='run',context_id='context',role=role,connections=2,warmups=0,success=True,depth='black-box',lookup=dict(enabled=False))
                (root/'manifest.json').write_text(json.dumps(manifest))
                rows=[];clock=2**63
                def event(kind,duration,connection=0):
                    nonlocal clock
                    rows.append(dict(contract='turtle-message-events/1',run_id='run',context_id='context',role=role,kind=kind,connection_id=connection,begin=dict(monotonic_ns=clock),end=dict(monotonic_ns=clock+duration),detail=0))
                    clock+=duration
                event('framework-preparation',7)
                if role=='server':event('listener-preparation',5)
                event('context',10)
                for connection in (1,2):
                    event('transport',2,connection);event('connection',3,connection);event('scenario',100,connection)
                def report(events):
                    (root/'events.jsonl').write_text(''.join(json.dumps(dict(e,sequence=i))+'\n' for i,e in enumerate(events,1)))
                    return endpoint(root)
                complete=report(rows)
                self.assertEqual(complete['listener_preparation_ns'],5 if role=='server' else 0)
                self.assertEqual(complete['connections'][0]['first_use_ns'],127 if role=='server' else 122)
                self.assertIsNone(complete['connections'][1]['first_use_ns'])
                for kind in ['framework-preparation','transport']+(['listener-preparation'] if role=='server' else []):
                    missing=report([e for e in rows if e['kind']!=kind])
                    self.assertIsNone(missing['connections'][0]['first_use_ns'])
                    self.assertEqual(missing['connections'][0]['protocol_ns'],100)
    def test_only_current_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp);(p/'manifest.json').write_text('{"schema":3}')
            with self.assertRaisesRegex(ValueError,'unsupported manifest'):endpoint(p)

if __name__=='__main__':unittest.main()
