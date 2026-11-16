#!/usr/bin/env python3
"""배치 안에서 저장한 seed로 실행 순서를 섞고 독립 프로세스·컨텍스트를 수집합니다."""
import argparse,itertools,json,pathlib,random
from run import run
from report import summarize


def study(plan,build,pki,output):
    if plan.get('contract')!='turtle-message-study-plan/1':raise ValueError('unsupported study plan')
    root=pathlib.Path(output);root.mkdir(parents=True,exist_ok=False)
    rng=random.Random(plan['seed']);schedule=[]
    for batch in range(plan['batches']):
        items=[dict(batch=batch,replicate=r,case=c) for r,c in itertools.product(range(plan['samples']),plan['cases'])]
        rng.shuffle(items)
        for item in items:item.update(path=f'run-{len(schedule)+1:05d}',status='scheduled');schedule.append(item)
    ledger=dict(contract='turtle-message-study/1',seed=plan['seed'],plan=plan,runs=schedule)
    def save():(root/'study.json').write_text(json.dumps(ledger,indent=2)+'\n')
    save()
    for item in schedule:
        case=item['case'];options=dict(plan.get('options',{}));options.update(case.get('options',{}));options['seed']=plan['seed']
        item['status']='running';save()
        try:
            run(build,pki,root/item['path'],client=case['client'],server=case['server'],**options)
            item['status']='complete'
        except Exception as error:item.update(status='failed',reason=str(error))
        save()
    return summarize(root,root/'report')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('plan');p.add_argument('--build',default='build-message');p.add_argument('--pki',default='pki/default');p.add_argument('--output',required=True);a=p.parse_args();study(json.loads(pathlib.Path(a.plan).read_text()),a.build,a.pki,a.output)
