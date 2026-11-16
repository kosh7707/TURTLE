#!/usr/bin/env python3
"""새 사건 계약만 읽고 클라이언트·서버의 컨텍스트별 비용과 연결 위치를 보고합니다."""
import argparse
import collections
import csv
import itertools
import json
import pathlib
import random
from fractions import Fraction

CONTRACT = 'turtle-message-events/1'
LEAF = {'transition', 'assemble', 'process', 'protect', 'unprotect', 'send', 'receive', 'wait', 'verify'}
CONDITION = ['scenario', 'mutual_auth', 'group', 'depth', 'records', 'send', 'record_size',
             'connections', 'warmups', 'client_bytes', 'server_bytes', 'observation', 'network_condition', 'lookup', 'credentials', 'credential_preparation']


def read(path):
    return json.loads(pathlib.Path(path).read_text())


def delta(event, metric='monotonic_ns'):
    if event['begin'] is None or event['end'] is None:
        return None
    a, b = event['begin'].get(metric), event['end'].get(metric)
    if a is None or b is None:
        return None
    if not isinstance(a, int) or not isinstance(b, int) or b < a:
        raise ValueError('noninteger or reversed measurement')
    return b-a


def stq(values):
    values = sorted(values)
    if not values:
        return None
    n = len(values)
    def weighted(first, last):
        return float(sum(Fraction(v)*max(0, min(8*(i+1), last*n)-max(8*i, first*n))
                         for i, v in enumerate(values))/((last-first)*n))
    return dict(count=n, minimum=values[0], maximum=values[-1],
                stq1=weighted(1, 3), stq2=weighted(3, 5), stq3=weighted(5, 7))


def overlap(a, an, b, bn):
    return max(a, b) < min(a+an, b+bn)


def endpoint(directory):
    directory = pathlib.Path(directory)
    m = read(directory/'manifest.json')
    if m.get('contract') != 'turtle-message-manifest/1':
        raise ValueError('unsupported manifest contract: '+str(directory))
    events = [json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    for i, e in enumerate(events, 1):
        if e.get('contract') != CONTRACT or e['sequence'] != i or e['context_id'] != m['context_id'] or e['run_id'] != m['run_id'] or e['role'] != m['role']:
            raise ValueError('event identity or contract mismatch')
    ctx = [e for e in events if e['kind'] == 'context']
    if len(ctx) != 1:
        raise ValueError('exactly one context preparation event is required')
    lookup = [e for e in events if e['kind'] == 'lookup']
    infrastructure=[e for e in events if e['kind']=='framework-preparation']
    listener=[e for e in events if e['kind']=='listener-preparation']
    def preparation_cost(items, expected):
        if len(items)!=expected:return None
        values=[delta(e) for e in items]
        return sum(values) if all(v is not None for v in values) else None
    lookup_cost=preparation_cost(lookup, int(m['lookup']['enabled']))
    infrastructure_cost=preparation_cost(infrastructure, 1)
    listener_cost=preparation_cost(listener, int(m['role']=='server'))
    preparation_parts=[delta(ctx[0]), lookup_cost, infrastructure_cost, listener_cost]
    preparation=sum(preparation_parts) if all(v is not None for v in preparation_parts) else None
    rows = []
    for connection in range(1, m['connections']+m['warmups']+1):
        es = [e for e in events if e['connection_id'] == connection]
        scenarios = [e for e in es if e['kind'] == 'scenario']
        setup = [e for e in es if e['kind'] == 'connection']
        transport=[e for e in es if e['kind']=='transport']
        valid = m['success'] and len(scenarios) == 1 and scenarios[0]['detail'] == 0 and len(setup) == 1
        row = dict(connection_id=connection, position=connection-m['warmups'],
                   warmup=connection<=m['warmups'], valid=valid,
                   protocol_ns=delta(scenarios[0]) if valid else None,
                   thread_cpu_ns=delta(scenarios[0], 'thread_cpu_ns') if valid else None,
                   connection_preparation_ns=delta(setup[0]) if len(setup)==1 else None,
                   transport_ns=delta(transport[0]) if len(transport)==1 else None,
                   cycles=delta(scenarios[0],'cycles') if valid else None, instructions=delta(scenarios[0],'instructions') if valid else None,
                   perf_time_enabled=delta(scenarios[0],'time_enabled') if valid else None, perf_time_running=delta(scenarios[0],'time_running') if valid else None,
                   allocation=dict(begin=scenarios[0]['begin'].get('allocation'),end=scenarios[0]['end'].get('allocation')) if valid and scenarios[0]['end'].get('allocation') is not None else None,
                   first_use_ns=None, breakdown=None, messages=[], records=[], batches=[])
        if valid and connection == 1:
            costs=[preparation, row['connection_preparation_ns'], row['protocol_ns'], row['transport_ns']]
            if all(cost is not None for cost in costs):row['first_use_ns'] = sum(costs)
        if valid and m['depth'] == 'white-box':
            parts = collections.defaultdict(int)
            for e in es:
                if e['kind'] in LEAF:
                    parts[e['kind']] += delta(e)
            parts['framework_remaining'] = row['protocol_ns']-sum(parts.values())
            if parts['framework_remaining'] < 0:
                raise ValueError('leaf costs overlap or exceed scenario interval')
            row['breakdown'] = dict(parts)
            messages = [e for e in es if e['kind'] == 'message']
            records = [e for e in es if e['kind'] == 'record']
            for e in messages:
                linked = [r['record_id'] for r in records if r['outgoing'] == e['outgoing'] and overlap(r['plain_offset'], r['plain_bytes'], e['plain_offset'], e['plain_bytes'])]
                direct={}
                for phase in ('assemble','process','transition'):
                    operations=[op for op in es if op['kind']==phase and op['message_id']==e['message_id']]
                    if not operations:continue
                    costs={}
                    for metric in ('monotonic_ns','thread_cpu_ns','cycles','instructions'):
                        values=[delta(op,metric) for op in operations]
                        costs[metric]=sum(values) if all(v is not None for v in values) else None
                    direct[phase]=costs
                row['messages'].append(dict(id=e['message_id'], type=e['type'], outgoing=e['outgoing'],
                                            plain_offset=e['plain_offset'], plain_bytes=e['plain_bytes'], records=linked,direct_stage_costs=direct))
            for r in records:
                linked = [e['message_id'] for e in messages if e['outgoing'] == r['outgoing'] and overlap(r['plain_offset'], r['plain_bytes'], e['plain_offset'], e['plain_bytes'])]
                operations=[op for op in es if op['kind'] in ('protect','unprotect') and op['record_id']==r['record_id']]
                if len(operations)!=1:raise ValueError('record must have exactly one protection operation')
                row['records'].append(dict(id=r['record_id'], outgoing=r['outgoing'], stream_offset=r['stream_offset'], bytes=r['bytes'], messages=linked, batch_id=r['batch_id'] or None,operation_ns=delta(operations[0])))
            row['batches'] = [dict(id=e['batch_id'], stream_offset=e['stream_offset'], bytes=e['bytes'], submission_ns=delta(e)) for e in es if e['kind']=='batch']
        rows.append(row)
    return dict(manifest=m, context_preparation_ns=delta(ctx[0]), lookup_preparation_ns=lookup_cost,
                framework_preparation_ns=infrastructure_cost,listener_preparation_ns=listener_cost,
                preparation_ns=preparation, connections=rows)


def summarize(input_dir, output_dir, bootstrap=1000):
    root = pathlib.Path(input_dir)
    study_path = root/'study.json'
    if study_path.exists():
        study = read(study_path)
        if study.get('contract') != 'turtle-message-study/1':
            raise ValueError('unsupported study contract')
        runs = [(root/r['path'], r) for r in study['runs']]
        seed = study['seed']
    else:
        runs, seed = [(root, dict(batch=0, path='.',status="complete"))], 1
    endpoints, failures = [], []
    incomplete_batches={s["batch"] for _,s in runs if s.get("status")!="complete"}
    for run, schedule in runs:
        pair = []
        for role in ('client', 'server'):
            try:
                pair.append(endpoint(run/role))
            except (FileNotFoundError, ValueError) as error:
                failures.append(dict(path=str(run/role), reason=str(error)))
        if len(pair) != 2:
            incomplete_batches.add(schedule["batch"])
            continue
        if pair[0]['manifest']['run_id'] != pair[1]['manifest']['run_id']:
            raise ValueError('client/server run identity mismatch')
        for i, e in enumerate(pair):
            e['batch'] = schedule['batch']
            e['peer_implementation'] = pair[1-i]['manifest']['implementation']
            e['pair_success'] = all(x['manifest']['success'] for x in pair)
            if not e['pair_success']:incomplete_batches.add(schedule['batch'])
            endpoints.append(e)
    ids = [e['manifest']['context_id'] for e in endpoints]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate context; independent sample would be counted twice')
    groups = {}
    flat = []
    for e in endpoints:
        m=e['manifest']
        condition={k:m[k] for k in CONDITION}
        condition.update(role=m['role'], peer=e['peer_implementation'], batch=e['batch'])
        for row in e['connections']:
            flat.append(dict(run_id=m['run_id'], context_id=m['context_id'], role=m['role'], implementation=m['implementation'], connection_id=row['connection_id'], warmup=row['warmup'], protocol_ns=row['protocol_ns'], first_use_ns=row['first_use_ns']))
            if row['warmup'] or not row['valid'] or not e['pair_success']:
                continue
            key=json.dumps(dict(condition, implementation=m['implementation'], position=row['position']), sort_keys=True)
            groups.setdefault(key, []).append((m['context_id'], row['protocol_ns']))
    distributions=[]
    for key, values in groups.items():
        distributions.append(dict(condition=json.loads(key), context_ids=[x[0] for x in values], values_ns=[x[1] for x in values], statistics=stq([x[1] for x in values])))
    comparisons=[]
    rng=random.Random(seed)
    for a,b in itertools.combinations(distributions,2):
        ac,bc=dict(a['condition']),dict(b['condition'])
        ai,bi=ac.pop('implementation'),bc.pop('implementation')
        if ai==bi or ac!=bc:
            continue
        av,bv=a['values_ns'],b['values_ns']
        if ac['batch'] in incomplete_batches:
            comparisons.append(dict(a=ai,b=bi,condition=ac,status='incomplete-scheduled-batch'));continue
        if ac['observation']['cpu_samples']!='not-collected' or ac['observation']['allocation']=='missing':
            comparisons.append(dict(a=ai,b=bi,condition=ac,status='separate-collection-or-missing-observation'));continue
        if min(len(av),len(bv))<2:
            comparisons.append(dict(a=ai,b=bi,condition=ac,status='insufficient-independent-contexts'))
            continue
        diffs=sorted(stq(rng.choices(bv,k=len(bv)))['stq2']-stq(rng.choices(av,k=len(av)))['stq2'] for _ in range(bootstrap))
        comparisons.append(dict(a=ai,b=bi,condition=ac,status='exploratory',resampling_unit='independent-process-context-at-fixed-connection-position',
                                difference_ns=stq(bv)['stq2']-stq(av)['stq2'],seed=seed,repetitions=bootstrap,
                                percentile_95_ns=[diffs[int(.025*(bootstrap-1))],diffs[int(.975*(bootstrap-1))]]))
    repeated={}
    for e in endpoints:
        m=e['manifest'];rows=[r for r in e['connections'] if not r['warmup']]
        if not e['pair_success'] or not rows or not all(r['valid'] for r in rows):continue
        condition={k:m[k] for k in CONDITION};condition.update(role=m['role'],implementation=m['implementation'],peer=e['peer_implementation'],batch=e['batch'])
        key=json.dumps(condition,sort_keys=True)
        repeated.setdefault(key,[]).append(dict(context_id=m['context_id'],connections=len(rows),representative_ns=stq([r['protocol_ns'] for r in rows])['stq2']))
    repeated_distributions=[dict(condition=json.loads(k),contexts=v,statistics=stq([r['representative_ns'] for r in v])) for k,v in repeated.items()]
    report=dict(contract='turtle-message-report/1', sample_unit='independent-process-context', endpoints=endpoints,
                failures=failures,distributions=distributions,comparisons=comparisons,repeated_context_distributions=repeated_distributions,
                attribution='records and I/O are counted once; message links do not apportion shared cost')
    out=pathlib.Path(output_dir);out.mkdir(parents=True,exist_ok=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    if flat:
        with (out/'connections.csv').open('w',newline='') as file:
            writer=csv.DictWriter(file,fieldnames=list(flat[0]));writer.writeheader();writer.writerows(flat)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input');p.add_argument('output');a=p.parse_args();summarize(a.input,a.output)
