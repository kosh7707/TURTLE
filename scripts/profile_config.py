"""실험 프로필의 세 책임을 구성하고 엔드포인트 입력으로 투영합니다."""
from copy import deepcopy

SCENARIO_MEASUREMENT = {'connections', 'warmups', 'seed', 'timeout_ms', 'flush_grace_ms'}
EXPERIMENT_MEASUREMENT = {'samples', 'failure_policy', 'runner_cpu', 'client_cpu', 'server_cpu', 'ca_cpu', 'batch'}
CREDENTIALS = {'ca_file', 'client_certificate', 'client_key', 'server_certificate', 'server_key', 'framework_io'}


def experiment_profile(*, name='default', tls=None, measurement=None, socket=None, lookup=None,
                       pki=None, technique=None):
    """프로필 작성용 함수. 파일 판독의 과거 형식 호환 경로는 제공하지 않습니다."""
    tls, measurement = deepcopy(tls or {}), deepcopy(measurement or {})
    scenario = {'tls': {k: v for k, v in tls.items() if k not in CREDENTIALS},
                'measurement': {k: v for k, v in measurement.items() if k in SCENARIO_MEASUREMENT}}
    endpoint = {'tls': {k: v for k, v in tls.items() if k in CREDENTIALS},
                'measurement': {k: v for k, v in measurement.items()
                                if k not in SCENARIO_MEASUREMENT | EXPERIMENT_MEASUREMENT}}
    for key, value in (('pki', pki), ('socket', socket), ('lookup', lookup), ('technique', technique)):
        if value is not None: endpoint[key] = deepcopy(value)
    return {'type': 'turtle-experiment-profile', 'schema': 1, 'name': name,
            'scenario': scenario, 'endpoint': endpoint,
            'experiment': {k: v for k, v in measurement.items() if k in EXPERIMENT_MEASUREMENT}}


def flatten_experiment(document):
    if document.get('type') != 'turtle-experiment-profile' or document.get('schema') != 1:
        raise ValueError('expected turtle-experiment-profile schema 1')
    if set(document) - {'type', 'schema', 'name', 'scenario', 'endpoint', 'experiment', 'endpoints'}:
        raise ValueError('unknown experiment profile section')
    result = deepcopy(document.get('endpoint', {}))
    result['name'] = document.get('name', 'default')
    shared = document.get('scenario', {})
    for key in ('tls', 'measurement'):
        result[key] = {**result.get(key, {}), **shared.get(key, {})}
    result['measurement'].update(document.get('experiment', {}))
    return result


def endpoint_profile(values):
    value = experiment_profile(**values)
    return {k: v for k, v in {**value, 'type': 'turtle-endpoint-profile'}.items() if k != 'experiment'}
