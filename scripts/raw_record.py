"""오프라인 도구가 공유하는 현재 TLS 원자료 판독과 관측 경계."""
import json


def require_tls_sample(header):
    if header.get('type') != 'sample' or header.get('schema') != 3:
        raise ValueError('TLS raw input requires schema 3')
    if header.get('measurement_contract_revision') not in (3, 4):
        raise ValueError('TLS raw input requires measurement contract revision 3 or 4')
    return header


def read_tls_header(path):
    with path.open() as source:
        return require_tls_sample(json.loads(source.readline()))


def read_tls_records(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if not rows:
        raise ValueError('TLS raw input has no sample header')
    require_tls_sample(rows[0])
    return rows


def lifetime_span(header, events):
    mode = header['adapter_connection']['mode']
    if mode == 'module':
        begin = next(e for e in events if e['kind'] == 'MODULE_BEGIN')
        name = 'module-to-teardown'
    elif mode == 'builtin':
        begin = next(e for e in events if e['kind'] == 'SETUP_BEGIN')
        name = 'context-setup-to-teardown'
    else:
        raise ValueError('unknown adapter connection mode')
    end = next(e for e in events if e['kind'] == 'CALL_END' and e['call'] == 'teardown')
    return name, begin, end
