#!/usr/bin/env python3
"""저자 구현의 캐시 경로, 인증, 바이트 감소와 네 시나리오를 확인합니다."""
import itertools
import json
from pathlib import Path
import sys
import tempfile

from prototype import check, verify


def main():
    turtle, report, interpret, adapters, pki = map(Path, sys.argv[1:6])
    with tempfile.TemporaryDirectory(prefix='turtle-bithac-') as temporary:
        root = Path(temporary)
        for variant, scenario, mutual in itertools.product(
                ('bithac-baseline', 'bithac'),
                ('handshake', 'server-ping', 'finished-ping', 'client-request'),
                (False, True)):
            destination = root / f'{variant}-{scenario}-{int(mutual)}'
            verify(turtle, report, interpret, adapters, pki, destination, variant, variant,
                   scenario, 'native', mutual, connections=2)
            decoded = json.loads((destination / 'sample-000001/client.decoded.json').read_text())
            for role in ('client', 'server'):
                rows = [json.loads(line) for line in
                        (destination / 'sample-000001' / f'{role}.jsonl').read_text().splitlines()]
                check(rows[0]['config']['scenario_name'] == 'research-tls13', 'research profile identity')
                check('68ad825a' in rows[0]['declaration']['source_version'], 'author commit identity')
                for connection in (0, 1):
                    hits = [e for e in rows[1:] if e['connection'] == connection and
                            e['kind'] == 'INTERNAL_END' and
                            e['trace_operation'] == 'cached_certificate_write']
                    expect_hit = variant == 'bithac' and connection == 1 and (mutual or role == 'server')
                    check(len(hits) == int(expect_hit), 'actual cache path differs from condition')
                    messages = decoded['connections'][connection][role + '_sent']['messages']
                    certificates = [m for m in messages if m['name'] == 'Certificate']
                    if mutual or role == 'server':
                        check(len(certificates) == 1, 'certificate message missing')
                        check(certificates[0]['length'] == (18 if role == 'client' else 50)
                              if expect_hit else certificates[0]['length'] > 100,
                              'cached certificate wire representation differs')
        print('16 BiTHaC baseline/cached real TLS runs passed')


if __name__ == '__main__':
    main()
