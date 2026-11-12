#!/usr/bin/env python3
"""실제 TLS에서 같은 ML-KEM 쌍의 상호 운용과 연산 분기·인증·네 시나리오를 확인합니다."""
import argparse
import itertools
import json
from pathlib import Path
import tempfile

from prototype import check, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('turtle', 'report', 'interpret', 'adapters', 'pki'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix='turtle-mlkem-') if args.output is None else None
    root = args.output or Path(temporary.name)
    root.mkdir(parents=True, exist_ok=True)
    results = []
    for client, server, scenario, policy, mutual in itertools.product(
            ('mlkem-c', 'mlkem-avx2'), ('mlkem-c', 'mlkem-avx2'),
            ('handshake', 'server-ping', 'finished-ping', 'client-request'),
            ('native', 'server-hello-first'), (False, True)):
        destination = root / f'{client}-{server}-{scenario}-{policy}-{int(mutual)}'
        results.append(verify(args.turtle, args.report, args.interpret, args.adapters, args.pki,
                              destination, client, server, scenario, policy, mutual,
                              connections=2, group='ML_KEM_768'))
        for role, variant in (('client', client), ('server', server)):
            rows = [json.loads(line) for line in
                    (destination / 'sample-000001' / f'{role}.jsonl').read_text().splitlines()]
            header = rows[0]
            check(header['declaration']['technique'] == 'mlkem768-tls13', 'profile identity')
            check('decea12e' in header['declaration']['source_version'], 'source commit absent')
            for index, connection in enumerate(header['connections']):
                check(connection['negotiated']['group'] == 'ML_KEM_768', 'KEM group not negotiated')
                ends = [e for e in rows[1:] if e['connection'] == index and e['kind'] == 'INTERNAL_END']
                expected = {'kem_keygen': 1, 'kem_decapsulate': 1, 'kem_encapsulate': 0} if role == 'client' else {
                    'kem_keygen': 0, 'kem_decapsulate': 0, 'kem_encapsulate': 1}
                for operation, count in expected.items():
                    calls = [e for e in ends if e['trace_operation'] == operation]
                    check(len(calls) == count and all(e['result'] == 0 for e in calls), 'KEM calls differ')
                polynomial = [e for e in ends if e['trace_operation'].startswith('kem_polynomial_')]
                check(len(polynomial) == (3 if role == 'client' else 1), 'polynomial evidence missing')
                check(all(e['message_type'] == (2 if variant == 'mlkem-avx2' else 1)
                          for e in polynomial), 'actual dispatch differs from requested comparison')
        (root / 'verification.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'{len(results)} actual ML-KEM TLS runs passed; each has two fresh TCP connections')


if __name__ == '__main__':
    main()
