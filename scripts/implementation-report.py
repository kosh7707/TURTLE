#!/usr/bin/env python3
"""명시한 현재 검증 목록으로 한국어 구현 보고서를 재생성합니다."""
import argparse
import json
import os
from pathlib import Path


def generate(verification, output):
    evidence = json.loads(verification.read_text())
    if evidence.get('type') != 'turtle-current-verification' or evidence.get('schema') != 1:
        raise ValueError('expected turtle-current-verification schema 1')
    if evidence.get('status') != 'complete':
        raise ValueError('verification is incomplete')
    if evidence.get('tls_schema') != 3 or evidence.get('measurement_contract_revision') not in (3, 4):
        raise ValueError('the report requires current TLS schema and measurement contract')
    checks = evidence['checks']
    if not checks or any(check['status'] != 'passed' for check in checks):
        raise ValueError('required verification did not pass')

    def link(path, label):
        target = (verification.parent / path).resolve()
        if not target.exists():
            raise ValueError(f'verification artifact missing: {target}')
        return f'[{label}]({os.path.relpath(target, output.parent)})'

    rows = []
    for check in checks:
        rows.append(f"| {check['name']} | {check['detail']} | {link(check['evidence'], '근거')} |")
    lines = [
        '# TURTLE 현재 구현·검증 보고서', '',
        f"검증일은 {evidence['date']}이며 실행 환경은 {evidence['environment']}입니다. "
        '이 문서는 명시한 검증 목록에서 생성하며 과거 성능 표나 개인 경로를 찾아 결합하지 않습니다.', '',
        '독립 `turtle-client`와 `turtle-server`는 IPv4:Port의 데이터 TCP와 제어 TCP로 실행합니다. '
        '준비 단계에서 시나리오·실행 ID·지원·컨텍스트·버퍼 준비를 확인하고 첫 측정 연결을 보존합니다. '
        '기본 내장 연결과 명시적 모듈 연결을 구별하며 프로그램 진입 전 로딩 비용은 미관측입니다.', '',
        f"이 검증의 TLS 원자료는 schema 3, 측정 계약은 개정 {evidence['measurement_contract_revision']}, 어댑터 ABI는 3, 제어 프로토콜은 {evidence['control_protocol']}입니다. "
        'TLS schema 1·2 판독과 이전 실행 명령·평면 프로필·부모 지휘 경로는 제거했습니다. '
        '서비스·실험 원장·해독·패킷·분석 산출물의 독립 버전 번호는 별도로 관리합니다.', '',
        '| 검사 | 확인한 범위 | 자료 |', '|---|---|---|', *rows, '',
        '검사 성공은 정상 TLS 기능과 자료 처리의 확인입니다. 성능 순위, 물리 NIC 통과, '
        '논문 성능 수치의 재현이나 전체 연구 완료를 뜻하지 않습니다. '
        '루프백은 커널 TCP/IP이고 veth는 가상 인터페이스를 통과합니다.', '',
        '남은 확인 사항은 다음과 같습니다.', '',
        *[f'- {item}' for item in evidence['limitations']], '',
        f"전체 명령과 파일 출처는 {link(verification.name, '검증 목록')}에 있습니다. "
        '측정 경계와 운영 명령은 [실행 계약](../design/runtime.md), '
        '재실행 절차는 [검증 기록](validation.md)을 따릅니다.', '',
        '```sh',
        'python3 scripts/implementation-report.py \\',
        f'  --verification {os.path.relpath(verification, Path.cwd())}',
        '```', '',
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verification', type=Path, required=True)
    parser.add_argument('--output', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'docs/project/implementation-report.md')
    args = parser.parse_args()
    generate(args.verification.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
