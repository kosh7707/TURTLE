#!/usr/bin/env python3
"""보존된 검증·예비실행 자료에서 한국어 구현 보고서 하나를 다시 만듭니다."""
import argparse
import json
import os
from pathlib import Path
import re


def generate(root, output):
    def read(path):
        return json.loads((root / path).read_text())
    def link(label, path):
        return f'[{label}]({Path(os.path.relpath(root / path, output.parent)).as_posix()})'
    prototype = read('artifacts/internal-span-matrix-final/verification.json')['runs']
    mlkem = read('artifacts/mlkem-matrix-final/verification.json')
    kernel = read('artifacts/kernel-loss-matrix-final/verification.json')
    observation = read('artifacts/observation-pilot-final/observation-summary.json')
    bithac = read('artifacts/bithac-pilot-1/bithac-summary.json')
    objects = read('.deps/manifests/mlkem-object-comparison.json')
    verification = read('artifacts/verification-implementation-final/verification.json')
    if not (kernel['status'] == observation['status'] == verification['status'] == 'complete' and
            objects['status'] == 'verified' and not bithac['failed_endpoints'] and
            all(row['status'] == 'passed' for row in prototype + mlkem)):
        raise RuntimeError('required local evidence is incomplete; do not publish a completion report')
    test_log = (root / 'artifacts/verification-implementation-final/ctest-final.log').read_text()
    tests = re.search(r'100% tests passed, 0 tests failed out of (\d+)', test_log)
    if not tests: raise RuntimeError('complete CTest evidence is absent')
    prototype_connections = sum(r['connections'] for r in prototype)
    mlkem_connections = sum(r['connections'] for r in mlkem)
    loss_rows = []
    cases = [('no-loss', '무손실'), ('client-first', '클라이언트 첫 바이트'),
             ('server-first', '서버 첫 바이트'), ('both-application', '양방향 응용 데이터 중간'),
             ('random-loss', '양방향 랜덤 5%')]
    for key, label in cases:
        local = [r for r in kernel['rows'] if r['case'] == key]
        loss_rows.append(f'| {label} | {len(local)//2} | ' + ' | '.join(str(sum(r[field] for r in local))
            for field in ('targeted_drops', 'qdisc_drops', 'kernel_retransmissions', 'observed_retransmitted_bytes')) + ' |')
    sends = []
    for library in ('openssl', 'wolfssl', 'mbedtls'):
        counts = []
        for policy in ('native', 'server-hello-first'):
            path = root / 'artifacts/internal-span-matrix-final' / f'{library}-{library}-client-request-{policy}-1' / 'sample-000001/server.jsonl'
            events = [json.loads(line) for line in path.read_text().splitlines()][1:]
            first = next(e for e in events if e['kind'] == 'IO_SEND_RETURN' and e['transferred'] > 0)
            counts.append(first['transferred'])
        sends.append(f'| {library} | {counts[0]} | {counts[1]} |')
    observation_rows = []
    labels = {'timing': '시간', 'trace': '상세 추적', 'trace-tx': '추적 + 송신 시각', 'cpu-profile': 'CPU 표본 수집'}
    for condition, label in labels.items():
        groups = {g['role']: g['metrics'] for g in observation['groups'] if g['condition'] == condition}
        n = groups['client']['elapsed_ns']['count']
        values = [groups[role]['elapsed_ns']['median']/1e6 for role in ('client', 'server')]
        values += [groups[role]['thread_cpu_ns']['median']/1e3 for role in ('client', 'server')]
        observation_rows.append(f'| {label} | {n} | {values[0]:.3f} | {values[1]:.3f} | {values[2]:.1f} | {values[3]:.1f} |')
    certificates = []
    for role, label in [('client', '클라이언트'), ('server', '서버')]:
        sizes = []
        for index in (0, 1):
            values = {r['certificate_message_bytes'] for r in bithac['rows'] if
                      r['variant'] == 'bithac' and r['role'] == role and r['connection'] == index}
            if len(values) != 1: raise RuntimeError('certificate sizes vary; report must retain that variation')
            sizes.append(values.pop())
        certificates.append(f'| {label} | {sizes[0]} | {sizes[1]} | {100*(1-sizes[1]/sizes[0]):.2f}% |')
    text = f'''# TURTLE 로컬 구현과 검증 보고서

2026년 11월 11일. x86_64 WSL2에서 수행한 구현·기능 검증 자료입니다.

세 TLS 구현체의 공통 실행·계측, 실제 논문 캐싱 경로, 동일 ML-KEM 구현 비교, 지정 바이트 손실과 커널 재전송 분석까지 로컬 실행에 연결했습니다. 남아 있던 wolfSSL 생성 구간과 Mbed TLS 처리 구간을 보완했고, 원자료에서 이 보고서와 분석 표를 다시 만들 수 있습니다. **로컬 구현·검증은 완료했으며, 네이티브 Linux 본 실험과 ARM 재현은 사용자 요청에 따라 유보했습니다.**

## 실행 범위와 구조

OpenSSL 3.5.4, wolfSSL 5.8.2-stable, Mbed TLS 3.6.4를 고정했습니다. BiTHaC는 저자 공개 코드의 wolfSSL 5.7.0 기반을 유지하고, ML-KEM-768은 같은 wolfSSL 5.8.2 소스의 C/AVX2 쌍을 사용합니다. 출처·컴파일 조건·패치 해시는 원자료와 의존성 manifest에 남습니다.

시행마다 새 TCP 연결에서 인증서 기반 TLS 1.3 전체 핸드셰이크를 수행합니다. 서버 인증·상호 인증과 순수 핸드셰이크, 서버 Ping, Finished와 Ping 결합, 클라이언트 요청·서버 응답을 검증했습니다. PSK·세션 재개·클라이언트 0-RTT·HRR는 기준 시나리오에 포함하지 않습니다.

```mermaid
flowchart LR
    C["클라이언트 네임스페이스<br/>TLS 프로세스 1개"]
    R["라우터 네임스페이스<br/>커널 포워딩"]
    S["서버 네임스페이스<br/>TLS 프로세스 1개"]
    C <-->|"veth 쌍 1"| R
    R <-->|"veth 쌍 2"| S
```

서버 수신 대기 포트 하나와 클라이언트 임시 포트로 TCP 연결 하나를 만듭니다. 라우터의 수신자 방향 출구 두 곳에서 netem을 독립 적용하고 조건별 실행을 분리합니다. Docker는 필요하지 않습니다. 실행·관측 보조 프로세스는 TLS 엔드포인트 수와 구별합니다.

기본 실행은 user namespace 격리를 사용합니다. BPF 커널 관측을 요청한 실행은 initial user namespace의 root를 유지하되 새 network namespace 안에서 수행합니다. 이 경로의 TLS 엔드포인트도 root이며 권한 차이를 비교 조건에 기록합니다. 호스트 인터페이스·라우트·qdisc 불변과 실행 소유 자원의 정리를 확인했습니다.

## 계측 계약과 이번 보완

공개 ABI 3, TLS 원자료 schema 2, 측정 계약 개정 3을 유지합니다. 네트워크 프로필은 schema 3, TCP 분석 결과는 schema 2로 확장했습니다. 기존 원자료의 의미를 새 의미로 소급 변경하지 않습니다.

| 구분 | 구현과 관측 경계 |
|---|---|
| 실행 생명주기 | 모듈 로드·컨텍스트 셋업·새 TCP·연결 객체 준비·프로토콜·정리를 구별합니다. 첫 측정 연결을 버리지 않습니다. |
| 클라이언트 완료 | 연결 준비 시작 또는 TCP 시작부터 ClientFinished 레코드의 실제 소켓 제출 완료까지를 따로 제공합니다. |
| 서버 완료 | 첫 TLS 수신부터 ClientFinished 처리 완료까지를 API 완료와 구별합니다. |
| 생성·처리 | 공개 메시지 콜백 대신 실제 구성·파싱·검증 경로에 사건을 넣습니다. wolfSSL 생성은 레코드 처리·I/O 전에 닫고, Mbed TLS 처리는 fetch 뒤 시작합니다. |
| 레코드·출력 | TLS 레코드, 출력 배치, 성공한 소켓 제출과 TCP 패킷을 별개로 유지합니다. 공유 비용을 메시지마다 나누지 않습니다. |
| CPU·메모리 | 총 역할 스레드 CPU 시간·계수와 perf 표본 비중을 구별합니다. 힙은 할당 훅이 관측한 요청 바이트이며 전체 RSS·스택이 아닙니다. |
| 누락 판정 | 정상 TLS 실패와 필수 관측 누락을 구별합니다. 요청한 커널 자료·target 제거·정리가 불완전하면 자동 비교에서 제외합니다. |

wolfSSL의 넓은 `library_message_write`와 새 생성 구간은 중첩합니다. 이를 더하지 않습니다. Mbed TLS 바디 밖의 키 준비·finalize, wolfSSL의 평문 헤더·transcript 위치 차이도 남습니다. 따라서 내부 메시지별 시간이 세 구현에서 같은 연산 목록을 뜻한다고 주장하지 않습니다. 자세한 위치는 {link('프로토타입 계약', 'docs/design/prototype.md')}에 있습니다.

## 최종 검증

| 검증 | 통과한 범위 | 근거 |
|---|---|---|
| 빌드·시험 | Release 제품·Debug 시험 빌드, 전체 {tests[1]}개 테스트와 CPU 분석 수정 뒤 관련 3개 시험 | {link('검증 목록과 로그', 'artifacts/verification-implementation-final/verification.json')} |
| 정적 검사 | 프로젝트 컴파일 조건 32개 cppcheck·clang-analyzer, 11개 부품 경계, Python·셸 문법 | 같은 검증 폴더 |
| 세 표준 구현체 | {len(prototype)}개 실제 실행, 새 TCP {prototype_connections}연결. 3×3 조합·네 시나리오·두 정책·두 인증과 큰 비대칭 응용 데이터 | {link('표준 TLS 행렬', 'artifacts/internal-span-matrix-final/verification.json')} |
| ML-KEM | 정상 벡터, {len(mlkem)}개 실제 실행·{mlkem_connections}연결, C/AVX2 실제 분기와 상호 운용 | {link('ML-KEM 행렬', 'artifacts/mlkem-matrix-final/verification.json')} |
| BiTHaC | 기준/캐시·네 시나리오·두 인증의 16개 실행과 캐시 준비/재사용, 3모드 예비 자료 {len(bithac['rows'])}행 | {link('BiTHaC 원자료 요약', 'artifacts/bithac-pilot-1/bithac-summary.json')} |
| TCP 손실·복구 | 세 라이브러리·다섯 조건·{len(kernel['rows'])//2}개 실제 TLS 연결, {len(kernel['rows'])}개 역할/연결 기록 | {link('커널 손실 검증', 'artifacts/kernel-loss-matrix-final/verification.json')} |
| 관측 설정 | 네 조건별 12개 새 프로세스 쌍·연결 1개·워밍업 0, 총 {len(observation['rows'])}개 역할 기록 | {link('관측 부담 예비 자료', 'artifacts/observation-pilot-final/observation-summary.json')} |

위 행은 서로 다른 검증 단위이며 CTest 안의 실제 TLS 시험과 보존 행렬이 일부 겹칩니다. 전부 더해 독립 표본 수로 사용하지 않습니다. 의존성 패치는 깨끗한 고정 원본에 fuzz=0으로 적용한 뒤 실제 빌드 소스와 파일별 일치를 확인했습니다. 저장소의 Git 메타데이터는 없어 커밋을 만들지 않았으며 소스 해시 목록을 남깁니다.

## 송신 정책과 실제 손실의 결과

같은 32바이트 요청·응답, 상호 인증의 보존 표본에서 첫 서버 소켓 제출량은 다음과 같습니다. 단위는 바이트입니다.

| 구현 | native | ServerHello 먼저 제출 |
|---|---:|---:|
{chr(10).join(sends)}

OpenSSL은 기본 정책에서 서버 flight를 함께 제출했고 정규화 정책은 ServerHello를 먼저 제출했습니다. wolfSSL·Mbed TLS의 해당 경로는 원래 ServerHello를 먼저 제출했습니다. 이 표는 소켓 제출 배치의 동작 확인이며 TCP 세그먼트 수나 완료시간 개선율이 아닙니다. 근거는 위 표준 TLS 행렬의 각 `client-request` 상호 인증 원자료입니다.

커널 손실 시험은 MTU 1500, TSO/GSO/GRO 끔, 방향별 지연 2ms, 양방향 응용 32KiB로 수행했습니다. 응용 중간 target은 0부터 센 TLS 스트림 위치로 클라이언트 8,192, 서버 16,384바이트입니다.

| 조건 | TLS 연결 | 지정 제거 사건 | qdisc 제거 사건 | 커널 재전송 사건 | 관측 중첩 payload 바이트 |
|---|---:|---:|---:|---:|---:|
{chr(10).join(loss_rows)}

지정 바이트를 포함하는 첫 소프트웨어 패킷 전체를 방향·연결마다 한 번 제거했고, 지정 제거 48건 모두 해당 바이트 범위와 겹치는 후속 커널 재전송 및 정상 TLS·응용 교환을 확인했습니다. 재전송은 원본 TCP 순번과 TLS 스트림 범위로 대응했습니다. 랜덤 손실의 qdisc 사건에는 순수 ACK 등도 포함될 수 있어 재전송 사건 수와 같지 않습니다. seed는 고정되지 않았으며 실제 제거 기록을 보존했습니다.

원본 pcap은 IP/TCP 헤더·옵션·payload를 포함합니다. BPF 사건, 사용자 공간 패킷 관측, 커널 TX_SCHED/TX_SOFTWARE/TX_ACK는 관측 위치와 시계를 구별합니다. TCP 분석의 헤더 합계는 TLS 데이터 패킷 대상이고 SYN·ACK·FIN 전체 트래픽과 분모가 다릅니다. {link('실행·자료 형식', 'docs/analysis/tcp-analysis.md')}에 지원 범위를 설명합니다.

## 논문 기법과 동일 KEM 비교

BiTHaC는 [저자 공개 코드](https://github.com/RWTH-SPICe/BiTHaC/tree/68ad825a37ef72cc1db4a67eb6d13275cc61f8aa)의 실제 양방향 인증서 캐싱입니다. 같은 기반의 캐시 끔/켬을 비교하고 첫 측정 연결의 준비 비용을 남겼습니다. 보존한 시험 체인의 Certificate 메시지 크기는 다음과 같습니다.

| 방향 | 빈 캐시 연결 | 재사용 연결 | 메시지 바이트 감소 |
|---|---:|---:|---:|
{chr(10).join(certificates)}

CertificateVerify·Finished·실제 인증·응용 교환과 캐시 송신 호출을 함께 확인했습니다. 비표준 연구 프로필로 식별하며 표준 TLS 기준선과 같은 프로토콜이라고 표시하지 않습니다. 이 비율은 Certificate 메시지 분모이며 전체 TCP/IP 감소율이 아닙니다. 시간·추적·메모리는 별도 실행이고, 두 연결을 공유하는 컨텍스트를 독립 표본 두 개로 취급하지 않습니다.

[논문](https://www.spice.rwth-aachen.de/assets/pdf/bodenhausen2025caching.pdf)의 정확한 처리시간 시작·종료 API는 확정되지 않았습니다. 공개 예제의 평균에는 객체·TCP·TLS·종료 작업이 들어가고 기본 10% 제외 규칙도 있습니다. TLS 1.3 공개 경로에는 작은 인증서 사전 검증 캐시가 없어 논문의 전체 처리시간 최적화나 성능 수치를 재현했다고 주장하지 않습니다. {link('원래 구간과의 대응', 'docs/experiments/research-reproduction.md')}에 확인한 차이와 가정을 남겼습니다.

ML-KEM 쌍은 두 관련 C 오브젝트만 다르고 나머지 {objects['identical_other_objects']}개가 같습니다. 키 생성·캡슐화·역캡슐화와 실제 C/AVX2 다항식 분기를 TLS 경로에서 확인했습니다. API 전체와 내부 다항식 구간은 중첩하므로 합산하지 않습니다. ML-KEM 내부 해시·표현·임시 메모리 차이는 최적화의 일부입니다. 이 비교는 미채택 AVX-512 후보 논문의 재현이 아닙니다. {link('비교 조건과 출처', 'docs/experiments/mlkem-comparison.md')}를 따릅니다.

## 관측 설정에 따른 변동

같은 OpenSSL 상호 인증·양방향 32바이트·연결 1개 조건을 4블록으로 나누고 블록 안 실행 순서를 섞었습니다. 표는 역할별 주 구간의 중앙값입니다. CPU 열은 해당 역할 스레드의 사용자+커널 시간이며 perf 표본 비중과 다릅니다.

| 설정 | 프로세스 쌍 | 클라이언트 경과 ms | 서버 경과 ms | 클라이언트 CPU µs | 서버 CPU µs |
|---|---:|---:|---:|---:|---:|
{chr(10).join(observation_rows)}

상세 추적과 송신 시각을 켠 실행에서 시간이 달라졌지만 WSL의 부하·스케줄링·가상화 변동도 포함됩니다. 서버의 상세 추적 CPU 중앙값이 시간 모드보다 작은 점도 있어 이 차이를 보편적 계측 부담률로 해석하지 않습니다. 시간 모드에도 공통 계측이 남으며, 종료 뒤 ACK 대기와 perf 시작·후처리 시간은 이 주 구간 밖입니다.

CPU 프로파일은 `cycles:u`, 997Hz, 엔드포인트 PID·주 TID·단조 시계 구간으로 분석했습니다. 이번 짧은 주 구간은 1~3표본이므로 함수 비중의 안정성을 주장하지 않습니다. build ID 없는 임시 vDSO 한 항목은 함수 이름을 unknown으로 유지해 같은 perf.data로 재분석했습니다. 최초 분석 상태·도구 경고를 보존했고 TLS 시행을 교체하지 않았습니다. 원래 파일의 build ID가 다른 경우는 여전히 missing입니다.

## 재생성과 유보 항목

수집된 자료만으로 다음을 다시 만들 수 있습니다. 관리자 권한이나 네트워크 다운로드는 재분석에 필요하지 않습니다.

```sh
python3 scripts/kernel-loss-study.py analyze --output artifacts/kernel-loss-matrix-final
python3 scripts/observation-study.py analyze --output artifacts/observation-pilot-final
python3 scripts/bithac-study.py analyze --output artifacts/bithac-pilot-1
python3 scripts/mlkem-study.py analyze --output artifacts/mlkem-pilot-1
python3 scripts/implementation-report.py
```

JSON·CSV·보고서를 반복 재생성해 값의 일치와 원자료 불변을 확인했습니다. {link('재분석 검증', 'artifacts/verification-implementation-final/reanalysis.json')}과 {link('실행·검증 기록', 'docs/project/validation.md')}에서 경로를 찾을 수 있습니다. perf 함수 표는 각 수집 폴더의 저장 바이너리와 `cpu-profile.py analyze`로 재생성합니다.

현재 로컬 구현에서 확인한 사실과 이후 연구 항목을 구별합니다. 네이티브 Linux에서 관측 부담·도구 호환성을 확인하고 반복 수·컨텍스트/캐시 조건·주 지표·통계를 동결하는 본 실험, ARM 재현은 유보 상태입니다. 논문 timer 경계의 미확정과 TLS 1.3 작은 사전 검증 캐시의 미지원도 그대로 남습니다. 이 보고서는 구현체 성능 순위나 전체 연구 완료를 선언하지 않습니다.
'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    generate(root, args.output.resolve() if args.output else root / 'docs/project/implementation-report.md')


if __name__ == '__main__':
    main()
