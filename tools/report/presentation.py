"""표준 라이브러리만으로 전체·네 구간 비교 보고서를 Markdown/HTML로 작성한다."""
from html import escape
PHASES = ("client_hello", "server_hello", "server_auth", "client_finished")
SENDERS = ("client", "server", "server", "client")

NAMES = {"client_hello": "ClientHello", "server_hello": "ServerHello",
         "server_auth": "서버 암호화 묶음", "client_finished": "클라이언트 Finished"}
ROLES = {"client": "클라이언트", "server": "서버"}


def write_report(root, manifest, report):
    spec = manifest["spec"]
    configs = {c["id"]: c.get("label", c["id"]) for c in spec["configurations"]}
    overall = {(r["configuration"], r["role"], r["metric"]): r for r in report["metrics"]}
    phases = {(r["configuration"], r["role"], r["phase"], r["metric"]): r for r in report["phase_metrics"]}
    blocks = []

    def para(s):
        blocks.append(("p", s))

    def title(s):
        blocks.append(("h2", s))

    def table(headers, rows):
        blocks.append(("table", headers, rows))

    def duration(row):
        return "미수집" if row["median"] is None else f'{row["median"]/1e6:.3f} ({row["iqr"]/1e6:.3f})'

    def number(row, field="median"):
        n = row[field]
        return "미수집" if n is None else f"{n:,.0f}" if n == int(n) else f"{n:,.1f}"

    attempts = report["attempts"]
    successful = sum(a["success"] for a in attempts)
    complete = sum(a["phase_complete"] for a in attempts)
    para(f"전체 {len(attempts)}회 시도 중 TLS 시나리오 성공 {successful}회, 네 구간 상세 계측 완료 {complete}회다. "
         "각 시도는 새 클라이언트·서버 프로세스를 사용한다. 실패한 시도는 대체하지 않는다.")
    separate = sum(not a.get("ordinary_timing_sample", True) for a in attempts)
    if separate:
        para(f"이 중 {separate}회는 perf 전용 수집이다. 원자료의 시간은 보존하지만 아래 일반 시간·바이트 비교 집계에서는 제외한다. "
             "하드웨어 카운터와 CPU 표본은 별도 표에 표시하며 계측 비용을 빼서 보정하지 않는다.")
    if spec.get("description"):
        para("실험 명세: " + spec["description"])
    if report.get("counter_metrics"):
        title("perf 하드웨어 카운터")
        para("호출 스레드의 사용자 공간 cycles와 instructions다. 준비·전체 핸드셰이크·시나리오 및 네 관측 구간에 연결한다. "
             "실행된 시간(time_running)이 활성 시간(time_enabled)보다 작으면 전체 구간 카운터로 채택하지 않는다. "
             "원시 값과 두 시간은 counter_report.csv와 counters.json에 남으며 자동 배율 보정은 하지 않는다.")
        scopes = {"prepare": "준비", "handshake": "전체 핸드셰이크", "scenario": "시나리오", "first_use": "첫 사용", **NAMES}
        selected = {(r["configuration"], r["role"], r["scope"], r["metric"]): r for r in report["counter_metrics"]}
        rows = []
        for config, role, scope in sorted({key[:3] for key in selected}):
            cycles = selected[config, role, scope, "cycles"]
            instructions = selected[config, role, scope, "instructions"]
            rows.append([configs[config], ROLES[role], scopes[scope], number(cycles), number(instructions),
                         str(cycles["valid_samples"]) + "/" + str(cycles["attempts"])])
        table(["구성", "엔드포인트", "구간", "cycles 중앙값", "instructions 중앙값", "유효/시도"], rows)
    if report.get("cpu_profiles"):
        title("perf CPU 표본")
        para("함수·모듈의 표본 수와 period 비중이다. 함수의 정확한 호출 시간·횟수로 환산하지 않는다. "
             "짧은 구간에 표본이 없으면 미수집으로 남기며 일반 시간 표본에 섞지 않는다. "
             "부모 핸드셰이크와 네 하위 구간의 표본 수를 더하지 않는다.")
        rows = []
        for p in report["cpu_profiles"]:
            for section in p.get("phases", []):
                top = section.get("functions", [])[:3]
                rows.append([p["directory"], configs[p["configuration"]], ROLES[p["role"]], NAMES[section["phase"]],
                             str(section["sample_count"]), "; ".join(f'{r["symbol"]} ({100*r["period_fraction"]:.1f}%)' for r in top) if top else "표본 없음"])
        if rows:
            table(["시도", "구성", "엔드포인트", "구간", "표본 수", "period 비중 상위 함수"], rows)
        for p in report["cpu_profiles"]:
            if p["availability"] != "available":
                para(f'{p["directory"]} {ROLES[p["role"]]}: {p["availability"]}, {p["reason"]}.')
    para("네 구간의 이름은 로컬 소켓 관측 경계를 뜻한다. 메시지 내부 생성·검증 함수의 비용을 뜻하지 않는다. "
         "특히 하나의 송신 콜백이 ServerHello와 암호화 묶음을 함께 내보내면, 그 전에 수행한 계산이 ServerHello 관측 구간에 들어갈 수 있다.")
    title("관측 구간의 경계")
    table(["구간", "시작", "끝"], [
        ["ClientHello", "handshake 호출 진입", "로컬 ClientHello 마지막 바이트의 소켓 호출 반환"],
        ["ServerHello", "ClientHello 구간 끝", "로컬 ServerHello 마지막 바이트의 소켓 호출 반환"],
        ["서버 암호화 묶음", "ServerHello 구간 끝", "로컬 서버 묶음 마지막 바이트의 소켓 호출 반환"],
        ["클라이언트 Finished", "서버 묶음 구간 끝", "handshake 호출 반환·성공 확인"],
    ])
    para("서버 암호화 묶음은 (EncryptedExtensions, Certificate, CertificateVerify, Finished)다. "
         "Hello는 평문 핸드셰이크 헤더를 확인한다. 암호화 구간은 구현자가 선언한 인증서 기반 서버 인증 1-RTT 조건과 "
         "성공한 공개 핸드셰이크의 송신 범위로 연결한다. 클라이언트 인증·재개·0-RTT·HRR 및 핸드셰이크 호출 중 티켓·응용 데이터가 없는 조건이며, 암호화 내용을 복호화해 확인하지 않는다.")
    para("양쪽 엔드포인트에서 동일한 바이트 범위를 참조하되 각자의 시계로 시간을 잰다. 네 구간은 표본별로 겹치지 않고 "
         "벽시계·호출 스레드 CPU 시간 합이 전체 핸드셰이크와 정확히 일치한다. 구간별 중앙값을 더하면 전체 중앙값과는 다를 수 있다.")
    title("실행 조건과 표본 수")
    table(["구성", "예정 반복", "실제 시도", "TLS 성공", "상세 계측 완료", "네트워크 관측 완료"], [
        [label, str(spec.get("repetitions", "미기록")), str(sum(a["configuration"] == config for a in attempts)),
         str(sum(a["configuration"] == config and a["success"] for a in attempts)),
         str(sum(a["configuration"] == config and a["phase_complete"] for a in attempts)),
         str(sum(a["configuration"] == config and a["network_complete"] for a in attempts))]
        for config, label in configs.items()])
    for config in spec["configurations"]:
        settings = config.get("netem", {})
        if spec.get("network", "netem") == "netem":
            parts = []
            for direction in ("client_to_server", "server_to_client"):
                rule = settings.get(direction, {})
                parts.append(f'{direction}: 지연 {rule.get("delay_ms", 0)} ms, 손실 {rule.get("loss_pct", 0)}%, 속도 {rule.get("rate_mbit", "미설정")} Mbit/s')
            para(f'{configs[config["id"]]} — ' + "; ".join(parts) + f'; MTU {settings.get("mtu", 1500)}.')
        else:
            para(f'{configs[config["id"]]} — loopback, 패킷 캡처·netem 관측 미수집.')
    para(f'실행 시작 UTC: {manifest.get("started_utc", "미기록")}. 기준 구성: {configs[report["baseline"]]}. '
         f'순서 seed: {spec.get("seed", 0)}. 부트스트랩 {report["statistics"]["bootstrap_samples"]}회, '
         f'seed {report["statistics"]["bootstrap_seed"]}. 구간은 독립 프로세스 표본 재추출의 95% 백분위 구간이다.')

    title("준비와 전체 핸드셰이크")
    para("단위는 ms, 값은 중앙값 (IQR)이다. 준비 중 키 생성은 네 핸드셰이크 구간 밖이므로 준비·첫 사용과 함께 비교한다. "
         "첫 사용은 표본별 준비+시나리오이며 TCP 연결·프로세스 시작·준비 장벽·종료·해제는 제외한다.")
    table(["구성", "엔드포인트", "준비 벽시계", "전체 핸드셰이크 벽시계", "전체 핸드셰이크 CPU", "첫 사용 벽시계"], [
        [label, ROLES[role], *[duration(overall[config, role, name]) for name in
                              ("prepare_wall_ns", "handshake_wall_ns", "handshake_thread_cpu_ns", "first_use_wall_ns")]]
        for config, label in configs.items() for role in ROLES])
    title("네 구간의 벽시계와 CPU 시간")
    para("단위는 ms, 값은 중앙값 (IQR)이다. 수신 구간에는 상대 처리·네트워크 대기가 포함될 수 있다. "
         "소켓 비용은 이 시간 구간에 속한 모든 소켓 호출의 합이며 CCS 대기도 포함한다. 관측 구간에 포함되므로 두 열을 더하지 않는다. "
         "CSV의 socket_*는 해당 메시지 바이트의 소켓 비용, interval_socket_*는 아래의 구간 전체 소켓 비용이다. n은 해당 지표의 유효 표본 수다.")
    for role in ROLES:
        table(["엔드포인트", "구성", "구간", "동작", "구간 벽시계", "구간 CPU", "소켓 벽시계", "n"], [
            [ROLES[role], label, NAMES[phase], "송신" if sender == role else "수신",
             duration(phases[config, role, phase, "interval_wall_ns"]),
             duration(phases[config, role, phase, "interval_thread_cpu_ns"]),
             duration(phases[config, role, phase, "interval_socket_wall_ns"]),
             str(phases[config, role, phase, "interval_wall_ns"]["valid_samples"])]
            for config, label in configs.items() for phase, sender in zip(PHASES, SENDERS)])
    title("기준 구성과 구간 중앙값 차이")
    para("벽시계 차이의 단위는 ms이며 비교 구성−기준 구성이다. 대괄호는 95% 부트스트랩 구간이다. "
         "내부 메시지 연산의 독립적인 속도 차이로 해석하지 않는다.")
    comparisons = []
    for config, label in configs.items():
        if config == report["baseline"]:
            continue
        for role in ROLES:
            for phase in PHASES:
                row = phases[config, role, phase, "interval_wall_ns"]
                delta = "미수집" if row["median_difference"] is None else f'{row["median_difference"]/1e6:+.3f} [{row["bootstrap_95_low"]/1e6:+.3f}, {row["bootstrap_95_high"]/1e6:+.3f}]'
                comparisons.append([label, ROLES[role], NAMES[phase], delta, str(row["valid_samples"])])
    if comparisons:
        table(["비교 구성", "엔드포인트", "구간", "차이 [95% 구간] ms", "n"], comparisons)
    else:
        para("비교 구성이 하나이므로 기준과의 차이 표는 없다.")

    title("구간별 레코드와 전송 바이트")
    para("각 방향의 송신 캡처를 한 번만 집계한다. 아래 값은 레코드·바이트 중앙값과 유효 표본 전체의 재전송 바이트 합이다. "
         "수신 역할의 행도 같은 송신 캡처를 참조하므로 양쪽 값을 합산하지 않는다. 호환용 CCS는 별도이며 각 시도의 analysis.json에 있다.")
    table(["구성", "구간", "송신자", "레코드", "TLS B", "프레임 포함 B", "재전송 합 B", "재전송 n"], [
        [label, NAMES[phase], ROLES[sender], number(phases[config, sender, phase, "record_count"]),
         number(phases[config, sender, phase, "tls_bytes"]), number(phases[config, sender, phase, "wire_bytes"]),
         number(phases[config, sender, phase, "retransmitted_bytes"], "sample_sum"),
         str(phases[config, sender, phase, "retransmitted_bytes"]["valid_samples"])]
        for config, label in configs.items() for phase, sender in zip(PHASES, SENDERS)])
    title("전송 콜백 밖의 실행과 공유 비용")
    para("다음 값은 ms 중앙값 (IQR)이다. 콜백 밖 시간에는 TLS 처리와 호출 경계의 기록 비용 등이 포함된다. "
         "공유 송신 직전 구간은 서로 다른 주 구간의 바이트를 함께 보내는 전송 호출 바로 전의 실행 시간이다. "
         "앞선 입력 처리와 뒤의 출력 준비가 함께 들어갈 수 있어 특정 메시지의 생성 비용으로 나누지 않는다.")
    table(["구성", "엔드포인트", "콜백 밖 벽시계", "콜백 밖 CPU", "공유 송신 직전 벽시계", "공유 송신 직전 CPU"], [
        [label, ROLES[role], *[duration(overall[config, role, name]) for name in
                              ("handshake_outside_transport_wall_ns", "handshake_outside_transport_thread_cpu_ns",
                               "handshake_before_shared_send_gap_wall_ns", "handshake_before_shared_send_gap_thread_cpu_ns")]]
        for config, label in configs.items() for role in ROLES])
    para("analysis.json은 콜백 사이 모든 구간의 정수 시작·끝 시각, 앞뒤 사건 ID, 공유 사건 ID를 보존한다. "
         "한 프레임 사건이 여러 구간과 연결되면 전용 프레임 비용에 복사하지 않는다. 직접 프레임 처리, 공유·CCS 비용의 합계 대조도 보존한다. "
         "프레임·계측이 패킷 구성과 실행에 미치는 간접 영향은 보정하지 않았다.")
    incomplete = [a for a in attempts if not a["success"] or not a["phase_complete"] or not a.get("perf_complete", True) or
                  (spec.get("network", "netem") == "netem" and not a["network_complete"])]
    if incomplete:
        title("완료하지 못한 시도")
        table(["시도", "구성", "이유"], [[a["directory"], configs[a["configuration"]],
              "; ".join(a["invalid_reasons"] + a["phase_invalid_reasons"] + a["network_invalid_reasons"] + a.get("perf_invalid_reasons", []))] for a in incomplete])
    title("원자료와 재생성")
    para("집계 지표마다 전체 시도·TLS 성공·상세 계측 성공·유효 표본 수와 미수집 이유를 별도로 저장한다. "
         "실제 0은 수집 가능한 표본이며 미수집·미지원·누락은 0으로 바꾸지 않는다.")
    links = [("전체 집계 JSON", "report.json"), ("전체 집계 CSV", "report.csv"), ("구간별 집계 CSV", "phase_report.csv"),
             ("명세와 출처", "manifest.json")]
    if report.get("counter_metrics"):
        links.append(("perf 카운터 CSV", "counter_report.csv"))
    if report.get("cpu_profiles"):
        links.append(("CPU 표본 보고서", "cpu_report.json"))
        links.append(("CPU 함수 표본 CSV", "cpu_report.csv"))
    if attempts:
        links.append(("첫 시도의 사건·레코드·패킷 연결", attempts[0]["directory"] + "/analysis.json"))
    blocks.append(("links", links))
    blocks.append(("code", "python3 tools/report/report.py <실험 디렉터리> <보고서 디렉터리>"))

    title_text = "TLS 핸드셰이크 네 구간 상세 보고서"
    markdown = ["# " + title_text]
    html = ["<!doctype html><html lang='ko'><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
            "<title>" + title_text + "</title>",
            "<style>body{font:16px/1.75 system-ui,sans-serif;max-width:1150px;margin:40px auto;padding:0 24px;color:#1c2936}h2{margin-top:32px;font-size:22px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:8px 10px;text-align:left;border-bottom:1px solid #d8e0e6;vertical-align:top}th{background:#f1f4f7}.table{overflow:auto}a{color:#275c91}pre{padding:14px;background:#f1f4f7;overflow:auto}@media print{body{font-size:11px;margin:0}table{font-size:10px}tr{break-inside:avoid}}</style>",
            "<h1>" + title_text + "</h1>"]
    for kind, *args in blocks:
        if kind == "p":
            markdown.append(args[0])
            html.append("<p>" + escape(args[0]) + "</p>")
        elif kind == "h2":
            markdown.append("## " + args[0])
            html.append("<h2>" + escape(args[0]) + "</h2>")
        elif kind == "table":
            headers, rows = args
            markdown.append("\n".join(["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"] +
                                      ["| " + " | ".join(str(v).replace("|", "\\|").replace("\n", " ") for v in row) + " |" for row in rows]))
            html.append("<div class='table'><table><thead><tr>" + "".join("<th>" + escape(v) + "</th>" for v in headers) +
                        "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + escape(str(v)) + "</td>" for v in row) + "</tr>" for row in rows) + "</tbody></table></div>")
        elif kind == "links":
            markdown.append(" · ".join(f"[{label}]({target})" for label, target in args[0]))
            html.append("<p>" + " · ".join(f'<a href="{escape(target)}">{escape(label)}</a>' for label, target in args[0]) + "</p>")
        elif kind == "code":
            markdown.append("```sh\n" + args[0] + "\n```")
            html.append("<pre><code>" + escape(args[0]) + "</code></pre>")
    (root / "report.md").write_text("\n\n".join(markdown) + "\n")
    (root / "report.html").write_text("\n".join(html) + "\n</html>\n")
