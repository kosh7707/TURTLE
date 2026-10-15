# 인용 후보 문헌 목록

이 폴더에는 논문에 인용할 문헌의 PDF를 모읍니다. 이 문서는 2026년 10월 15일에 만든 후보 목록이며, 어느 절에 어떤 뜻으로 쓸지를 항목마다 적었습니다. 분량 제한이 빡빡하므로 **필수**, **권장**, **선택**으로 나눴습니다. 논증은 여섯 항목 틀을 따릅니다. 현상과 배경, 문제와 실제 영향, 선행 연구, 남은 공백, 해결, 실험 근거입니다.

표시가 **확인**인 항목은 기억에 의존한 서지 정보이므로 내려받을 때 학회와 연도를 다시 확인해야 합니다. 표시가 없는 항목은 2026년 10월 15일에 원문이나 공식 페이지로 확인했습니다. arXiv와 ePrint만 있는 문헌은 "이런 연구가 진행되고 있다"를 보이는 데 쓰고, 핵심 주장의 근거로는 쓰지 않습니다.

---

## 1. 현상과 배경

### 1.1 표준 문서

- **필수** RFC 9846, "The Transport Layer Security (TLS) Protocol Version 1.3", E. Rescorla, 2026년 7월. RFC 8446을 대체합니다.
  쓰임: 전체 핸드셰이크의 정의, 4.6.1절의 NewSessionTicket이 "보낼 수 있다(MAY)"는 규정, 부록 D.4의 호환용 ChangeCipherSpec, PSK와 재개를 범위에서 빼는 근거입니다.
  https://www.rfc-editor.org/rfc/rfc9846.html

- **권장** RFC 8879, "TLS Certificate Compression", 2020년 12월.
  쓰임: 표준화된 인증서 쪽 경량화 기법의 예입니다. 배치자의 선택을 "기법"으로 다루는 실험 조건 가운데 하나입니다.
  https://www.rfc-editor.org/rfc/rfc8879.html

- **선택** RFC 8449, "Record Size Limit Extension for TLS", 2018년 8월.
  쓰임: 레코드 크기 제한을 배치자의 선택으로 다룰 때 인용합니다.
  https://www.rfc-editor.org/rfc/rfc8449.html

- **권장** draft-ietf-uta-tls13-iot-profile-24, "TLS/DTLS 1.3 Profiles for the Internet of Things", 2026년 8월. 아직 RFC가 아니며 IESG 검토 중입니다.
  쓰임: IETF 스스로 경량화의 비용을 "철저히 평가해야 한다"고 하면서도 바이트 수와 RAM 수치만 제시한다는 점을 1번 항목에서 인용합니다. 인용 전에 해당 절의 문장을 -24 판에서 다시 찾아야 합니다.
  https://datatracker.ietf.org/doc/html/draft-ietf-uta-tls13-iot-profile-24

- **선택** RFC 9528, "Ephemeral Diffie-Hellman Over COSE (EDHOC)", 2024년 3월.
  쓰임: 범위 밖 프로토콜이지만, 1.2절에서 DTLS 1.3과 바이트 수만으로 비교하는 문장이 "바이트 수만 비교하는 문화"의 예가 됩니다.
  https://www.rfc-editor.org/rfc/rfc9528.html

- **선택** draft-ietf-tls-ctls-10, "Compact TLS 1.3", 2024년 4월. 2년 넘게 갱신이 없습니다.
  쓰임: 범위 밖이라고 밝힐 때만 인용합니다.
  https://datatracker.ietf.org/doc/html/draft-ietf-tls-ctls-10

- **선택** RFC 7250, "Using Raw Public Keys in TLS and DTLS", 2014년 6월.
  쓰임: 보안 성질이 달라 범위에서 뺀다는 문장에서만 인용합니다.
  https://www.rfc-editor.org/rfc/rfc7250.html

### 1.2 경량화 연구의 예

- **필수** J. Bodenhausen, S. Mangel, T. Vogt, M. Henze, "BiTHaC: Bidirectional TLS Handshake Caching for Constrained Industrial IoT Scenarios", IEEE LCN 2025. arXiv 2508.03321.
  쓰임: wolfSSL을 고친 경량화 기법의 대표 예입니다. 대역폭 61.1퍼센트, 연산 8.5퍼센트 감소라는 수치가 어떤 구간에서 나온 것인지를 2번 항목에서 묻습니다. 재측정 후보이기도 합니다. arXiv 페이지에 코드 링크가 없으므로 저자에게 요청해 볼 만합니다.
  https://arxiv.org/abs/2508.03321

- **필수** D. Goncharskyi 외, "Lightweight TLS 1.3 Handshake for C-ITS Systems", IEEE ICC 2023. **확인** (ResearchGate에는 2023년 5월로 표시되며 ICC 게재는 IEEE Xplore에서 확인해야 합니다.)
  쓰임: OpenSSL 3.0.6에 "Certificate Get" 확장을 넣어 인증서 체인 전송을 평균 4874바이트에서 68바이트로 줄였다는 연구입니다. 돌아온 클라이언트에 대한 기법이므로 "어느 연결의 비용인가"라는 우리 질문이 바로 적용됩니다.
  https://www.researchgate.net/publication/374940168_Lightweight_TLS_13_Handshake_for_C-ITS_Systems

- **선택** "An Efficient TLS 1.3 Handshake Protocol with VC Certificate Type", arXiv 2407.12536, 2024년 7월. 저자와 게재처는 **확인**이 필요합니다.
  쓰임: 인증서 쪽 경량화가 계속 나오고 있다는 예로만 씁니다.
  https://arxiv.org/abs/2407.12536

- **권장** G. Restuccia, H. Tschofenig, E. Baccelli, "Low-Power IoT Communication Security: On the Performance of DTLS and TLS 1.3", PEMWN 2020. arXiv 2011.12035.
  쓰임: wolfSSL과 Mbed TLS를 제약 장비에서 시간, 에너지, 메모리로 나란히 잰 드문 학술 비교입니다. 라이브러리마다 따로 만든 시험 프로그램으로 쟀다는 점을 본문에서 확인한 뒤, "여러 라이브러리 비교가 있어도 공용 계약이 없었다"는 문장에 인용합니다.
  https://arxiv.org/abs/2011.12035

- **선택** R. Hummen, J. H. Ziegeldorf, H. Shafagh, S. Raza, K. Wehrle, "Towards Viable Certificate-based Authentication for the Internet of Things", HotWiSec 2013. **확인**
  쓰임: 인증서 기반 핸드셰이크 비용 문제가 10년 넘게 묵은 것임을 한 문장으로 보일 때 인용합니다.

---

## 2. 문제와 실제 영향

- **필수** RFC 9411, "Benchmarking Methodology for Network Security Devices", 2023년 3월.
  쓰임: 표준 벤치마크조차 암호 모음과 버전을 고정하고 재개를 끄지만(4.3.1.4절, 4.3.2.4절), "TLS 핸드셰이크율"의 시작과 끝은 정의하지 않고(7.6.3.4절) 서버의 티켓 발급 여부도 정하지 않으며, 엔드포인트의 CPU와 메모리는 지표가 아닙니다(6.3절). 인용 전에 4.3.2.4절의 티켓 문장을 직접 읽어야 합니다. 6.1절의 보고 항목은 우리 원자료 머리글과 대조할 수 있습니다.
  https://www.rfc-editor.org/rfc/rfc9411.html

- **필수** E. van der Kouwe, G. Heiser, D. Andriesse, H. Bos, C. Giuffrida, "SoK: Benchmarking Flaws in Systems Security", IEEE EuroS&P 2019. **확인**
  쓰임: 보안 학회가 이미 받아들인 벤치마크 결함의 분류입니다. 우리 문제를 그 어휘로 자리매김하면 심사자가 익숙하게 읽습니다.

- **권장** T. Enghardt, T. Zinner, A. Feldmann, "Web Performance Pitfalls", PAM 2019. **확인**
  쓰임: 지표의 정의가 결론을 바꾼다는 것이 웹 성능에서 이미 보였다는 선례입니다. 우리는 그것을 TLS 핸드셰이크의 엔드포인트 비용에서 보입니다.

- **권장** T. Mytkowicz, A. Diwan, M. Hauswirth, P. F. Sweeney, "Producing Wrong Data Without Doing Anything Obviously Wrong!", ASPLOS 2009. **확인**
  쓰임: 환경 요인이 측정을 흔든다는 고전입니다. 코어 고정과 환경 기록을 정당화할 때 인용합니다.

- **권장** 서로 다른 구간 정의의 실제 예로 세 편 안팎을 고릅니다. 모두 양자 내성 쪽이므로 인접 분야의 예로만 씁니다.
  - C. Paquin, D. Stebila, G. Tamvada, "Benchmarking Post-Quantum Cryptography in TLS", PQCrypto 2020. ePrint 2019/1447. `s_time`을 고친 `s_timer`로 클라이언트 벽시계 시간을 재고 네트워크를 모의했습니다.
    https://eprint.iacr.org/2019/1447
  - D. Sikeridis, P. Kampanakis, M. Devetsikiotis, "Post-Quantum Authentication in TLS 1.3: A Performance Study", NDSS 2020. **확인** 구간 정의를 본문에서 확인해야 합니다.
  - "Faster Post-Quantum TLS 1.3 Based on ML-KEM: Implementation and Assessment", arXiv 2404.13544, 2024. `s_server`와 `s_time`으로 초당 연결 수를 쟀습니다.
    https://arxiv.org/abs/2404.13544
  - "Energy-Aware System-Level Evaluation of Post-Quantum TLS on Embedded User Equipment over a Disaggregated 5G Network", arXiv 2607.03988, 2026. 클라이언트 응용 계층에서 시작부터 완료까지를 쟀습니다.
    https://arxiv.org/abs/2607.03988
  쓰임: 같은 해에 나온 논문들이 서로 다른 관측 위치와 구간을 쓴다는 것을 한 문단에서 보입니다.

- **권장** Rustls 성능 보고. J. Aas, J. Birr-Pixton, D. McCarney, "Rustls Outperforms OpenSSL and BoringSSL", 2024년 10월, 그리고 "Q1 2026 Rustls Performance Update", 2026년 4월. 블로그이므로 각주로 다룹니다.
  쓰임: 산업계의 라이브러리 간 비교는 메모리 버퍼로 연결해 "네트워크와 시스템 호출이 없는 상한"임을 스스로 밝힙니다. 비교는 존재하지만 대상이 다르다는 예입니다.
  https://memorysafety.org/blog/rustls-performance-outperforms/
  https://www.memorysafety.org/blog/26q1-rustls-performance/

- **선택** lesismal/go-tls-benchmark (GitHub). 검색 요약에 따르면 클라이언트가 인증서 체인 검증을 건너뜁니다. 인용 전에 README와 코드에서 직접 확인해야 합니다.
  쓰임: 라이브러리 간 비교가 검증을 뺀 채 이루어진 구체적 사례로 각주에 넣습니다.
  https://github.com/lesismal/go-tls-benchmark

- **선택** wolfSSL, "wolfSSL vs MbedTLS: An apples-to-apples benchmark across Intel, ARM, and RISC-V targets" (공급자 블로그).
  쓰임: 공급자도 같은 플래그 빌드의 필요를 인정하지만, 암호 연산 수준이고 공급자가 직접 한 비교라는 점을 각주로 적습니다.
  https://www.wolfssl.com/wolfssl-vs-mbedtls-an-apples-to-apples-benchmark-across-intel-arm-cortex-a-and-cortex-m-and-risc-v-targets/

---

## 3. 선행 연구

### 3.1 고정 계약 벤치마크

- **필수** D. J. Bernstein, T. Lange (편집), "eBACS: ECRYPT Benchmarking of Cryptographic Systems" (SUPERCOP). 웹 자료입니다.
  쓰임: 구현자 계약과 공통 측정을 분리한 원형, 안정화 사분위수(StQ) 통계, 사이클 측정 방식의 출처입니다. 우리 틀이 무엇을 빌리고 무엇을 바꿨는지의 기준점입니다.
  https://bench.cr.yp.to/

- **권장** M. J. Kannwischer, J. Rijneveld, P. Schwabe, K. Stoffelen, "pqm4: Testing and Benchmarking NIST PQC on ARM Cortex-M4", ePrint 2019/844. **확인**
  쓰임: 제약 장비에서 계약 기반으로 스택을 칠해 재는 방식의 출처입니다. 스택 측정을 미지원으로 둔 이유를 설명할 때도 인용합니다.
  https://eprint.iacr.org/2019/844

- **선택** D. Stebila, M. Mosca, "Post-Quantum Key Exchange for the Internet and the Open Quantum Safe Project", SAC 2016. **확인**
  쓰임: 양자 내성 벤치마크가 구현체 하나 위에서 알고리즘만 바꾸므로 비교 가능성을 공짜로 얻었다는 설명에 인용합니다.

### 3.2 TLS 핸드셰이크를 재는 도구

- **권장** rustls ci-bench, `BENCHMARKING.md` (GitHub). 소프트웨어로 인용합니다.
  쓰임: 클라이언트와 서버를 따로 명령어 수로 재는 가장 가까운 TLS 수준 선례입니다. 다만 한 라이브러리, 메모리 통로입니다.
  https://github.com/rustls/rustls/blob/main/BENCHMARKING.md

- **권장** 라이브러리 자체 도구 묶음. 각각 소프트웨어로 인용하고 선행 연구 표의 한 행씩으로 씁니다.
  - OpenSSL perftools (handshake, 메모리 BIO 쌍, 한 프로세스): https://github.com/openssl/perftools
  - OpenSSL `s_time` (클라이언트, 실제 소켓, TCP 연결 포함): https://docs.openssl.org/master/man1/openssl-s_time/
  - wolfSSL `tls_bench` (`-m`이면 메모리 통로, 한 프로세스 양쪽): https://github.com/wolfSSL/wolfssl/tree/master/examples/benchmark
  - Tempesta tls-perf (클라이언트 부하, 실제 소켓, 지연 분포): https://github.com/tempesta-tech/tls-perf
  - GnuTLS `gnutls-cli --benchmark-tls-kx` (한 프로세스): https://www.gnutls.org/manual/
  - Sashan/openssl-bench (rustls 비교용 쌍둥이 도구): https://github.com/Sashan/openssl-bench

### 3.3 바깥에서 관측하는 연구

- **필수** D. Gómez-Cambronero, D. Munteanu, A. I. González-Tablas, "Layered Performance Analysis of TLS 1.3 Handshakes: Classical, Hybrid, and Pure Post-Quantum Key Exchange", SPIQE 2026 (Euro S&P 2026 워크숍). arXiv 2603.11006.
  쓰임: 패킷 캡처와 키 로그로 연결을 다섯 층으로 나눈 연구입니다. 관측 위치가 바깥이라 엔드포인트의 CPU와 메모리를 귀속할 수 없고, 부하 분산기와 HTTP가 사이에 있습니다. 가장 가까운 경쟁 연구이므로 차이를 선명하게 적습니다.
  https://arxiv.org/abs/2603.11006

- **선택** A. A. Giron, F. Schardong, R. Custódio, "TLS 1.3 Handshake Analyzer", SBSeg 2022 (확장 트랙). **확인**
  쓰임: 같은 계열의 도구 논문이 더 있다는 예입니다.
  https://sol.sbc.org.br/index.php/sbseg_estendido/article/view/21693

- **선택** M. Seemann, J. Iyengar, "Automating QUIC Interoperability Testing", EPIQ 2020. **확인**
  쓰임: 캡처와 키 로그 해독이 시험 기반 시설에 이미 쓰인 선례입니다. 상호 운용성 시험은 있는데 벤치마크 틀은 없다는 대조에도 씁니다.

### 3.4 구현체 하나의 비용을 분해한 고전

- **권장** C. Coarfa, P. Druschel, D. S. Wallach, "Performance Analysis of TLS Web Servers", NDSS 2002, 확장판 ACM TOCS 24(1), 2006. **확인**
  쓰임: 핸드셰이크 비용을 쪼개 본 연구가 20년 넘게 있었지만 구현체 하나를 프로파일러로 본 것임을 보입니다.

- **선택** G. Apostolopoulos, V. Peris, D. Saha, "Transport Layer Security: How Much Does It Really Cost?", INFOCOM 1999. **확인**
  L. Zhao, R. Iyer, S. Makineni, L. Bhuyan, "Anatomy and Performance of SSL Processing", ISPASS 2005. **확인**
  쓰임: Coarfa와 함께 한 문장에 묶어 인용합니다. 둘 다 넣을 필요는 없습니다.

- **선택** D. Naylor 외, "The Cost of the 'S' in HTTPS", CoNEXT 2014. **확인**
  쓰임: 비용 질문이 웹 수준에서는 던져졌지만 구현체 수준의 공용 계약으로는 이어지지 않았다는 대조에 씁니다.

### 3.5 제약 장비의 측정 방법 (인접 분야)

- **권장** G. Tasopoulos, J. Li, A. P. Fournaris, R. K. Zhao, A. Sakzad, R. Steinfeld, "Performance Evaluation of Post-Quantum TLS 1.3 on Resource-Constrained Embedded Systems", ISPEC 2022. ePrint 2021/1553. **확인**
  쓰임: wolfSSL을 Cortex-M4에서 시간과 메모리로 잰 방법의 예입니다. 라즈베리파이나 임베디드로 갈 때 메모리 측정의 선례로 씁니다.
  https://eprint.iacr.org/2021/1553

- **선택** K. Bürstinghaus-Steinbach, C. Krauß, R. Niederhagen, M. Schneider, "Post-Quantum TLS on Embedded Systems", AsiaCCS 2020. **확인**
  쓰임: Mbed TLS를 Cortex-M4에서 잰 예로, Tasopoulos와 함께 묶어 인용합니다.

---

## 4. 남은 공백

이 항목은 새 문헌보다 2번과 3번의 표로 논증합니다. 필요하면 RFC 9411의 6.1절 보고 항목과 van der Kouwe의 결함 분류를 다시 인용합니다.

---

## 5. 해결 (설계 근거)

- **필수** RFC 9850, "The SSLKEYLOGFILE Format for TLS", M. Thomson, Y. Rosomakho, H. Tschofenig, 2025년 12월. RFC 번호는 미러 페이지에서 확인했으므로 rfc-editor.org에서 한 번 더 확인해야 합니다.
  쓰임: 우리가 읽는 키 로그 형식의 출처이며, 생산 환경에서 쓰면 안 된다는 규정이 "실험 전용"이라는 우리 입장을 뒷받침합니다.
  https://www.rfc-editor.org/rfc/rfc9850.html

- **선택** M. Fowler, "Inversion of Control Containers and the Dependency Injection pattern", 2004. 웹 자료입니다.
  쓰임: "프레임워크가 라이프사이클을 쥐고 구현자는 정해진 자리에 끼운다"는 원리를 Spring이라는 이름 없이 부를 때 인용합니다.
  https://martinfowler.com/articles/injection.html

- **권장** 리눅스 매뉴얼과 커널 문서. 각주로 씁니다.
  - `perf_event_open(2)`: https://man7.org/linux/man-pages/man2/perf_event_open.2.html
  - `clock_gettime(2)`의 `CLOCK_THREAD_CPUTIME_ID`: https://man7.org/linux/man-pages/man2/clock_gettime.2.html
  - `socket(7)`의 `SO_RCVBUF`와 `SO_SNDBUF`: https://man7.org/linux/man-pages/man7/socket.7.html
  - 커널 타임스탬프 문서(`SO_TIMESTAMPNS`): https://www.kernel.org/doc/html/latest/networking/timestamping.html

- **권장** T. Hoefler, R. Belli, "Scientific Benchmarking of Parallel Computing Systems: Twelve Ways to Tell the Masses when Reporting Performance Results", SC 2015. **확인**
  쓰임: 보고 규칙의 출처입니다. 원자료를 모두 남기고, 분포와 변동을 보이고, 평균을 함부로 쓰지 않는다는 원칙을 한 문장으로 뒷받침합니다.

- **선택** T. Kalibera, R. Jones, "Rigorous Benchmarking in Reasonable Time", ISMM 2013. **확인**
  쓰임: 묶음 반복 구조와 부트스트랩 구간의 근거입니다.

- **선택** B. Efron, R. J. Tibshirani, "An Introduction to the Bootstrap", Chapman and Hall, 1993. **확인**
  쓰임: 부트스트랩 자체의 인용입니다. Kalibera를 넣으면 생략할 수 있습니다.

---

## 6. 실험 근거

- **필수** 측정 대상 소프트웨어의 판을 인용합니다. 판은 저장소 README의 고정 판과 같아야 합니다.
  - OpenSSL 3.5.4: https://www.openssl.org/
  - wolfSSL 5.8.2-stable: https://github.com/wolfSSL/wolfssl
  - Mbed TLS 3.6.4: https://github.com/Mbed-TLS/mbedtls

- 재측정 대상은 1.2절의 BiTHaC와 Certificate Get입니다. 조건 실험의 표준 근거는 1.1절의 RFC 8879와 RFC 8449입니다.

---

## 아직 찾지 못한 것

- 경량화 논문 조사 표에 넣을 논문 10편 안팎의 목록입니다. 연구자가 보유한 문헌에서 먼저 고릅니다.
- 2024년 이후 arXiv와 워크숍에서 "TLS 핸드셰이크 벤치마크 틀"을 직접 다룬 논문이 있는지의 최종 확인입니다. 2026년 10월 15일의 검색에서는 찾지 못했습니다.
- 영어가 아닌 문헌과 학위 논문입니다.
