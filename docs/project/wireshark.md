# Wireshark 독립 대조

Wireshark/TShark는 원본 pcap에서 TURTLE 프레임 계층이 의도대로 동작하는지 확인하는 선택적 개발 도구다. 프레임워크와 논문 계측 경로에는 포함하지 않는다.

```sh
python3 tools/wireshark/check_capture.py verify \
  out/runs/comparison/attempts/00000 out/runs/wireshark-check
python3 tools/wireshark/check_capture.py open \
  out/runs/comparison/attempts/00000 --capture client
```

`tools/wireshark/turtle.lua`는 TCP 재조립 뒤 TU 헤더와 원래 TLS 레코드를 분리해 표시한다. TShark는 원본 패킷의 TCP 시퀀스·페이로드와 C++ 분석의 패킷 범위를 대조하고, 재조립한 TLS 바이트를 엔드포인트 스트림과 비교한다. 입력 pcap·스트림·분석 파일은 변경하지 않는다. 검증 자료는 지정한 별도 출력 디렉터리에 쓴다.

이 대조는 암호화 메시지를 복호화하거나 내부 TLS 함수의 시간을 측정하지 않는다. 프레임워크의 성공 여부는 C++ 분석기가 판단한다. GUI를 열지 않고도 TShark 검증을 실행할 수 있다.
