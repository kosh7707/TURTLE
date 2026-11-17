#ifndef TURTLE_IMPLEMENTATION_H
#define TURTLE_IMPLEMENTATION_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum turtle_role { TURTLE_CLIENT, TURTLE_SERVER } turtle_role;
enum { TURTLE_TLS13 = 0x0304 };
/* 구현자가 선택한 실행 조건의 선언이다. 암호화 메시지의 내용 검사 결과가 아니다.
 * SERVER_AUTH_1RTT: 인증서 기반 서버 인증, 클라이언트 인증/0-RTT/재개/HRR 없음,
 * 핸드셰이크 호출 중 응용 데이터와 세션 티켓 없음. 호환용 CCS는 허용한다.
 * 조건을 보장하지 않는 구현은 UNSPECIFIED를 반환한다. */
typedef enum turtle_handshake_profile {
    TURTLE_PROFILE_UNSPECIFIED = 0,
    TURTLE_PROFILE_SERVER_AUTH_1RTT = 1
} turtle_handshake_profile;
/* 동기식, 호출 스레드 전용이다. 양수는 진행, 0은 EOF, -1은 실패다.
 * 부분 진행을 허용한다. state와 버퍼는 빌려 쓰며 소켓을 소유하지 않는다.
 * send가 반환하기 전에 그 호출에서 만든 프레임 출력을 소켓에 제출한다. */
typedef struct turtle_transport {
    void* state;
    ptrdiff_t (*receive)(void*, void*, size_t);
    ptrdiff_t (*send)(void*, const void*, size_t);
} turtle_transport;

typedef struct turtle_handshake_info {
    uint16_t version;             /* 표시 문자열이 아닌 정규화한 버전 */
    int resumed;                  /* 0: 전체, 1: 재개, -1: 알 수 없음 */
    const char* cipher;            /* NULL: 미지원. release까지 유효하다. */
    const char* group;             /* NULL: 미지원. release까지 유효하다. */
    turtle_handshake_profile profile;
} turtle_handshake_info;
/* 소스 계약이며 바이너리 플러그인 ABI가 아니다. 모든 함수는 동기식이다.
 * prepare는 컨텍스트 하나와 연결 하나를 소유한 상태를 반환한다.
 * 실패하면 자체 자원을 정리하고 NULL을 반환한다. argv는 해석 없이 전달한다.
 * transport/argv 수명은 release까지다. release는 I/O 없이 모두 해제한다.
 * handshake는 성공 시 info를 채우고 1, 실패 시 0을 반환한다.
 * shutdown은 선택적이다(NULL 허용). 성공 1/실패 0이며 시나리오 밖에서 호출한다.
 * 준비 중 네트워크 I/O와 별도 작업 스레드에서 전송 호출은 허용하지 않는다. */
typedef struct turtle_implementation {
    const char* name;
    void* (*prepare)(turtle_role, int argc, const char* const* argv, turtle_transport);
    void (*release)(void*);
    int (*handshake)(void*, turtle_handshake_info*);
    ptrdiff_t (*read)(void*, void*, size_t);
    ptrdiff_t (*write)(void*, const void*, size_t);
    int (*shutdown)(void*);
} turtle_implementation;
#ifdef __cplusplus
}
#endif
#endif
