#ifndef TURTLE_ENDPOINT_H
#define TURTLE_ENDPOINT_H
#include <turtle/implementation.h>
#ifdef __cplusplus
extern "C" {
#endif
/* 공통 CLI 진입점. 함수표와 인자는 이 호출 동안 빌려 쓴다.
 * -- 뒤의 인자는 prepare에 그대로 전달한다. 프로세스당 한 번 호출한다. */
int turtle_endpoint_main(const turtle_implementation*, int argc, char** argv);
#ifdef __cplusplus
}
#endif
#endif
