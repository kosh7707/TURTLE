#include <turtle/endpoint.h>
_Static_assert(TURTLE_TLS13 == 0x0304, "normalized protocol");
_Static_assert(TURTLE_PROFILE_SERVER_AUTH_1RTT == 1, "declared measurement profile");
int main(int argc, char** argv) {
    /* C 소스에서 공통 진입점을 링크한다. TLS 성공 시험이 아니다. */
    return turtle_endpoint_main(NULL, argc, argv) == 1 ? 0 : 1;
}
