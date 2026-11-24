// Two negative capability declarations, never benchmark implementations.
#include <string_view>
#include <turtle/role.h>
int main(int argc, char **argv) {
  const bool declared = argc > 1 && std::string_view(argv[argc - 1]) == "late";
  auto *s = turtle_session_open(argc, argv, "negative-capability-fixture", 0,
                                declared);
  if (!s)
    return 1;
  turtle_transport io{};
  if (turtle_session_transport(s, &io) == 1 &&
      turtle_session_ready(s, 1) == 1) {
    turtle_action action{};
    if (turtle_pull(s, &action) == 1 && action.op == TURTLE_FIRST_HS) {
      // End-of-HS facts mean CF is already processed. This cannot constitute
      // evidence of a usable pre-CF server send, even with successful TLS.
      const turtle_handshake_info finished{
          TURTLE_TLS13, 0, nullptr, nullptr, TURTLE_PROFILE_MTLS_1RTT, 1, 0};
      turtle_before(s);
      turtle_returned(s);
      turtle_submit(s, {TURTLE_OK, 0, 0}, &finished);
    }
  }
  return turtle_session_close(s);
}
