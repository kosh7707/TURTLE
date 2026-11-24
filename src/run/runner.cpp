// Compatibility only: old source adapters run the same role-owned scheduler.
// Native integrations obtain turtle_action directly and bracket the actual
// public TLS call (rather than this legacy aggregate adapter operation).
#include "run/runner.hpp"
#include <memory>
#include <turtle/endpoint.h>
#include <turtle/role.h>
extern "C" int turtle_endpoint_main(const turtle_implementation *api, int argc,
                                    char **argv) {
  if (!api || !api->prepare || !api->release || !api->query ||
      !api->handshake || !api->read || !api->write)
    return 1;
  auto *s = turtle_session_open(argc, argv, api->name, api->hooks,
                                api->server_first != nullptr);
  if (!s)
    return 1;
  turtle::run::mark_legacy(s);
  const auto &c = *turtle_session_config(s);
  turtle_transport t{};
  if (turtle_session_transport(s, &t) != 1)
    return turtle_session_close(s);
  std::unique_ptr<void, decltype(api->release)> tls(
      api->prepare(c.role, c.argc, c.argv, t), api->release);
  if (turtle_session_ready(s, tls != nullptr) == 1) {
    turtle_action a;
    while (turtle_pull(s, &a) == 1 && a.op != TURTLE_DONE) {
      ptrdiff_t rc = -1;
      turtle_before(s);
      switch (a.op) {
      case TURTLE_FIRST_HS:
        rc = 1;
        break; // legacy server_first combines flight + write
      case TURTLE_FIRST_WRITE:
        rc = api->server_first(tls.get(), a.out, a.size);
        break;
      case TURTLE_HS:
        rc = api->handshake(tls.get());
        break;
      case TURTLE_READ:
        rc = api->read(tls.get(), a.in, a.size);
        break;
      case TURTLE_WRITE:
        rc = api->write(tls.get(), a.out, a.size);
        break;
      case TURTLE_SHUTDOWN:
        rc = api->shutdown ? api->shutdown(tls.get()) : -1;
        break;
      default:
        break;
      }
      turtle_returned(s);
      turtle_result result{rc > 0                    ? TURTLE_OK
                           : rc == 0                 ? TURTLE_EOF
                           : rc == TURTLE_WANT_READ  ? TURTLE_AGAIN_READ
                           : rc == TURTLE_WANT_WRITE ? TURTLE_AGAIN_WRITE
                                                     : TURTLE_ERROR,
                           0, 0};
      if (rc > 0 && (a.op == TURTLE_FIRST_WRITE || a.op == TURTLE_WRITE ||
                     a.op == TURTLE_READ))
        result.bytes = rc;
      turtle_handshake_info f{};
      bool facts =
          rc == 1 && a.op == TURTLE_HS && api->query(tls.get(), &f) == 1;
      if (turtle_submit(s, result, facts ? &f : nullptr) < 0)
        break;
    }
  }
  tls.reset();
  return turtle_session_close(s);
}
