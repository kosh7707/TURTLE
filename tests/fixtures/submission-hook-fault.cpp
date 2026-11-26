// Exercise a real TLS task with deliberate observation faults, not a stub handshake.
#define turtle_tls_set_hooks openssl_set_hooks
#include "../../docs/examples/submissions/openssl/implementation.cpp"
#undef turtle_tls_set_hooks

#include <cstdlib>
#include <filesystem>
#include <string_view>
#include <thread>

extern "C" turtle_status turtle_tls_set_hooks(turtle_tls *tls,
                                             const turtle_transport_hooks *hooks) {
  const auto *requested = std::getenv("TURTLE_TEST_HOOK_FAULT");
  const std::string_view fault(requested ? requested : "");
  if (!hooks) {
    auto rc = openssl_set_hooks(tls, hooks);
    return fault == "detach" ? TURTLE_TLS_ERROR : rc;
  }
  if (fault == "error")
    return TURTLE_TLS_ERROR;
  if (fault == "unsupported")
    return TURTLE_TLS_UNSUPPORTED;
  if (fault == "missing")
    return TURTLE_TLS_OK;
  if (fault == "foreign-thread") {
    // A deliberate off-owner observation must not turn a real TLS success
    // into an application error or qualify a misleading partial trace.
    std::thread worker([hooks] { hooks->before_send(hooks->context, nullptr, 1); });
    worker.join();
  }
  if (fault == "legacy" || fault == "failed-send-observation") {
    auto observed = *hooks;
    if (fault == "legacy") {
      observed.coverage = nullptr;
      observed.transfer_begin = nullptr;
      observed.transfer_end = nullptr;
    } else {
      static auto forward = hooks->transfer_end;
      observed.transfer_end = [](void *ctx, int sent, size_t requested,
                                  ptrdiff_t result, const unsigned char *bytes) {
        // Fault only the evidence, not the actual TLS write.
        forward(ctx, sent, requested, sent ? -1 : result, bytes);
      };
    }
    return openssl_set_hooks(tls, &observed);
  }
  if (fault == "maps" || fault == "trace-write" || fault == "count-write") {
    const auto *directory = std::getenv("TURTLE_TEST_EVENTS");
    const auto *id = std::getenv("TURTLE_CONNECTION_ID");
    if (!directory || !id)
      return TURTLE_TLS_ERROR;
    const std::string sidecar = std::string(id) + ".client." +
        (fault == "maps" ? "maps.partial" :
         fault == "count-write" ? "csv.count.partial" : "csv.partial");
    if (!std::filesystem::create_directory(std::filesystem::path(directory) / sidecar))
      return TURTLE_TLS_ERROR;
  }
  if (fault == "overflow") {
    for (int i = 0; i < 8193; ++i) {
      hooks->before_send(hooks->context, nullptr, 1);
      hooks->after_recv(hooks->context, nullptr, 1);
    }
  }
  return openssl_set_hooks(tls, hooks);
}
