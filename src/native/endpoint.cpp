#include "native/endpoint_observe.hpp"
#include "native/submission_endpoint.hpp"
#include <turtle/endpoint.h>
#include <turtle/observe.h>
#include <turtle/start.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {
using View = std::string_view;
View env(const char *key) {
  const char *s = std::getenv(key);
  return s ? View(s) : View{};
}
struct Failure {
  turtle_result result;
};
void require(bool ok) {
  if (!ok)
    throw Failure{TURTLE_ERROR};
}
void check(turtle_result rc, bool early_server_action = false) {
  switch (rc) {
  case TURTLE_OK:
    return;
  case TURTLE_UNSUPPORTED:
    if (early_server_action)
      turtle_observe_fact("server_first", 0);
    [[fallthrough]];
  case TURTLE_CLOSED:
    throw Failure{rc};
  default:
    throw Failure{TURTLE_ERROR};
  }
}
std::string supplied(View expected) {
  std::string input(expected.size(), '\0');
  require(std::fread(input.data(), 1, input.size(), stdin) == input.size() &&
          input == expected);
  return input;
}
void publish(View bytes) {
  require(std::fwrite(bytes.data(), 1, bytes.size(), stdout) == bytes.size() &&
          std::fflush(stdout) == 0);
}

struct Scenario {
  const turtle_endpoint &ep;
  turtle_result (*accept_greeting)(void *, const void *, size_t) = nullptr;
  bool started = false, read_first = false;

  void begin_tls(bool reading = false) {
    if (!started) {
      started = true;
      read_first = reading;
      if (reading)
        turtle::native::detail::read_first_event(turtle_observe_now(), false);
      else
        turtle_observe_event("hs_begin");
    }
  }
  void handshake(turtle_hs_point at) {
    begin_tls();
    auto rc = ep.handshake_until(ep.conn, at);
    auto returned = turtle_observe_now();
    check(rc, at == TURTLE_SERVER_CAN_SEND);
    if (read_first) {
      turtle::native::detail::read_first_event(returned, true);
      return;
    }
    turtle_observe_event_at(returned, at == TURTLE_SERVER_CAN_SEND
                                          ? "hs_progress"
                                          : "hs_complete");
  }

  void handshake_with_greeting(View bytes) {
    begin_tls();
    auto rc = accept_greeting(ep.conn, bytes.data(), bytes.size());
    auto returned = turtle_observe_now();
    check(rc, true);
    turtle_observe_event_at(returned, "hs_complete");
    turtle_observe_fact("submission_greeting_accepted", 1);
  }

  void send(View rest, turtle_hs_point at = TURTLE_LOCAL_COMPLETE) {
    const size_t total = rest.size();
    uint64_t anchor = 0;
    while (!rest.empty()) {
      size_t n = 0;
      if (rest.size() == total)
        anchor = turtle::native::detail::full_offer(rest.data(), total);
      else
        turtle::native::detail::suffix_offer(anchor, total - rest.size(), rest.size());
      auto rc = ep.write_plain(ep.conn, at, rest.data(), rest.size(), &n);
      auto returned = turtle_observe_now();
      check(rc, at == TURTLE_SERVER_CAN_SEND);
      require(n && n <= rest.size());
      turtle_observe_plain_at(returned, "write_accepted", rest.data(), n);
      rest.remove_prefix(n);
    }
    if (at == TURTLE_SERVER_CAN_SEND)
      turtle_observe_fact("server_first", 1);
  }

  // A single real TLS return can straddle the greeting/response boundary.
  // Record it once, then validate each complete message separately.
  void receive(View first, View second = {}, std::string *deferred = nullptr) {
    std::string local;
    auto &bytes = deferred ? *deferred : local;
    bytes.resize(first.size() + second.size());
    const std::array<View, 2> messages{first, second};
    size_t used = 0, verified = 0, next = 0;
    while (used != bytes.size()) {
      size_t n = 0;
      size_t cap = bytes.size() - used;
      char *out = bytes.data() + used;
      begin_tls(true);
      auto rc = ep.read_plain(ep.conn, out, cap, &n);
      auto returned = turtle_observe_now();
      check(rc);
      require(n && n <= cap);
      turtle_observe_plain_at(returned, "read_return", out, n);
      used += n;
      while (next < messages.size() && !messages[next].empty() &&
             used - verified >= messages[next].size()) {
        auto msg = View(bytes).substr(verified, messages[next].size());
        require(msg == messages[next]);
        turtle_observe_plain("validated", msg.data(), msg.size());
        if (!deferred)
          publish(msg);
        verified += msg.size();
        ++next;
      }
    }
  }

  void run() {
    View role = env("TURTLE_ROLE"), scenario = env("TURTLE_SCENARIO");
    require(role == "client" || role == "server");
    require(scenario.size() == 2 && scenario[0] == 'S' && scenario[1] >= '0' &&
            scenario[1] <= '4');
    const bool client = role == "client";
    const bool response = scenario == "S3" || scenario == "S4";
    const bool request = scenario == "S1" || response;
    const bool greeting = scenario == "S2" || scenario == "S4";
    View cad = env("TURTLE_REQUEST"), sad1 = env("TURTLE_GREETING"),
         sad2 = env("TURTLE_RESPONSE");
    auto valid = [](View s) { return !s.empty() && s.size() <= 16384; };
    require((!request || valid(cad)) && (!greeting || valid(sad1)) &&
            (!response || valid(sad2)));

    if (!ep.handshake_until ||
        ((client ? request : ((greeting && !accept_greeting) || response)) &&
         !ep.write_plain) ||
        ((client ? (greeting || response) : request) && !ep.read_plain))
      throw Failure{TURTLE_UNSUPPORTED};

    // The server owns its configured response before READY. Only validation
    // of the peer's actual CAD, not a controller pipe round trip, gates TLS.
    const bool server_response = !client && response;
    const std::string reply(server_response ? sad2 : View{});
    std::string outgoing;
    if (client && request)
      outgoing = supplied(cad);
    if (!client && greeting)
      outgoing = supplied(sad1);
    if (server_response)
      turtle::native::detail::ready_with_prepared_response();
    else
      turtle_observe_event("ready");
    require(turtle_wait_start() >= 0);
    const bool composite = !client && greeting && accept_greeting;
    if (composite)
      handshake_with_greeting(outgoing);
    else if (!client && greeting) {
      handshake(TURTLE_SERVER_CAN_SEND);
      send(outgoing, TURTLE_SERVER_CAN_SEND);
    }
    if (client && scenario == "S2")
      receive(sad1); // Arm an ordinary read, not a full-handshake barrier.
    if (!composite)
      handshake(TURTLE_LOCAL_COMPLETE);
    if (client && request)
      send(outgoing);
    std::string received_request;
    if (!client && request)
      receive(cad, {}, server_response ? &received_request : nullptr);
    if (response) {
      if (!client)
        send(reply);
      else if (greeting)
        receive(sad1, sad2);
      else
        receive(sad2);
    }
    turtle_observe_event("end");
    if (server_response) {
      // Finish the same audited stdio transcript as an ordinary participant,
      // but only after the measured operation. Neither stream is synthesized:
      // publish the received bytes and verify the controller's actual copy.
      publish(received_request);
      supplied(reply);
    }
  }
};

turtle_result run_endpoint(
    const turtle_endpoint *ep,
    turtle_result (*accept_greeting)(void *, const void *, size_t)) {
  if (!ep)
    return TURTLE_ERROR;
  try {
    Scenario{*ep, accept_greeting}.run();
    return TURTLE_OK;
  } catch (const Failure &failure) {
    if (failure.result == TURTLE_UNSUPPORTED)
      turtle_observe_fact("endpoint_unsupported", 1);
    return failure.result;
  } catch (...) {
    return TURTLE_ERROR; // Never propagate a C++ exception to the C caller.
  }
}
} // namespace

extern "C" turtle_result turtle_run_endpoint(const turtle_endpoint *ep) {
  return run_endpoint(ep, nullptr);
}

extern "C" turtle_result turtle_observe_run_submission_endpoint(
    const turtle_endpoint *ep,
    turtle_result (*accept_greeting)(void *, const void *, size_t)) {
  return run_endpoint(ep, accept_greeting);
}
