#pragma once
namespace turtle::submission {
constexpr const char *end_event(char scenario, bool server) {
  switch (scenario) {
  case '0': return "handshake_complete";
  case '1': return server ? "request_validated" : "request_write_accepted";
  case '2': return server ? "cf_transport_receive" : "greeting_full_read";
  case '3':
  case '4': return server ? "reply_write_accepted" : "reply_first_read";
  default: return "";
  }
}
}
