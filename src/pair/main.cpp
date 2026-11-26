// Compatibility diagnostic only: never returns a benchmark measurement.
#include "mock.hpp"
#include "process/process.hpp"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fstream>
#include <future>
#include <iostream>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace {
using namespace turtle::process;
using turtle::artifact::Json;
namespace fs = std::filesystem;
unsigned port_number(std::string_view text) {
  unsigned port = 0;
  const auto [p, ec] =
      std::from_chars(text.data(), text.data() + text.size(), port);
  if (ec != std::errc{} || p != text.data() + text.size() || !port ||
      port > 65535)
    throw std::runtime_error("expected READY and decimal port 1..65535");
  return port;
}
struct Commands {
  Args server, client;
};
Commands load_profile(const fs::path &file) {
  auto profile = turtle::artifact::load(file);
  auto args = [&](const char *role) {
    auto a = profile.at(role).get<Args>();
    if (a.empty() || a.front().empty() ||
        std::any_of(a.begin(), a.end(), [](const auto &s) {
          return s.find('\0') != std::string::npos;
        }))
      throw std::runtime_error(std::string("invalid argv for ") + role);
    return a;
  };
  Commands commands{args("server"), args("client")};
  if (std::none_of(
          commands.client.begin(), commands.client.end(),
          [](const auto &s) { return s.find("{port}") != std::string::npos; }))
    throw std::runtime_error("missing {port} in client argv");
  fs::current_path(fs::absolute(file).parent_path());
  return commands;
}
void supervise(Commands commands, const fs::path &out, int cancel) {
  auto end = deadline(30);
  Child server(commands.server, {}, out / "server.err");
  server.close_input();
  const std::string ready = server.line(end, cancel);
  if (!ready.starts_with("READY "))
    throw std::runtime_error("server did not announce READY");
  const std::string port =
      std::to_string(port_number(std::string_view(ready).substr(6)));
  for (auto &arg : commands.client) {
    for (size_t pos = 0; (pos = arg.find("{port}", pos)) != arg.npos;
         pos += port.size())
      arg.replace(pos, 6, port);
  }
  Child client(commands.client, {}, out / "client.err");
  client.close_input();
  auto server_log = std::async(std::launch::async, [&] {
    turtle::artifact::write_text(out / "server.log",
                                 ready + "\n" + server.collect(end, cancel));
  });
  try {
    turtle::artifact::write_text(out / "client.log",
                                 client.collect(end, cancel));
    if (client.wait(end, cancel) != 0)
      throw std::runtime_error("client exited unsuccessfully");
    server_log.get();
    if (server.wait(end, cancel) != 0)
      throw std::runtime_error("server exited unsuccessfully");
  } catch (...) {
    server.stop(); // release a blocked reader and terminate the server's
                   // process group
    throw;
  }
}
int run_pair(const char *profile, const fs::path &out) {
  ::umask(0077);
  if (::mkdir(out.c_str(), 0700) != 0)
    throw std::system_error(errno, std::generic_category(), out.string());
  Json report = {{"mode", profile ? "external" : "mock"},
                 {"performance_eligible", false},
                 {"status", "failed"}};
  try {
    sigset_t signals;
    sigemptyset(&signals);
    for (auto sig : {SIGTERM, SIGINT, SIGHUP})
      sigaddset(&signals, sig);
    if (sigprocmask(SIG_BLOCK, &signals, nullptr) != 0)
      throw std::runtime_error("cannot block interrupts");
    int cancel = signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
    if (cancel < 0)
      throw std::runtime_error("cannot supervise signals");
    struct Close {
      int fd;
      ~Close() { ::close(fd); }
    } owned{cancel};
    auto self = fs::read_symlink("/proc/self/exe").string();
    auto commands = profile ? load_profile(profile)
                            : Commands{{self, "--mock-server"},
                                       {self, "--mock-client", "{port}"}};
    supervise(std::move(commands), out, cancel);
    report["status"] = "ok";
  } catch (const std::exception &e) {
    report["error"] = e.what();
    std::cerr << "pair diagnostic: " << e.what() << '\n';
  }
  turtle::artifact::save(out / "run.json", report);
  return report["status"] == "ok" ? 0 : 1;
}
} // namespace
int main(int argc, char **argv) try {
  if (argc == 2 && std::string_view(argv[1]) == "--mock-server") {
    mock_role(false, 0);
    return 0;
  }
  if (argc == 3 && std::string_view(argv[1]) == "--mock-client") {
    mock_role(true, port_number(argv[2]));
    return 0;
  }
  if (argc != 2 && argc != 3)
    throw std::runtime_error("usage: turtle-pair [PROFILE] NEW_OUTPUT");
  return run_pair(argc == 3 ? argv[1] : nullptr,
                  std::filesystem::absolute(argv[argc - 1]));
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
