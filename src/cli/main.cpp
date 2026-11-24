#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include "native/stream.hpp"
#include <charconv>
#include <iostream>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace {
constexpr auto usage =
    "usage: turtle check SPEC | turtle run SPEC NEW_OUTPUT | turtle analyze "
    "RUN | turtle retry OLD_RUN FAILED_CONNECTION_ID NEW_OUTPUT | turtle "
    "target client|server NEW_OUTPUT APP [ARGS...] | turtle "
    "--client|--server NEW_OUTPUT APP [ARGS...]";
}
int main(int argc, char **argv) {
  try {
    std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd == "__capture" && argc == 6) {
      unsigned port = 0;
      std::string_view text(argv[5]);
      auto [pos, err] = std::from_chars(text.begin(), text.end(), port);
      if (err != std::errc() || pos != text.end() || !port || port > 65535)
        throw std::runtime_error("invalid_capture_port");
      return turtle::capture::collect(argv[2], argv[3], argv[4], port);
    }
    if (cmd == "--help" || cmd == "--version") {
      std::cout << "TURTLE C++20\n" << usage << '\n';
      return 0;
    }
    if (argc == 3 && cmd == "check")
      return turtle::native::check(argv[2]);
    if (argc == 3 && cmd == "analyze") {
      auto root = std::filesystem::absolute(argv[2]);
      if (turtle::artifact::load(root / "manifest.json").at("schema") ==
          "turtle.native-manifest.v1")
        return turtle::native::regenerate(root);
      return turtle::analysis::regenerate(root)
                 ? 0
                 : 1; // archived v2/v3, never live admission
    }
    turtle::artifact::Json p;
    std::filesystem::path out;
    if (cmd == "retry" && argc == 5) {
      out = argv[4];
    } else if (cmd == "run" && argc == 4) {
      p = argv[2];
      out = argv[3];
    } else {
      int n = cmd == "target" ? 4 : 3;
      if ((cmd != "target" && cmd != "--client" && cmd != "--server") ||
          argc <= n)
        throw std::runtime_error(usage);
      auto av = turtle::artifact::Json::array();
      for (int i = n; i < argc; ++i)
        av.push_back(argv[i]);
      p = {{"v", 1},
           {"target",
            {{"role", cmd == "target" ? argv[2] : cmd.substr(2)},
             {"argv", av}}}};
      out = argv[n - 1];
    }
    ::signal(SIGPIPE, SIG_IGN);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr))
      throw std::runtime_error("signal_mask_failed");
    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0)
      throw std::runtime_error("signalfd_failed");
    struct Close {
      int fd;
      ~Close() { ::close(fd); }
    } close{fd};
    if (cmd == "retry")
      return turtle::native::retry(argv[2], argv[3], out,
                                   std::filesystem::canonical("/proc/self/exe"),
                                   fd);
    return turtle::native::execute(
        p, out, std::filesystem::canonical("/proc/self/exe"), fd);
  } catch (const std::exception &e) {
    std::cerr << "turtle: " << e.what() << '\n';
    return 1;
  }
}
