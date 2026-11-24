#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include "control/controller.hpp"
#include <charconv>
#include <iostream>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
namespace {
constexpr auto usage =
    "usage: turtle check SPEC | turtle run SPEC OUTPUT | turtle analyze RUN | "
    "turtle retry OLD_RUN FAILED_RUN_ID NEW_OUTPUT | turtle target "
    "client|server OUTPUT APP [ARGS...]";
}
int main(int argc, char **argv) {
  try {
    if (argc == 2 && (std::string(argv[1]) == "--help" ||
                      std::string(argv[1]) == "--version")) {
      std::cout << "TURTLE C++20\n" << usage << '\n';
      return 0;
    }
    if (argc == 6 && std::string(argv[1]) == "__capture") {
      unsigned port{};
      std::string_view s(argv[5]);
      auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), port);
      if (ec != std::errc{} || p != s.data() + s.size() || !port ||
          port > 65535)
        throw std::runtime_error("invalid_capture_port");
      return turtle::capture::collect(argv[2], argv[3], argv[4], port);
    }
    if (argc == 3 && std::string(argv[1]) == "check")
      return turtle::control::check(argv[2]);
    if (argc == 3 && std::string(argv[1]) == "analyze")
      return turtle::analysis::regenerate(std::filesystem::absolute(argv[2]))
                 ? 0
                 : 1;
    bool retry = argc == 5 && std::string_view(argv[1]) == "retry";
    bool target = argc >= 5 && std::string_view(argv[1]) == "target";
    if (!retry && !target && (argc != 4 || std::string_view(argv[1]) != "run"))
      throw std::runtime_error(usage);
    ::signal(SIGPIPE, SIG_IGN);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr))
      throw std::runtime_error("signal_mask_failed");
    int cancel = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (cancel < 0)
      throw std::runtime_error("signalfd_failed");
    struct Close {
      int fd;
      ~Close() { ::close(fd); }
    } owned{cancel};
    auto self = std::filesystem::canonical("/proc/self/exe").string();
    if (retry)
      return turtle::control::retry(argv[2], argv[3], argv[4], self, cancel);
    if (target) {
      auto args = turtle::artifact::Json::array();
      for (int i = 4; i < argc; ++i)
        args.push_back(argv[i]);
      return turtle::control::execute_target(argv[2], args, argv[3], self,
                                             cancel);
    }
    return turtle::control::execute(argv[2], argv[3], self, cancel);
  } catch (const std::exception &e) {
    std::cerr << "turtle: " << e.what() << '\n';
    return 1;
  }
}
