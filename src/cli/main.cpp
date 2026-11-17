#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include "control/controller.hpp"
#include <iostream>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
int main(int argc, char **argv) {
  try {
    if (argc == 2 && (std::string(argv[1]) == "--help" ||
                      std::string(argv[1]) == "--version")) {
      std::cout << "TURTLE C++20\nusage: turtle run SPEC OUTPUT | turtle "
                   "analyze RUN\n";
      return 0;
    }
    if (argc == 5 && std::string(argv[1]) == "__capture")
      return turtle::capture::collect(argv[2], argv[3], argv[4]);
    if (argc == 3 && std::string(argv[1]) == "analyze")
      return turtle::analysis::regenerate(std::filesystem::absolute(argv[2]))
                 ? 0
                 : 1;
    if (argc != 4 || std::string(argv[1]) != "run")
      throw std::runtime_error(
          "usage: turtle run SPEC OUTPUT | turtle analyze RUN");
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
    return turtle::control::execute(argv[2], argv[3], self, cancel);
  } catch (const std::exception &e) {
    std::cerr << "turtle: " << e.what() << '\n';
    return 1;
  }
}
