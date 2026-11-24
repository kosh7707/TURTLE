#include "process/images.hpp"
#include "process/process.hpp"
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
namespace fs = std::filesystem;
using namespace turtle;
using artifact::Json;
namespace {
void expect(bool ok, const char *why) {
  if (!ok)
    throw std::runtime_error(why);
}
} // namespace
int main(int argc, char **argv) try {
  if (std::string_view(argv[0]) == "sha256sum") {
    signal(SIGTERM, SIG_IGN);
    const auto child = fork();
    if (!child) {
      sleep(20);
      _exit(1);
    }
    expect(child > 0, "cannot start hash descendant");
    std::ofstream(std::getenv("TURTLE_TEST_HASH_STARTED")) << getpid() << ' ' << child;
    sleep(20);
    return 1;
  }
  expect(argc == 2, "usage: test MODULE");
  expect(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "cannot test snapshot ownership");
  process::ImageSnapshots images;
  const auto self = images.collect(getpid(), getpid());
  expect(process::image_key(self, getpid()).at("mapped").size() >= 1,
         "direct executable not identified");
  expect(!images.collect(getpid(), getppid())
              .at("available")
              .get<bool>(),
         "unrelated pid accepted");
  auto module = fs::canonical(argv[1]);
  auto base = process::image_key(self, getpid());
  void *handle = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
  expect(handle != nullptr, "load module");
  auto inventory = images.collect(getpid(), getpid());
  auto changed = process::image_key(inventory, getpid());
  expect(changed != base && changed.at("mapped").at(module.string()) ==
                                process::digest(module),
         "module drift not detected");
  dlclose(handle);
  expect(process::image_key(inventory, getpid()) == changed,
         "offline inventory consulted running process");
  char path[] = "/tmp/turtle-image-budget-XXXXXX";
  expect(mkdtemp(path) != nullptr, "temp directory");
  fs::path fake = fs::path(path) / "sha256sum", started = fs::path(path) / "started";
  fs::create_symlink(fs::canonical("/proc/self/exe"), fake);
  setenv("PATH", path, 1);
  setenv("TURTLE_TEST_HASH_STARTED", started.c_str(), 1);
  pid_t sentinel = fork();
  if (!sentinel)
    _exit(47);
  expect(sentinel > 0, "cannot start unrelated child");
  for (int i = 0; i < 2; ++i) {
    process::ImageSnapshots attempt;
    const auto begin = std::chrono::steady_clock::now();
    auto slow = attempt.collect(getpid(), getpid(), process::deadline(0.5));
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    expect(fs::is_regular_file(started), "slow hash was not exercised");
    fs::remove(started);
    expect(!slow.at("available").get<bool>() && slow.at("reason") == "image_snapshot_timeout",
           "timed out inventory accepted");
    expect(elapsed < std::chrono::seconds(2), "slow hash held release for child cleanup");
  }
  fs::remove(fake);
  fs::remove(path);
  int status;
  expect(waitpid(sentinel, &status, 0) == sentinel && WIFEXITED(status) && WEXITSTATUS(status) == 47,
         "snapshot consumed unrelated child");
  // This subreaper must own neither live children nor uncollected zombies.
  int leaked = 0;
  pid_t rc;
  while ((rc = waitpid(-1, nullptr, WNOHANG)) > 0)
    ++leaked;
  expect(rc == -1 && errno == ECHILD && !leaked,
         ("snapshot left children: " + std::to_string(leaked)).c_str());
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
