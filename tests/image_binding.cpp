#include "process/images.hpp"
#include "process/process.hpp"
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <signal.h>
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
    std::ofstream(std::getenv("TURTLE_TEST_HASH_STARTED")) << getpid();
    signal(SIGTERM, SIG_IGN);
    sleep(20);
    return 1;
  }
  expect(argc == 2, "usage: test MODULE");
  const auto self = process::image_inventory(getpid(), getpid());
  expect(process::image_key(self, getpid()).at("mapped").size() >= 1,
         "direct executable not identified");
  expect(!process::image_inventory(getpid(), getppid())
              .at("available")
              .get<bool>(),
         "unrelated pid accepted");
  auto module = fs::canonical(argv[1]);
  auto base = process::image_key(self, getpid());
  void *handle = dlopen(module.c_str(), RTLD_NOW | RTLD_LOCAL);
  expect(handle != nullptr, "load module");
  auto inventory = process::image_inventory(getpid(), getpid());
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
  const auto begin = std::chrono::steady_clock::now();
  auto slow = process::image_inventory(getpid(), getpid(), process::deadline(0.5));
  const auto elapsed = std::chrono::steady_clock::now() - begin;
  expect(fs::is_regular_file(started), "slow hash was not exercised");
  fs::remove(fake); fs::remove(started); fs::remove(path);
  expect(!slow.at("available").get<bool>() && slow.at("reason") == "image_snapshot_timeout",
         "timed out inventory accepted");
  expect(elapsed < std::chrono::seconds(2), "slow hash held release for child cleanup");
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
