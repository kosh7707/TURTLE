#include "process/images.hpp"
#include "process/process.hpp"
#include <dlfcn.h>
#include <iostream>
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
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
