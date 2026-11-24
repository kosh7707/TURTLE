#include "process/images.hpp"
#include "process/process.hpp"
#include <iostream>
#include <set>
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
  expect(argc == 5, "usage: test CLI ENDPOINT MODULE WORK");
  const auto self = process::image_inventory(getpid(), getpid());
  expect(process::image_key(self, getpid()).at("mapped").size() >= 1,
         "direct executable not identified");
  expect(!process::image_inventory(getpid(), getppid())
              .at("available")
              .get<bool>(),
         "unrelated pid accepted");
  fs::path root = fs::absolute(argv[4]);
  fs::create_directories(root);
  std::string temp = (root / "run-XXXXXX").string();
  expect(mkdtemp(temp.data()) != nullptr, "private dir");
  root = temp;
  auto wrapper = root / "same launcher", loadable = root / "extra.so";
  fs::copy_file(argv[3], loadable);
  artifact::write_text(
      wrapper,
      "#!/bin/sh\ncase \" $* \" in *' --purpose measurement '*) export "
      "LD_PRELOAD=\"$TEST_MODULE\";; esac\nexec \"$TEST_ENDPOINT\" \"$@\"\n");
  fs::permissions(wrapper, fs::perms::owner_all);
  auto spec = root / "spec.json", run = root / "results";
  artifact::save(
      spec, {{"v", 1},
             {"target", {{"role", "server"}, {"argv", {wrapper.string()}}}},
             {"scenario", "S2"},
             {"auth", "mtls"},
             {"repetitions", 1},
             {"warmups", 1}});
  process::Environment env{{"TEST_MODULE", loadable.string()},
                           {"TEST_ENDPOINT", fs::absolute(argv[2]).string()}};
  auto pre = process::command({argv[1], "check", spec.string()}, 30, env);
  auto checks = Json::parse(pre.at("stdout").get<std::string>());
  if (pre.at("returncode") != 0 && checks.at("configurations")
                                           .at("target")
                                           .at("features")
                                           .at("perf_counters")
                                           .at("availability") != "available")
    return 77;
  expect(pre.at("returncode") == 0, "preflight");
  auto result =
      process::command({argv[1], "run", spec.string(), run.string()}, 60, env);
  expect(result.at("returncode") != 0,
         "probe transferred despite a changed mapped module");
  auto manifest = artifact::load(run / "manifest.json");
  expect(manifest.at("attempts").size() == 3,
         "expected probe, warmup, measurement");
  const auto &last = manifest.at("attempts").back();
  auto dir = run / last.at("directory").get<std::string>();
  auto report = artifact::load(dir / "analysis.json"),
       maps = artifact::load(dir / "images.json");
  expect(report.at("success") == true && !report.at("eligible").get<bool>() &&
             !report.at("ordinary_timing_sample").get<bool>(),
         "conflated TLS task and image evidence");
  expect(report.at("configuration_invalid_reasons").at(0) ==
             "participant_image_changed_between_trials",
         "wrong drift reason");
  const auto &server = maps.at("roles").at("server");
  expect(server.at("ready").at("mapped").at(loadable.string()) ==
             process::digest(loadable),
         "missing loaded module");
  expect(server.at("finished").at("mapped") == server.at("ready").at("mapped"),
         "terminal witness missing");
  fs::remove(wrapper);
  fs::remove(loadable);
  expect(
      process::command({argv[1], "analyze", run.string()}).at("returncode") !=
          0,
      "offline drift accepted");
  expect(report == artifact::load(dir / "analysis.json"),
         "replay consulted host binaries");
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
