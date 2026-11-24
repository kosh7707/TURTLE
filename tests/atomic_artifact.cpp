#include "analysis/analysis.hpp"
#include "artifact/json.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
using namespace turtle::artifact;
namespace fs = std::filesystem;
void expect(bool ok, const char *why) {
  if (!ok)
    throw std::runtime_error(why);
}
template <class F> void refuses(F action) {
  try {
    action();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error("unexpected report destination accepted");
}
int main(int argc, char **argv) try {
  expect(argc == 2, "usage: atomic_artifact WORK");
  fs::create_directories(argv[1]);
  auto pattern = (fs::absolute(argv[1]) / "run-XXXXXX").string();
  expect(::mkdtemp(pattern.data()) != nullptr, "fresh test directory");
  const fs::path root(pattern);
  fs::create_directories(root / "attempts/0");
  for (const auto &dir : {root, root / "attempts/0"}) {
    const auto report = dir / "analysis.json";
    const auto reserved = dir / "analysis.json.tmp";
    write_text(reserved, "reserved");
    save(report, Json{{"valid", false}});
    save(report, Json{{"valid", true}});
    expect(load(report).at("valid") == true, "report replacement");
    expect(fs::exists(reserved) && read_text(reserved) == "reserved",
           "unrelated work file changed");
    struct stat st{};
    expect(lstat(report.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600,
           "report permissions");
    fs::remove(report);
    fs::create_directory(report);
    refuses([&] { save(report, nullptr); });
    expect(fs::is_directory(report), "invalid destination changed");
    fs::remove(report);
    fs::create_symlink("absent", report);
    refuses([&] { save(report, nullptr); });
    expect(fs::is_symlink(report) && !fs::exists(dir / "absent"),
           "dangling destination changed");
    fs::remove(report);
    for (auto &entry : fs::directory_iterator(dir))
      expect(!entry.path().filename().string().starts_with(".turtle-write-"),
             "temporary file not cleaned");
  }
  fs::create_directory_symlink(root / "attempts", root / "alias");
  refuses([&] { save(root / "alias/0/not-a-report", nullptr); });
  expect(!fs::exists(root / "attempts/0/not-a-report"), "alias accepted");
  const Json config = {{"id", "one"},
                       {"measurement_contract", "counts-enough.v1"},
                       {"scenario", "S0"},
                       {"auth", "server"},
                       {"measured_role", "client"},
                       {"warmups", 0},
                       {"required_metrics", Json::array()},
                       {"recording", "basic"},
                       {"application", Json::object()}};
  const Json slot = {{"purpose", "measurement"},
                     {"configuration", "one"},
                     {"run_id", "example"},
                     {"directory", "attempts/0"},
                     {"artifacts_sha256", Json::object()}};
  const Json manifest = {
      {"schema", "turtle.manifest.v3"},
      {"status", "complete"},
      {"spec", {{"repetitions", 1}, {"configurations", Json::array({config})}}},
      {"attempts", Json::array({slot})},
      {"order", Json::array({slot})}};
  save(root / "manifest.json", manifest);
  expect(!turtle::analysis::regenerate(root), "unexpected inventory accepted");
  expect(load(root / "analysis.json").at("eligible_measurements") == 0 &&
             load(root / "attempts/0/analysis.json").at("raw_evidence_valid") ==
                 false,
         "rejection reports not published");
  expect(read_text(root / "analysis.json.tmp") == "reserved" &&
             read_text(root / "attempts/0/analysis.json.tmp") == "reserved",
         "replay touched unrelated working files");
  auto legacy = manifest;
  legacy["schema"] = "turtle.manifest.v2";
  legacy["attempts"][0]["directory"] = "not-an-attempt";
  save(root / "manifest.json", legacy);
  refuses([&] { turtle::analysis::regenerate(root); });
  fs::remove_all(root);
  std::cout << "Confined replacement at aggregate and attempt levels passed\n";
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
