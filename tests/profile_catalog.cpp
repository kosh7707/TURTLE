#include "profiling/profiling.hpp"
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
using namespace turtle::artifact;
namespace fs = std::filesystem;
namespace {
void offline_replay(const fs::path &root) {
  auto role = root / "client";
  fs::create_directories(role);
  fs::create_directory(root / "tools");
  fs::create_symlink(turtle::process::executable("sha256sum"),
                     root / "tools/sha256sum");
  // The analysis host has the integrity utility but no perf decoder.
  if (::setenv("PATH", (root / "tools").c_str(), 1))
    throw std::runtime_error("cannot isolate PATH");
  write_text(role / "perf.data", "archived recording fixture");
  save(role / "profile.json",
       {{"schema", "turtle.cpu-collection.v1"}, {"clock", "CLOCK_MONOTONIC"},
        {"ordinary_timing_sample", false}, {"status", "collected"},
        {"event", "cycles:u"}, {"frequency_hz", 997},
        {"perf", "/old-collector/bin/perf"},
        {"perf_data_sha256", turtle::process::digest(role / "perf.data")},
        {"binaries", Json::array()}});
  Json summary = {{"collection", {{"cpu_samples", true}}}, {"pid", 123},
                  {"tid", 123}, {"scenario", {{"begin", {{"wall_ns", 100}}},
                                             {"end", {{"wall_ns", 200}}}}}};
  auto replay = [&] {
    return turtle::profiling::analyze(role, summary, Json::array(), Json::object());
  };
  auto expect_missing = [&](const std::string &reason) {
    auto r = replay();
    if (r.at("availability") != "missing" || r.at("reason") != reason)
      throw std::runtime_error("expected " + reason + ": " + r.dump());
  };
  auto decoded = role / "perf.script.txt";
  const std::string row = "123/123 0.000000150: 9 cycles:u: ab foo ([vdso])\n";
  Json saved;
  auto &cmd = saved["roles"]["client"]["cpu_profile"]["analysis_command"];
  cmd = {{"returncode", 0}, {"stdout", "perf.script.txt"}};
  save(root / "analysis.json", saved);
  expect_missing("archived_perf_script_missing");
  if (fs::exists(decoded))
    throw std::runtime_error("offline analysis created decoder output");
  write_text(decoded, row);
  fs::remove(root / "analysis.json");
  expect_missing("archived_perf_script_status_missing");
  write_text(root / "analysis.json", "{");
  expect_missing("archived_perf_script_status_missing");
  save(root / "analysis.json", saved);
  // Publish the unsuccessful result exactly as the attempt writer does. Data
  // and the archived decoder receipt must still be usable after host repair.
  fs::rename(root / "tools/sha256sum", root / "tools/offline");
  auto failed = replay();
  if (failed.at("availability") != "missing")
    throw std::runtime_error("unverified recording accepted without SHA-256");
  saved["roles"]["client"]["cpu_profile"] = failed;
  save(root / "analysis.json", saved);
  fs::rename(root / "tools/offline", root / "tools/sha256sum");
  write_text(decoded, "incomplete decoder output\n");
  auto incomplete = replay();
  if (incomplete.at("availability") != "missing" ||
      incomplete.contains("perf_script_sha256"))
    throw std::runtime_error("unparsed decoder output accepted or pinned");
  saved["roles"]["client"]["cpu_profile"] = incomplete;
  save(root / "analysis.json", saved);
  write_text(decoded, row);
  auto r = replay();
  if (r.at("availability") != "available" || r.at("scenario").at("period_sum") != 9 ||
      r.at("scenario").at("unknown_symbol_samples") != 1 || read_text(decoded) != row)
    throw std::runtime_error("offline profile replay failed: " + r.dump());
  saved["roles"]["client"]["cpu_profile"] = r;
  save(root / "analysis.json", saved);
  if (replay() != r)
    throw std::runtime_error("offline replay is not repeatable");
  write_text(decoded, row + row);
  expect_missing("archived_perf_script_changed");
  write_text(decoded, row);
  saved["roles"]["client"]["cpu_profile"]["analysis_command"]["returncode"] = 1;
  save(root / "analysis.json", saved);
  expect_missing("archived_perf_script_failed");
}
} // namespace
int main(int argc, char **argv) try {
  if (argc != 3)
    return 1;
  fs::create_directories(argv[1]);
  auto pattern = (fs::absolute(argv[1]) / "catalog-XXXXXX").string();
  if (!::mkdtemp(pattern.data()))
    return 1;
  const fs::path root(pattern);
  write_text(root / "perf.data", "catalog parser fixture");
  const auto executable = fs::absolute(argv[2]);
  for (const auto &[module, expected] :
       {std::pair{"/tmp/perf-vdso.so-aB123z", true},
        std::pair{"[vdso32]", true},
        std::pair{"/tmp/perf-vdso.so-aB123z/mapped.so", false},
        std::pair{"/usr/lib/unspecified.so", false}}) {
    write_text(root / "catalog", std::string("0123 [vdso]\n") +
                                     std::string(41, ' ') + module + "\n");
    save(root / "profile.json",
         {{"perf", executable.string()}, {"commands", Json::array()}});
    turtle::profiling::finish(root, 0);
    auto p = load(root / "profile.json");
    if ((p.at("status") == "collected") != expected ||
        p.at("unparsed_build_ids").empty() != expected)
      return 1;
  }
  offline_replay(root);
  fs::remove_all(root);
  std::cout << "Profile catalog and data-only legacy replay verified\n";
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
