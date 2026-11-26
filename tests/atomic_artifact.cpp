#include "analysis/analysis.hpp"
#include "artifact/json.hpp"
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
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
namespace {
template <typename Error = std::exception, typename F> void rejects(F action) {
  try {
    action();
  } catch (const Error &) {
    return;
  }
  throw std::runtime_error("accepted invalid value");
}

void test_json() {
  const auto input = R"({"max":18446744073709551615,"exact":9007199254740993,"min":-9223372036854775808,"fraction":-0.25e1,"zero":0,"unavailable":null,"emoji":"\uD83D\uDE03","esc":"\u0000\t\n\r\f\b\/\\\"","network":{"x":[true,false,[]]}})";
  const auto j = Json::parse(input);
  expect(integer(j.at("max")) == std::numeric_limits<std::uint64_t>::max(),
        "exact uint64 maximum");
  expect(integer(j.at("exact")) == 9007199254740993ULL, "integer beyond 2^53");
  expect(j.at("min").get<std::int64_t>() == std::numeric_limits<std::int64_t>::min(),
        "exact int64 minimum");
  expect(j.at("fraction").get<double>() == -2.5, "finite exponent");
  expect(j.at("unavailable").is_null() && !j.contains("not_reported") &&
            j.at("zero").get<int>() == 0,
        "null, absent, and observed zero differ");
  expect(j.at("emoji") == "\xF0\x9F\x98\x83", "paired surrogate");
  expect(j.at("esc").get<std::string>() == std::string("\0\t\n\r\f\b/\\\"", 9),
        "escape decoding and embedded zero");
  expect(Json::parse(j.dump()) == j && Json::parse(j.dump(2)) == j,
        "compact and indented output round-trip");
  expect(Json::parse(R"({"z":[],"a":1.0})").dump() == R"({"a":1.0,"z":[]})",
        "deterministic keys and round-trip floating kind");
  expect(Json::parse("[[\"key\",1]]").at(0).is_array(), "parsed arrays remain arrays");
  expect(Json::parse("1") == Json(1) && Json(1.0) == Json(1) &&
            Json(9007199254740993ULL) != Json(9007199254740992.0) &&
            Json(UINT64_MAX) != Json(0x1p64) && Json(INT64_MAX) != Json(0x1p63),
        "integer comparisons must not round through double");
  expect(j.value("missing", "none") == "none", "missing fallback");
  rejects([&] { (void)j.value("unavailable", true); });
  rejects([&] { (void)j.at("not_reported"); });
  rejects([&] { (void)j.at("max").get<std::int64_t>(); });
  rejects([&] { (void)integer(j.at("min")); });
  rejects([&] { (void)integer(j.at("fraction")); });

  for (auto bad : {"", " ", "[1,]", "{\"x\":1,}", "{x:1}", "{\"x\":1,\"\\u0078\":2}",
                   "01", "+1", "1.", ".1", "1e+", "0 1", "1e999",
                   "18446744073709551616", "-9223372036854775809",
                   R"("\uD800")", R"("\uDC00")", R"("\uD800\uD801")",
                   "\"\xC0\x80\"", "\"\xED\xA0\x80\"", "\"\xF4\x90\x80\x80\"",
                   "\"\x01\"", "\"\xF0\"", "\"a\nb\"", "true\v"}) {
    rejects<Json::Invalid>([&] { (void)Json::parse(bad); });
  }
  std::string deep(Json::max_depth + 1, '[');
  deep += '1';
  deep.append(Json::max_depth + 1, ']');
  rejects<Json::Invalid>([&] { (void)Json::parse(deep); });
  rejects<Json::Invalid>([] { (void)Json("\xC2").dump(); });
  std::cout << "Exact integer bounds, strict syntax, UTF-8, null/error, and output round-trip verified\n";
}
} // namespace

int main(int argc, char **argv) try {
  expect(argc == 2, "usage: atomic_artifact WORK | --json");
  if (std::string_view(argv[1]) == "--json") {
    test_json();
    return 0;
  }
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
