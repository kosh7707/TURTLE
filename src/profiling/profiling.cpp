#include "profiling/profiling.hpp"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
namespace turtle::profiling {
using artifact::integer;
namespace fs = std::filesystem;
process::Environment environment(const fs::path &root) {
  return {{"DEBUGINFOD_URLS", ""},
          {"LC_ALL", "C"},
          {"PERF_BUILDID_DIR", (root / "empty-buildid-cache").string()}};
}
namespace {
Json invoke(const process::Args &args, const fs::path &output) {
  auto r = process::command(args, 90, environment(output.parent_path()));
  artifact::write_text(output, r.at("stdout"));
  artifact::write_text(output.string() + ".stderr", r.at("stderr"));
  return {{"argv", args},
          {"returncode", r.at("returncode")},
          {"stdout", output.filename().string()},
          {"stderr", output.filename().string() + ".stderr"}};
}
std::string build_id(const fs::path &p) {
  auto r =
      process::command({"readelf", "-n", p.string()}, 30, {{"LC_ALL", "C"}});
  std::regex pattern("Build ID: ([0-9a-fA-F]+)");
  std::smatch m;
  auto s = r.at("stdout").get<std::string>();
  if (r.at("returncode") != 0 || !std::regex_search(s, m, pattern))
    return {};
  auto value = m[1].str();
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}
bool virtual_module(std::string_view name) {
  if (name == "[vdso]" || name == "[vdso32]" || name == "[vdsox32]")
    return true;
  constexpr std::string_view prefix = "/tmp/perf-vdso.so-";
  if (!name.starts_with(prefix))
    return false;
  name.remove_prefix(prefix.size());
  return name.size() == 6 &&
         name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
                                "uvwxyz0123456789") == name.npos;
}
} // namespace
void validate_settings(const Json &options) {
  if (!options.is_object())
    throw std::runtime_error("cpu_samples_requires_settings_object");
  auto event = options.value("event", std::string("cycles:u"));
  auto frequency = integer(options.value("frequency_hz", Json(997)));
  auto perf = options.value("perf", std::string("perf"));
  if ((event != "cycles:u" && event != "cpu-clock:u") || frequency < 1 ||
      frequency > 100000 || perf.empty() ||
      perf.find('\0') != std::string::npos)
    throw std::runtime_error("invalid_perf_settings");
}
Json settings(const Json &options) {
  validate_settings(options);
  return {
      {"perf", process::executable(options.value("perf", std::string("perf")))},
      {"event", options.value("event", std::string("cycles:u"))},
      {"frequency_hz", options.value("frequency_hz", Json(997))}};
}
Json probe(const Json &options, int cancel) {
  try {
    auto chosen = settings(options);
    // Test the requested event, not merely presence of an executable. No TLS
    // process participates and this disposable recording is never analyzed.
    auto pattern = (fs::temp_directory_path() / "turtle-perf-XXXXXX").string();
    if (!::mkdtemp(pattern.data()))
      throw std::runtime_error("perf_probe_tempdir_failed");
    struct Scratch {
      fs::path path;
      ~Scratch() {
        std::error_code ec;
        fs::remove_all(path, ec);
      }
    } scratch{pattern};
    auto output = (scratch.path / "probe.data").string();
    auto r = process::command(
        {chosen.at("perf"), "record", "-q", "-e", chosen.at("event"), "-F",
         chosen.at("frequency_hz").dump(), "--strict-freq", "--clockid", "mono",
         "--no-inherit", "--no-buildid-cache", "-o", output, "--", "true"},
        10, environment(scratch.path), cancel);
    if (r.at("returncode") != 0)
      throw std::runtime_error("perf_record_probe_failed:" +
                               r.at("stderr").get<std::string>());
    auto decode =
        process::command({chosen.at("perf"), "script", "-i", output, "--ns",
                          "-F", "pid,tid,time,event,period,ip,sym,dso"},
                         10, environment(scratch.path), cancel);
    if (decode.at("returncode") != 0)
      throw std::runtime_error("perf_script_probe_failed:" +
                               decode.at("stderr").get<std::string>());
    chosen.update({{"availability", "available"}, {"reason", nullptr}});
    return chosen;
  } catch (const std::exception &e) {
    return {{"availability", "unsupported"}, {"reason", e.what()}};
  }
}
process::Args prepare(const fs::path &root, const Json &options) {
  auto c = settings(options);
  process::Args args = {c.at("perf"),
                        "record",
                        "-e",
                        c.at("event"),
                        "-F",
                        std::to_string(integer(c.at("frequency_hz"))),
                        "--strict-freq",
                        "--clockid",
                        "mono",
                        "--no-inherit",
                        "--no-buildid-cache",
                        "--buildid-all",
                        "-o",
                        (root / "perf.data").string(),
                        "--"};
  c.update({{"schema", "turtle.cpu-collection.v1"},
            {"record_prefix", args},
            {"clock", "CLOCK_MONOTONIC"},
            {"ordinary_timing_sample", false},
            {"status", "requested"},
            {"perf_executable_sha256",
             process::digest(c.at("perf").get<std::string>())},
            {"commands", Json::array()}});
  artifact::save(root / "profile.json", c);
  return args;
}
void finish(const fs::path &root, int returncode) {
  auto source = root / "profile.json";
  auto p = artifact::load(source);
  p.update({{"record_returncode", returncode},
            {"status", "missing"},
            {"reason", nullptr}});
  try {
    std::string perf = p.at("perf");
    p["commands"].push_back(
        invoke({perf, "--version"}, root / "perf.version.txt"));
    if (returncode || !fs::exists(root / "perf.data") ||
        fs::file_size(root / "perf.data") == 0)
      throw std::runtime_error("perf_record_failed_or_data_missing");
    p["perf_data_sha256"] = process::digest(root / "perf.data");
    for (const auto &[action, extra, file] :
         std::vector<std::tuple<std::string, process::Args, std::string>>{
             {"buildid-list", {}, "perf.buildids.txt"},
             {"evlist", {"-v"}, "perf.events.txt"},
             {"report", {"--stdio", "--header-only"}, "perf.header.txt"}}) {
      process::Args a = {perf, action, "-i", (root / "perf.data").string()};
      a.insert(a.end(), extra.begin(), extra.end());
      auto cmd = invoke(a, root / file);
      p["commands"].push_back(cmd);
      if (cmd.at("returncode") != 0)
        throw std::runtime_error("perf_metadata_failed:" + action);
    }
    Json binaries = Json::array(), unparsed = Json::array();
    std::istringstream lines(artifact::read_text(root / "perf.buildids.txt"));
    std::string line;
    std::regex expression("^([0-9a-fA-F]+)\\s+(.+)$");
    bool complete = true;
    while (std::getline(lines, line)) {
      std::smatch m;
      if (!std::regex_match(line, m, expression)) {
        // Some perf versions pad an empty build-id column for the kernel vDSO.
        // Do not relax provenance requirements for any file-backed module.
        const auto first = line.find_first_not_of(" \t");
        if (!line.empty() &&
            (first == line.npos ||
             !virtual_module(std::string_view(line).substr(first)))) {
          unparsed.push_back(line);
          complete = false;
        }
        continue;
      }
      auto id = m[1].str(), name = m[2].str();
      std::transform(id.begin(), id.end(), id.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      Json entry = {{"source", name},
                    {"build_id", id},
                    {"availability", "unsupported"},
                    {"reason", "virtual_or_non_file_object"}};
      fs::path original(name);
      if (original.is_absolute() && !virtual_module(name)) {
        entry.update({{"availability", "missing"},
                      {"reason", "recorded_binary_unavailable"}});
        if (fs::is_regular_file(original)) {
          auto destination = root / "symbols" / original.relative_path();
          fs::create_directories(destination.parent_path());
          fs::copy_file(original, destination,
                        fs::copy_options::overwrite_existing);
          auto observed = build_id(destination);
          entry["observed_build_id"] = observed;
          if (observed == id)
            entry.update({{"availability", "available"},
                          {"reason", nullptr},
                          {"path", fs::relative(destination, root).string()},
                          {"sha256", process::digest(destination)}});
          else
            entry["reason"] = "recorded_binary_build_id_mismatch";
        }
        if (entry.at("availability") == "missing")
          complete = false;
      }
      binaries.push_back(entry);
    }
    p.update({{"binaries", binaries}, {"unparsed_build_ids", unparsed}});
    if (!complete || binaries.empty())
      throw std::runtime_error("binary_provenance_incomplete");
    p["status"] = "collected";
  } catch (const std::exception &e) {
    p["reason"] = e.what();
  }
  artifact::save(source, p);
}
Json parse_samples(const std::string &text) {
  Json samples = Json::array(), other = Json::array();
  std::regex expression(
      R"(^\s*(\d+)/(\d+)\s+(\d+)\.(\d{1,9}):\s+(\d+)\s+(\S+):\s+([0-9a-fA-F]+)\s+(.+)$)");
  std::istringstream lines(text);
  std::string line;
  while (std::getline(lines, line)) {
    if (line.empty() || line[0] == '#' ||
        line.find_first_not_of(" \t\r") == std::string::npos)
      continue;
    std::smatch m;
    if (!std::regex_match(line, m, expression)) {
      other.push_back(line);
      continue;
    }
    auto tail = m[8].str();
    auto pos = tail.rfind(" (");
    if (pos == std::string::npos || tail.back() != ')') {
      other.push_back(line);
      continue;
    }
    auto fraction = m[4].str();
    fraction.append(9 - fraction.size(), '0');
    samples.push_back(
        {{"pid", std::stoull(m[1])},
         {"tid", std::stoull(m[2])},
         {"wall_ns", std::stoull(m[3]) * 1000000000ULL + std::stoull(fraction)},
         {"period", std::stoull(m[5])},
         {"event", m[6].str()},
         {"ip", m[7].str()},
         {"symbol", tail.substr(0, pos)},
         {"module", tail.substr(pos + 2, tail.size() - pos - 3)}});
  }
  return {{"samples", samples}, {"unparsed_or_lost", other}};
}
Json distribution(const Json &samples) {
  std::map<std::pair<std::string, std::string>,
           std::pair<std::uint64_t, std::uint64_t>>
      functions;
  std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> modules;
  std::uint64_t total = 0, unknown = 0;
  for (const auto &s : samples) {
    auto n = integer(s.at("period"));
    total += n;
    if (s.at("symbol") == "[unknown]")
      ++unknown;
    auto &f = functions[{s.at("module"), s.at("symbol")}];
    ++f.first;
    f.second += n;
    auto &m = modules[s.at("module")];
    ++m.first;
    m.second += n;
  }
  auto weights = [&](auto pair) {
    return Json{
        {"sample_count", pair.first},
        {"period_sum", pair.second},
        {"period_fraction", total ? Json(static_cast<double>(pair.second) /
                                         static_cast<double>(total))
                                  : Json(nullptr)}};
  };
  Json fs = Json::array(), ms = Json::array();
  for (const auto &[key, pair] : functions) {
    auto row = weights(pair);
    row.update({{"module", key.first}, {"symbol", key.second}});
    fs.push_back(row);
  }
  for (const auto &[name, pair] : modules) {
    auto row = weights(pair);
    row["module"] = name;
    ms.push_back(row);
  }
  auto order = [](const Json &a, const Json &b) {
    if (a.at("period_sum") != b.at("period_sum"))
      return integer(a.at("period_sum")) > integer(b.at("period_sum"));
    return std::make_pair(a.at("module").get<std::string>(),
                          a.value("symbol", std::string())) <
           std::make_pair(b.at("module").get<std::string>(),
                          b.value("symbol", std::string()));
  };
  std::sort(fs.begin(), fs.end(), order);
  std::sort(ms.begin(), ms.end(), order);
  return {{"availability", samples.empty() ? "missing" : "available"},
          {"reason",
           samples.empty() ? Json("no_samples_in_window") : Json(nullptr)},
          {"sample_count", samples.size()},
          {"period_sum", samples.empty() ? Json(nullptr) : Json(total)},
          {"unknown_symbol_samples", unknown},
          {"functions", fs},
          {"modules", ms}};
}
Json window(const Json &samples, std::uint64_t begin, std::uint64_t end) {
  if (end < begin)
    throw std::runtime_error("profile_window_reversed");
  Json local = Json::array();
  for (const auto &s : samples) {
    auto t = integer(s.at("wall_ns"));
    if (begin <= t && t < end)
      local.push_back(s);
  }
  auto r = distribution(local);
  r.update({{"begin_ns", begin}, {"end_ns", end}});
  return r;
}
Json analyze(const fs::path &root, const Json &summary, const Json &events,
             const Json &phases) {
  bool requested = summary.at("collection").value("cpu_samples", false);
  Json r = {{"requested", requested},
            {"availability", "not_collected"},
            {"reason", nullptr}};
  if (!requested)
    return r;
  try {
    auto p = artifact::load(root / "profile.json");
    if (p.at("schema") != "turtle.cpu-collection.v1" ||
        p.at("clock") != "CLOCK_MONOTONIC" ||
        p.at("ordinary_timing_sample") != false)
      throw std::runtime_error("cpu_collection_contract_mismatch");
    r["collection"] = p;
    if (p.at("status") != "collected")
      throw std::runtime_error(
          p.value("reason", Json("cpu_collection_incomplete")).dump());
    if (process::digest(root / "perf.data") !=
        p.at("perf_data_sha256").get<std::string>())
      throw std::runtime_error("perf_data_changed");
    std::set<std::string> available;
    for (const auto &b : p.at("binaries"))
      if (b.at("availability") == "available") {
        auto path = root / b.at("path").get<std::string>();
        if (process::digest(path) != b.at("sha256").get<std::string>() ||
            build_id(path) != b.at("build_id").get<std::string>())
          throw std::runtime_error("preserved_binary_changed");
        available.insert(b.at("source"));
      }
    std::string analysis_perf = p.at("perf");
    if (!fs::is_regular_file(analysis_perf))
      analysis_perf = "perf";
    analysis_perf = settings({{"perf", analysis_perf},
                              {"event", p.at("event")},
                              {"frequency_hz", p.at("frequency_hz")}})
                        .at("perf");
    r["analysis_tool"] = {{"path", analysis_perf},
                          {"sha256", process::digest(analysis_perf)}};
    auto cmd = invoke(
        {analysis_perf, "script", "-i", (root / "perf.data").string(),
         "--symfs", (root / "symbols").string(), "--ns", "--show-lost-events",
         "--no-inline", "-F", "pid,tid,time,event,period,ip,sym,dso"},
        root / "perf.script.txt");
    auto parsed = parse_samples(artifact::read_text(root / "perf.script.txt"));
    r.update({{"analysis_command", cmd},
              {"unparsed_or_lost", parsed.at("unparsed_or_lost")}});
    if (cmd.at("returncode") != 0 || !parsed.at("unparsed_or_lost").empty())
      throw std::runtime_error(
          "perf_script_failed_or_lost_or_unparsed_samples");
    Json local = Json::array();
    for (auto s : parsed.at("samples")) {
      if (s.at("event") != p.at("event"))
        throw std::runtime_error("perf_sample_event_mismatch");
      if (!available.contains(s.at("module").get<std::string>())) {
        s["symbol"] = "[unknown]";
        s["symbol_status"] = "module_not_preserved";
      }
      if (s.at("pid") == summary.at("pid") && s.at("tid") == summary.at("tid"))
        local.push_back(s);
    }
    auto w = [&](const Json &interval) {
      return window(local, integer(interval.at("begin").at("wall_ns")),
                    integer(interval.at("end").at("wall_ns")));
    };
    r.update({{"availability", local.empty() ? "missing" : "available"},
              {"reason", local.empty() ? Json("no_calling_thread_samples")
                                       : Json(nullptr)},
              {"sample_count", local.size()},
              {"ignored_other_thread_samples",
               parsed.at("samples").size() - local.size()},
              {"all_calling_thread", distribution(local)},
              {"scenario", w(summary.at("scenario"))},
              {"calls", Json::array()},
              {"phases", Json::array()},
              {"events", Json::array()},
              {"outside_transport", Json::array()}});
    std::uint64_t handshake_count = 0, phase_count = 0;
    for (const auto &e : events) {
      auto row = w(e);
      row.update({{"event_id", e.at("id")},
                  {"kind", e.at("kind")},
                  {"parent", e.at("parent")}});
      r["events"].push_back(row);
      if (e.at("kind") == "call") {
        row["operation"] = e.at("operation");
        r["calls"].push_back(row);
        if (e.at("operation") == "handshake")
          handshake_count = integer(row.at("sample_count"));
      }
    }
    for (const auto &phase : phases.value("rows", Json::array())) {
      auto row = w(phase.at("interval"));
      row["phase"] = phase.at("phase");
      phase_count += integer(row.at("sample_count"));
      r["phases"].push_back(row);
    }
    if (r.at("phases").size() == 4 && phase_count != handshake_count)
      throw std::runtime_error("cpu_sample_phase_partition_mismatch");
    for (const auto &gap :
         phases.value("outside_transport_intervals", Json::array())) {
      auto row = w(gap);
      row["id"] = gap.at("id");
      r["outside_transport"].push_back(row);
    }
    artifact::save(root / "cpu-samples.json",
                   {{"schema", "turtle.cpu-samples.v1"}, {"samples", local}});
  } catch (const std::exception &e) {
    r.update({{"availability", "missing"}, {"reason", e.what()}});
  }
  return r;
}
} // namespace turtle::profiling
