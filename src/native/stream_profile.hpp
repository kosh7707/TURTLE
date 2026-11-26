#pragma once
#include "native/stream_process.hpp"
#include "profiling/profiling.hpp"
#include <sys/stat.h>

namespace turtle::native::detail {
// Diagnostic process only: attach perf to the actual target before exec, wait
// for Linux perf's enable acknowledgement, then release that same process.
// Ordinary trials never take this barrier or run a profiler.
class FunctionProfile {
  std::filesystem::path dir;
  std::unique_ptr<process::Child> recorder;
  std::filesystem::path ctl, ack;

public:
  explicit FunctionProfile(const std::filesystem::path &root)
      : dir(root / "profile"), ctl(dir / "control"), ack(dir / "ack") {
    std::filesystem::create_directory(dir);
  }
  ~FunctionProfile() {
    std::error_code ec;
    std::filesystem::remove(ctl, ec);
    std::filesystem::remove(ack, ec);
  }
  void attach(App &app, const artifact::Json &options, int cancel,
              process::Deadline end) {
    auto wait = [&] {
      pollfd f{cancel, POLLIN, 0};
      if (Clock::now() >= end)
        throw std::runtime_error("profile_attach_timeout");
      if (poll(&f, 1, 5) > 0 && f.revents)
        throw std::runtime_error("interrupted");
    };
    while (true) {
      siginfo_t si{};
      auto r =
          waitid(P_PID, app.pid, &si, WSTOPPED | WEXITED | WNOHANG | WNOWAIT);
      if (r == 0 && si.si_pid == app.pid) {
        if (si.si_code != CLD_STOPPED)
          throw std::runtime_error("profile_target_not_stopped");
        break;
      }
      if (r < 0 && errno != EINTR)
        throw std::runtime_error("profile_wait_failed");
      wait();
    }
    if (mkfifo(ctl.c_str(), 0600) || mkfifo(ack.c_str(), 0600))
      throw std::runtime_error("perf_control_fifo_failed");
    FD input(open(ctl.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC)),
        output(open(ack.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (input.fd < 0 || output.fd < 0)
      throw std::runtime_error("perf_control_open_failed");
    auto argv = profiling::prepare(dir, options);
    argv.pop_back();
    std::erase(argv, "--no-inherit"); // include threads created after exec;
                                      // filter actual event TID on replay.
    argv.insert(argv.end(),
                {"--delay=-1",
                 "--control=fifo:" + ctl.string() + "," + ack.string(), "-p",
                 std::to_string(app.pid)});
    auto meta = artifact::load(dir / "profile.json");
    meta["record_argv"] = argv;
    meta.erase("record_prefix");
    meta["target_pid"] = app.pid;
    artifact::save(dir / "profile.json", meta);
    recorder = std::make_unique<process::Child>(
        argv, profiling::environment(dir), dir / "record.stderr");
    if (write(input.fd, "enable\n", 7) != 7)
      throw std::runtime_error("perf_enable_failed");
    std::string response;
    while (response.find('\n') == response.npos) {
      wait();
      char b[32];
      auto n = read(output.fd, b, sizeof(b));
      if (n > 0)
        response.append(b, n);
      else if (n < 0 && errno != EINTR && errno != EAGAIN)
        throw std::runtime_error("perf_ack_failed");
    }
    if ((response != "ack\n" && response != std::string("ack\n\0", 5)) ||
        kill(app.pid, SIGCONT))
      throw std::runtime_error("perf_enable_not_acknowledged");
  }
  void finish() {
    if (!recorder)
      return;
    FD input(open(ctl.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (input.fd < 0 || write(input.fd, "stop\n", 5) != 5)
      throw std::runtime_error("perf_stop_failed");
    int status = recorder->wait(process::deadline(10));
    recorder.reset();
    profiling::finish(dir, status);
    auto meta = artifact::load(dir / "profile.json");
    if (meta.at("status") != "collected")
      return;
    process::Args argv = {meta.at("perf").get<std::string>(),
                          "script",
                          "-i",
                          (dir / "perf.data").string(),
                          "--symfs",
                          (dir / "symbols").string(),
                          "--ns",
                          "--show-lost-events",
                          "--no-inline",
                          "-F",
                          "pid,tid,time,event,period,ip,sym,dso"};
    auto r = process::command(argv, 60, profiling::environment(dir));
    artifact::write_text(dir / "samples.txt", r.at("stdout").get<std::string>());
    artifact::write_text(dir / "script.stderr", r.at("stderr").get<std::string>());
    meta["decode_argv"] = argv;
    meta["decode_returncode"] = r.at("returncode");
    artifact::save(dir / "profile.json", meta);
  }
};
// Pure replay of the preserved decoder output, never executes an archived
// perf path. Only samples in the same process, thread and semantic time window
// count towards a native function diagnostic.
inline artifact::Json function_report(const std::filesystem::path &root,
                                      const artifact::Json &raw,
                                      const artifact::Json &evidence,
                                      const std::string &role) {
  using artifact::Json;
  Json result = {{"availability", "missing"},
                 {"reason", "no_verified_thread_window"},
                 {"ordinary_timing_sample", false}};
  try {
    auto dir = root / "profile";
    auto meta = artifact::load(dir / "profile.json");
    if (meta.at("status") != "collected" ||
        meta.value("decode_returncode", -1) != 0) {
      result["reason"] = meta.value("reason", Json("record_or_decode_failed"));
      return result;
    }
    const auto &timing = evidence.at("timing");
    auto &first = timing.at("begin");
    auto &last = timing.at("end");
    auto pid = raw.at("pid").at(role);
    if (first.is_null() || last.is_null() ||
        first.at("tid") != last.at("tid") || first.at("pid") != pid ||
        last.at("pid") != pid || meta.at("target_pid") != pid)
      return result;
    auto decoded =
        profiling::parse_samples(artifact::read_text(dir / "samples.txt"));
    if (!decoded.at("unparsed_or_lost").empty())
      throw std::runtime_error("lost_or_unparsed_perf_samples");
    Json rows = Json::array();
    for (auto sample : decoded.at("samples")) {
      if (sample.at("event") != meta.at("event"))
        throw std::runtime_error("wrong_perf_event");
      if (sample.at("pid") != pid || sample.at("tid") != first.at("tid"))
        continue;
      bool preserved = false;
      for (auto &image : meta.at("binaries"))
        if (image.at("source") == sample.at("module") &&
            image.at("availability") == "available")
          preserved = true;
      if (!preserved)
        sample["symbol"] = "[unknown]";
      rows.push_back(sample);
    }
    auto window = profiling::window(rows, artifact::integer(first.at("ns")),
                                    artifact::integer(last.at("ns")));
    result.update(window);
    if (result.at("sample_count") != 0 &&
        result.at("unknown_symbol_samples") == result.at("sample_count")) {
      result["availability"] = "missing";
      result["reason"] = "no_resolved_function_samples";
    }
    result["pid"] = pid;
    result["tid"] = first.at("tid");
    result["begin_seq"] = first.at("seq");
    result["end_seq"] = last.at("seq");
  } catch (const std::exception &e) {
    result["reason"] = e.what();
  }
  return result;
}
} // namespace turtle::native::detail
