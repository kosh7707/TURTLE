#include "submission/process_maps.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using turtle::submission::MapsState;
using turtle::submission::process_maps;
using turtle::submission::write_process_maps;

namespace {
const fs::path exe = "/job/build/bin/client";
const std::vector<fs::path> libs = {"/job/build/prefix/lib/lib sample.so.1"};
const std::string exe_line = "1000-2000 r-xp 0000 08:01 42 " + exe.string() + "\n";
const std::string lib_line = "2000-3000 r-xp 1000 08:01 57 " + libs.front().string() + "\n";
const std::string anon_line = "3000-4000 rw-p 0000 00:00 0     \n";

class FailingBuffer : public std::streambuf {
public:
  explicit FailingBuffer(std::string initial) : prefix(std::move(initial)) {
    setg(prefix.data(), prefix.data(), prefix.data() + prefix.size());
  }

private:
  int_type underflow() override {
    throw std::runtime_error("mock maps I/O error");
  }
  std::string prefix;
};

void expect(MapsState actual, MapsState expected, const char *why) {
  if (actual != expected)
    throw std::runtime_error(why);
}
} // namespace

int main() try {
  auto snapshot = [](const std::string &data) {
    std::istringstream in(data);
    return process_maps(in, exe, libs);
  };
  expect(snapshot(exe_line + lib_line), MapsState::incomplete,
         "newline-terminated prefix after matching paths qualified without a completion marker");
  expect(snapshot(exe_line), MapsState::incomplete,
         "newline-terminated prefix before matching paths counted as contrary");
  expect(snapshot(exe_line + lib_line + anon_line + "# turtle-maps rows=3\n"), MapsState::matched,
         "complete matching maps rejected");
  expect(snapshot(exe_line + anon_line + "# turtle-maps rows=2\n"), MapsState::contradicted,
         "valid contrary snapshot was not rejected");
  expect(snapshot(exe_line + lib_line + "# turtle-maps rows=3\n"), MapsState::incomplete,
         "lost whole row with retained completion marker was not distinguished");
  expect(snapshot(exe_line + lib_line + "# turtle-maps rows=2\n" + anon_line), MapsState::incomplete,
         "completion marker before end of snapshot was accepted");
  FailingBuffer failure(exe_line + lib_line + "# turtle-maps rows=2\n");
  std::istream failed_read(&failure);
  expect(process_maps(failed_read, exe, libs), MapsState::incomplete,
         "read failure after matching pathnames and marker was not distinguished");
  expect(snapshot(exe_line + lib_line + "broken line\n# turtle-maps rows=3\n"), MapsState::incomplete,
         "malformed row after matching pathnames was not distinguished");
  expect(snapshot(exe_line + lib_line + "4000-5000 rwxp bad bad bad\n# turtle-maps rows=3\n"),
         MapsState::incomplete, "invalid maps fields were accepted");
  expect(snapshot(exe_line + lib_line + "# turtle-maps rows=2"),
         MapsState::incomplete, "unterminated completion marker was accepted");
  expect(snapshot(""), MapsState::incomplete, "empty snapshot counted as contradiction");

  std::istringstream producer(exe_line + lib_line);
  std::ostringstream output;
  if (!write_process_maps(producer, output) ||
      output.str() != exe_line + lib_line + "# turtle-maps rows=2\n")
    throw std::runtime_error("writer did not retain and seal complete raw rows");
  FailingBuffer producer_fault(exe_line + lib_line);
  std::istream failed_source(&producer_fault);
  std::ostringstream partial;
  if (write_process_maps(failed_source, partial) || partial.str() != exe_line + lib_line)
    throw std::runtime_error("writer sealed a full-row prefix after a read error");
  std::istringstream short_source(exe_line + lib_line.substr(0, lib_line.size() - 1));
  std::ostringstream short_output;
  if (write_process_maps(short_source, short_output) || short_output.str() != exe_line)
    throw std::runtime_error("writer sealed a truncated source row");

  const fs::path live_exe = fs::canonical("/proc/self/exe");
  std::ifstream raw_live("/proc/self/maps");
  std::ostringstream captured;
  if (!write_process_maps(raw_live, captured))
    throw std::runtime_error("could not collect a complete live Linux maps stream");
  std::istringstream live(captured.str());
  expect(process_maps(live, live_exe, {}),
         MapsState::matched, "live maps snapshot could not identify this test");
  expect(snapshot(captured.str()),
         MapsState::contradicted, "live maps with absent executables must contradict");
  expect(process_maps(fs::path("/proc/self/mem"), exe, libs), MapsState::incomplete,
         "kernel read error counted as contradiction");
  expect(process_maps(fs::path("/proc/self/exe/no-maps"), exe, libs),
         MapsState::unavailable, "stat failure counted as contradiction");
  expect(process_maps(fs::path("/proc/self"), exe, libs), MapsState::unavailable,
         "directory counted as a maps snapshot");
  return 0;
} catch (const std::exception &error) {
  std::cerr << error.what() << '\n';
  return 1;
}
