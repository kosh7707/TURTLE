#include "submission/image_receipt.hpp"

#include <iostream>
#include <stdexcept>

int main() try {
  using turtle::artifact::Json;
  using turtle::submission::prepared_image;
  const pid_t pid = 751;
  const std::string exe = "/job/build/bin/client";
  const std::string exe_hash(64, 'a');
  const std::string library = "/job/build/prefix/lib/libsample.so.1";
  const std::string library_hash(64, 'b');
  const std::map<std::string, std::string> libraries{{library, library_hash}};
  const Json good{{"available", true},
                  {"phase", "prepared"},
                  {"pid", pid},
                  {"launcher_pid", pid},
                  {"exe", exe},
                  {"mapped", {{exe, exe_hash},
                              {library, library_hash},
                              {"/lib/libc.so.6", std::string(64, 'c')}}}};
  auto expect = [&](const Json &receipt, const char *state, const char *why) {
    const auto result = prepared_image(receipt, pid, exe, exe_hash, libraries);
    if (result.at("state") != state)
      throw std::runtime_error(std::string(why) + ": " + result.dump());
    if (result.at("reason").is_null() != (std::string_view(state) == "matched"))
      throw std::runtime_error(std::string("unexpected reason: ") + result.dump());
  };

  expect(good, "matched", "complete prepared receipt rejected");
  expect(nullptr, "unavailable", "missing receipt is still only ancillary");
  const auto reason = [&](const char *value, const char *state) {
    Json receipt{{"available", false}, {"reason", value}};
    expect(receipt, state, value);
    if (prepared_image(receipt, pid, exe, exe_hash, libraries).at("reason") != value)
      throw std::runtime_error("native capture reason lost");
  };
  reason("image_snapshot_timeout", "unavailable");
  reason("image_snapshot_cancelled", "unavailable");
  reason("participant_executable_stat_failed", "unavailable");
  reason("image_file_restat_failed", "unavailable");
  reason("participant_executable_replaced", "contradicted");
  reason("image_mapping_replaced", "invalid");
  reason("image_changed_during_hash", "invalid");
  reason("image_map_malformed", "invalid");

  Json changed = good;
  changed["pid"] = pid + 1;
  expect(changed, "contradicted", "wrong participant");
  changed = good;
  changed["launcher_pid"] = pid + 1;
  expect(changed, "contradicted", "wrong launcher");
  changed = good;
  changed["phase"] = "after_task";
  expect(changed, "contradicted", "wrong phase");
  changed = good;
  changed["exe"] = library;
  expect(changed, "contradicted", "wrong executable");
  changed = good;
  changed["mapped"][exe] = library_hash;
  expect(changed, "contradicted", "wrong executable digest");
  changed = good;
  changed["mapped"][library] = exe_hash;
  expect(changed, "contradicted", "wrong private digest");
  changed = good;
  changed["mapped"].erase(library);
  changed["mapped"]["/usr/lib/libsample.so.1"] = library_hash;
  expect(changed, "contradicted", "private path replaced by a host pathname");

  changed = good;
  changed["mapped"][library] = "not-a-digest";
  expect(changed, "invalid", "malformed digest is not merely missing");
  changed = good;
  changed.erase("exe");
  expect(changed, "invalid", "malformed available inventory");
  expect({{"available", "false"}}, "invalid", "availability must be boolean");
  expect({{"available", false}}, "invalid", "unavailable receipt must explain why");
  expect(Json::object(), "invalid", "non-null inventory must declare availability");
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
