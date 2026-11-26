#pragma once
#include "process/images.hpp"

#include <exception>
#include <map>
#include <string>

namespace turtle::submission {
inline artifact::Json prepared_image(
    const artifact::Json &receipt, pid_t pid, const std::string &expected_exe,
    const std::string &expected_digest,
    const std::map<std::string, std::string> &expected_libraries) {
  using artifact::Json;
  auto issue = [](const char *state, const std::string &reason) -> Json {
    return {{"state", state}, {"reason", reason}};
  };
  // Prepared inventory corroborates the job's required post-task maps; it
  // does not substitute for those maps when capture is unavailable.
  if (receipt.is_null())
    return issue("unavailable", "prepared receipt absent");
  if (!receipt.contains("available") || !receipt.at("available").is_boolean())
    return issue("invalid", "prepared receipt lacks boolean availability");
  if (receipt.at("available") == false) {
    const auto field = receipt.find("reason");
    if (field == receipt.end() || !field->is_string())
      return issue("invalid", "unavailable prepared receipt lacks a reason");
    const auto &reason = field->get_ref<const std::string &>();
    if (reason == "participant_executable_replaced")
      return issue("contradicted", reason);
    // These failures cannot establish that a selected library was replaced:
    // the collector also scans non-selected mappings.
    if (reason == "image_mapping_replaced" ||
        reason == "image_changed_during_hash" || reason == "image_map_malformed")
      return issue("invalid", reason);
    return issue("unavailable", reason);
  }
  try {
    if (!receipt.at("pid").is_number_integer() ||
        !receipt.at("launcher_pid").is_number_integer() ||
        !receipt.at("phase").is_string())
      return issue("invalid", "malformed prepared process or phase");
    if (receipt.at("pid") != pid || receipt.at("launcher_pid") != pid)
      return issue("contradicted", "prepared PID or launcher differs from launched role");
    if (receipt.at("phase") != "prepared")
      return issue("contradicted", "image receipt is not from the prepared phase");

    const auto image = process::image_key(receipt, pid);
    const auto &mapped = image.at("mapped");
    if (image.at("exe") != expected_exe)
      return issue("contradicted", "prepared executable path differs from launched role");
    if (mapped.at(expected_exe) != expected_digest)
      return issue("contradicted", "prepared executable digest differs from launch digest");
    for (const auto &[path, digest] : expected_libraries) {
      if (!mapped.contains(path))
        return issue("contradicted", "prepared image lacks linked library: " + path);
      if (mapped.at(path) != digest)
        return issue("contradicted", "prepared library digest differs from link digest: " + path);
    }
  } catch (const std::exception &error) {
    return issue("invalid", error.what());
  }
  return {{"state", "matched"}, {"reason", nullptr}};
}
} // namespace turtle::submission
