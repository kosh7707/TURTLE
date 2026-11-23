#pragma once
#include "process/process.hpp"
#include <memory>
namespace turtle::control {
using process::Args;
using process::Child;
using process::command;
using process::deadline;
using process::digest;
using process::Environment;
using process::executable;
class Capture {
public:
  Capture(std::filesystem::path root, std::string role);
  // LISTEN has returned the actual port; the client does not exist yet.
  void start(Args prefix, const std::string &exe, const std::string &interface,
             unsigned port, int cancel);
  artifact::Json finish();

private:
  std::filesystem::path root_;
  std::string role_;
  std::unique_ptr<Child> child_;
  artifact::Json state_;
};
class Topology {
public:
  Topology(std::filesystem::path root, artifact::Json settings, int cancel_fd);
  ~Topology();
  void start();
  void finish() noexcept;
  Args prefix(const std::string &) const;
  static constexpr const char *client_ip = "192.0.2.2";
  static constexpr const char *server_ip = "198.51.100.2";

private:
  std::filesystem::path root_;
  artifact::Json settings_, state_;
  int cancel_;
  std::map<std::string, std::string> names_;
  std::vector<std::string> created_;
  bool finished_ = false;
  std::string invoke(const Args &, bool check = true, bool cleanup = false);
  std::string inside(const std::string &, const Args &, bool cleanup = false);
  artifact::Json snapshot(bool cleanup = false);
};
std::string identifier();
} // namespace turtle::control
