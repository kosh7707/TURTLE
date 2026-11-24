#pragma once
#include "artifact/json.hpp"
#include <chrono>
#include <cstdio>
#include <map>
#include <string>
#include <sys/types.h>
#include <vector>
namespace turtle::process {
using Args = std::vector<std::string>;
using Environment = std::map<std::string, std::string>;
using Deadline = std::chrono::steady_clock::time_point;
Deadline deadline(double seconds);
class Child {
public:
  enum class Group { isolated, inherit };
  Child(const Args &, const Environment & = {},
        const std::filesystem::path &error_file = {}, Group group = Group::isolated);
  ~Child();
  Child(const Child &) = delete;
  pid_t pid() const noexcept { return pid_; }
  Child &operator=(const Child &) = delete;
  std::string line(Deadline, int cancel_fd = -1);
  std::string collect(Deadline, int cancel_fd = -1);
  void send(const std::string &);
  void close_input();
  int wait(Deadline, int cancel_fd = -1);
  void signal(int);
  int stop() noexcept;
  std::string errors();

private:
  pid_t pid_ = -1;
  Group group_;
  int input_ = -1, output_ = -1, status_ = -1;
  FILE *error_ = nullptr;
  std::string buffered_;
  bool eof_ = false;
  void receive(Deadline, int);
};
artifact::Json command(const Args &, double timeout = 30,
                       const Environment & = {}, int cancel_fd = -1);
std::string digest(const std::filesystem::path &);
std::string executable(const std::string &);
} // namespace turtle::process
