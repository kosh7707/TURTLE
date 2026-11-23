#pragma once
#include "artifact/json.hpp"
#include <filesystem>
#include <string>
namespace turtle::control {
int retry(const std::filesystem::path &, const std::string &failed_id,
          const std::filesystem::path &output, const std::string &self,
          int cancel_fd);
int execute_spec(artifact::Json, const std::filesystem::path &output,
                 const std::string &self, int cancel_fd);
int check(const std::filesystem::path &spec);
int execute(const std::filesystem::path &spec,
            const std::filesystem::path &output, const std::string &executable,
            int cancel_fd);
} // namespace turtle::control
