#pragma once
#include "artifact/json.hpp"

namespace turtle::native {
int check(const std::filesystem::path &profile);
int execute(artifact::Json profile, const std::filesystem::path &output,
            const std::filesystem::path &self, int cancel,
            artifact::Json retry_of = nullptr);
int retry(const std::filesystem::path &, const std::string &,
          const std::filesystem::path &, const std::filesystem::path &, int);
int regenerate(const std::filesystem::path &output);
} // namespace turtle::native
