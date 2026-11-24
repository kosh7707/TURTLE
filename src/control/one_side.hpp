#pragma once
#include "artifact/json.hpp"
namespace turtle::control {
// Resolve only the one-sided input; legacy two-endpoint manifests remain
// unchanged.
artifact::Json one_side(const artifact::Json &,
                        const std::filesystem::path &base,
                        const std::filesystem::path &controller);
class TrialIdentities {
public:
  TrialIdentities() = default;
  TrialIdentities(const TrialIdentities &) = delete;
  ~TrialIdentities();
  void prepare(artifact::Json &spec, const std::filesystem::path &controller,
               int cancel);
  void export_public(const std::filesystem::path &output) const;

private:
  std::filesystem::path directory_;
};
} // namespace turtle::control
