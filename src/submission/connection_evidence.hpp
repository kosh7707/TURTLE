#pragma once

#include "artifact/json.hpp"
#include <istream>
#include <string_view>

namespace turtle::submission {

artifact::Json app_evidence(const artifact::Json &participants,
                            std::string_view scenario, std::string_view auth,
                            const artifact::Json &application,
                            std::string_view measured_role);
artifact::Json sdk_application_interval(const artifact::Json &native_timing,
                                         std::string_view role);
artifact::Json read_transport(std::istream &csv, std::istream &count,
                              std::string_view role,
                              const artifact::Json &handshake_complete = nullptr,
                              const artifact::Json &cad_last_read = nullptr);
} // namespace turtle::submission
