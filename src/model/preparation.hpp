#pragma once

#include <string>

namespace turtle::model {

// Preparation evidence is serialized outside every TLS measurement window.
// Empty documents mean not observed, never an unavailable counter with value 0.
struct PreparationInfo {
    std::string stage = "local_environment";
    std::string control_document;
    std::string local_document;
    std::string peer_document;
    bool scenario_agreed = false;
};

} // namespace turtle::model
