#pragma once

// Small serializers shared by the TLS and service raw writers. This is an
// internal record-module header, not an implementation-facing contract.
#include "model/model.hpp"

#include <nlohmann/json.hpp>

namespace turtle::record::detail {

inline nlohmann::json tcp_json(const std::optional<model::TcpInfoSnapshot>& value) {
    using Json = nlohmann::json;
    const auto nullable = [](const auto& field) -> Json {
        return field ? Json(*field) : Json(nullptr);
    };
    if (!value)
        return nullptr;
    return {{"structure_bytes", value->structure_bytes},
            {"state", nullable(value->state)},
            {"retransmits", nullable(value->retransmits)},
            {"retrans", nullable(value->retrans)},
            {"total_retrans", nullable(value->total_retrans)},
            {"unacked", nullable(value->unacked)},
            {"lost", nullable(value->lost)},
            {"snd_mss", nullable(value->snd_mss)},
            {"rcv_mss", nullable(value->rcv_mss)},
            {"segs_out", nullable(value->segs_out)},
            {"segs_in", nullable(value->segs_in)},
            {"data_segs_out", nullable(value->data_segs_out)},
            {"data_segs_in", nullable(value->data_segs_in)},
            {"bytes_acked", nullable(value->bytes_acked)},
            {"bytes_received", nullable(value->bytes_received)},
            {"note", value->note}};
}

} // namespace turtle::record::detail
