#pragma once
#include "observation/observation.hpp"
#include "spec/spec.hpp"
#include <functional>
#include <span>
#include <vector>
namespace turtle {
class Execution {
    const Spec& spec_;
    const turtle_implementation& api_;
    turtle_connection* tls_;
    Observer& obs_;
    int socket_;
    std::uint64_t connection_, deadline_;
    std::vector<std::uint8_t> message_, pending_, wire_, decoded_, incoming_, plain_pending_;
    std::size_t pending_size_ = 0, incoming_size_ = 0, incoming_used_ = 0, plain_pending_size_ = 0;
    std::uint64_t tx_offset_ = 0, rx_offset_ = 0, tx_plain_ = 0, rx_plain_ = 0,
                  rx_message_offset_ = 0;
    std::uint64_t tx_message_ = 0, rx_message_ = 0, tx_record_ = 0, rx_record_ = 0, batch_ = 1;
    std::uint64_t current_message_ = 0;
    std::uint64_t identity(bool outgoing, std::uint64_t number) const;
    void transition(turtle_transition, unsigned, std::span<const std::uint8_t> = {});
    void protect(unsigned, std::span<const std::uint8_t>);
    void flush_plain();
    void submit();
    void io_receive(std::span<std::uint8_t>);
    unsigned receive_record();
    void send_message(unsigned);
    void receive_message(unsigned);
    void send_application(std::size_t);
    void receive_application(std::size_t);
    void checked(bool);

  public:
    std::vector<std::uint8_t> tx_stream, rx_stream, tx_plain_stream, rx_plain_stream;
    Execution(const Spec&, const turtle_implementation&, turtle_connection*, Observer&, int,
              std::uint64_t);
    turtle_result run();
};
} // namespace turtle
