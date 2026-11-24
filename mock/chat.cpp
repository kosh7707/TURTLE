#include "chat.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
constexpr std::size_t max_line = 4096;

std::runtime_error os_error(const char *where) {
    return std::runtime_error(std::string(where) + ": " + std::strerror(errno));
}

// A zero event mask means the peer sent an orderly TLS close_notify.
short retry_event(SSL *ssl, int result, const char *where) {
    switch (SSL_get_error(ssl, result)) {
    case SSL_ERROR_WANT_READ:  return POLLIN;
    case SSL_ERROR_WANT_WRITE: return POLLOUT;
    case SSL_ERROR_ZERO_RETURN: return 0;
    default:
        const char *reason = ERR_reason_error_string(ERR_peek_last_error());
        throw std::runtime_error(std::string(where) + ": " +
                                 (reason ? reason : "TLS transport failure"));
    }
}

template<class OnLine>
void consume(const char *data, std::size_t size, std::string &line, OnLine on_line) {
    for (std::size_t i = 0; i < size; ++i) {
        if (data[i] == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            bool keep_reading = on_line(line);
            line.clear();
            if (!keep_reading) break;
        } else {
            if (line.size() == max_line) throw std::runtime_error("chat line exceeds 4096 bytes");
            line += data[i];
        }
    }
}

// Application -> TLS: a successful call accepts plaintext, not proof of peer delivery.
short write_plaintext(SSL *ssl, std::string &pending) {
    std::size_t n;
    ERR_clear_error();
    int result = SSL_write_ex(ssl, pending.data(), pending.size(), &n);
    if (result == 1) {
        pending.erase(0, n);
        return 0;  // No retry pending.
    }
    short event = retry_event(ssl, result, "TLS write");
    if (!event) throw std::runtime_error("peer closed during write");
    return event;
}

// TLS -> application: one SSL read is not necessarily one complete chat line.
short read_peer_lines(SSL *ssl, std::string &line) {
    char data[4096];
    std::size_t n;
    ERR_clear_error();
    int result = SSL_read_ex(ssl, data, sizeof(data), &n);
    if (result == 1) {
        consume(data, n, line, [](const std::string &message) {
            std::cout << "peer> " << message << std::endl;
            return true;
        });
        return POLLIN;
    }
    short event = retry_event(ssl, result, "TLS read");
    if (!event && !line.empty()) throw std::runtime_error("incomplete peer chat line");
    return event;  // Zero means an orderly peer close.
}
} // namespace

void run_chat(SSL *ssl) {
    const int sock = SSL_get_fd(ssl);
    const int flags = fcntl(sock, F_GETFL);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
        throw os_error("set socket nonblocking");

    std::string local_line, peer_line, outgoing;
    bool closing = false, sent_close = false, peer_closed = false;
    short read_event = POLLIN, write_retry = 0, close_event = POLLOUT;
    // Today the terminal decides when to send. A scenario would supply that trigger.
    auto queue_line = [&](const std::string &line) {
        if (line == "/quit") { closing = true; return false; }
        outgoing += line + '\n';
        return true;
    };
    while (!sent_close || !peer_closed) {
        bool shutting_down = closing && outgoing.empty() && !sent_close;
        // After SSL_write_ex wants a write, OpenSSL requires us to retry it
        // before attempting any other TLS I/O on the connection.
        bool allow_read = !peer_closed && !shutting_down && write_retry != POLLOUT;
        short events = allow_read ? read_event : 0;
        short write_event = write_retry ? write_retry : POLLOUT;
        if (!outgoing.empty()) events |= write_event;
        if (shutting_down) events |= close_event;
        pollfd fds[] = {{sock, events, 0},
                        {(!closing && outgoing.empty()) ? STDIN_FILENO : -1, POLLIN, 0}};
        bool buffered = allow_read && SSL_pending(ssl) > 0;
        if (poll(fds, 2, buffered ? 0 : -1) < 0) {
            if (errno == EINTR) continue;
            throw os_error("poll");
        }
        auto ready = [&](short event) {
            return (fds[0].revents & (event | POLLHUP | POLLERR | POLLNVAL)) != 0;
        };
        if (shutting_down && ready(close_event)) {
            ERR_clear_error();
            int result = SSL_shutdown(ssl);
            // A pending alert must be flushed before draining peer data.
            if (result == 0 && SSL_want_write(ssl)) close_event = POLLOUT;
            else if (result >= 0) sent_close = true;
            else {
                close_event = retry_event(ssl, result, "TLS shutdown");
                if (!close_event) throw std::runtime_error("incomplete TLS shutdown");
            }
            if (result == 1) peer_closed = true;
        }
        if (!outgoing.empty() && ready(write_event)) {
            write_retry = write_plaintext(ssl, outgoing);
        }
        if (allow_read && write_retry != POLLOUT && (buffered || ready(read_event))) {
            read_event = read_peer_lines(ssl, peer_line);
            if (!read_event) {
                peer_closed = closing = true;
                outgoing.clear();
            }
        }
        if (!closing && fds[1].revents) {
            char buf[4096];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n > 0) consume(buf, static_cast<std::size_t>(n), local_line, queue_line);
            else if (n == 0) {
                if (!local_line.empty()) queue_line(local_line);
                closing = true;
            } else if (errno != EINTR && errno != EAGAIN) throw os_error("stdin");
        }
    }
}
