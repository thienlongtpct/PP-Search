#pragma once

// TLS 1.3 socket transport built on OpenSSL. Both sides present X.509
// certificates issued by a deployment CA; the peer certificate chain is
// verified against that CA and its common name is checked against the
// identity the caller expects. No cryptography is implemented here.

#include "pps/transport.hpp"

#include <memory>
#include <string>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

namespace pps {

struct TlsCredentials {
    std::string ca_file;
    std::string certificate_file;
    std::string private_key_file;
};

class TlsContext {
public:
    TlsContext(const TlsCredentials& credentials, bool server);
    ~TlsContext();
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    SSL_CTX* native() const { return context_; }
    // Common name of our own certificate.
    const std::string& identity() const { return identity_; }

private:
    SSL_CTX* context_ = nullptr;
    std::string identity_;
};

class TlsConnection final : public Transport {
public:
    // Takes ownership of a connected socket and completes the handshake.
    TlsConnection(int socket_fd, TlsContext& context, bool server, Millis timeout);
    ~TlsConnection() override;

    void send(wire::Frame frame, Millis timeout) override;
    wire::Frame receive(Millis timeout) override;
    const std::string& peer_identity() const override { return peer_identity_; }
    TransportCounters counters() const override { return counters_; }
    void close() override;

    // True if a frame can be read without waiting (data buffered or socket
    // readable within `timeout`).
    bool wait_readable(Millis timeout);

    // Test hook: writes raw bytes without framing (malformed-message tests).
    void send_raw_for_test(const std::vector<std::uint8_t>& bytes, Millis timeout);
    // Test hook: overrides the next outgoing sequence number.
    void set_next_sequence_for_test(std::uint32_t sequence) { next_send_sequence_ = sequence; }

private:
    void write_all(const std::uint8_t* data, std::size_t size,
                   std::chrono::steady_clock::time_point deadline);
    void read_exact(std::uint8_t* data, std::size_t size,
                    std::chrono::steady_clock::time_point deadline);
    void wait_io(int ssl_error, std::chrono::steady_clock::time_point deadline,
                 const char* what);

    int fd_ = -1;
    SSL* ssl_ = nullptr;
    std::string peer_identity_;
    TransportCounters counters_;
    std::uint32_t next_send_sequence_ = 0;
    std::uint32_t next_receive_sequence_ = 0;
    bool closed_ = false;
};

class TlsListener {
public:
    // Binds host:port (port 0 picks a free port).
    TlsListener(const std::string& host, int port, TlsContext& context);
    ~TlsListener();
    TlsListener(const TlsListener&) = delete;
    TlsListener& operator=(const TlsListener&) = delete;

    int port() const { return port_; }
    // Waits up to `timeout` for a connection and completes the TLS handshake.
    // Returns nullptr on timeout. Handshake failures (bad certificate etc.)
    // throw TransportError; the listener stays usable.
    std::unique_ptr<TlsConnection> accept(Millis timeout, Millis handshake_timeout);

private:
    int fd_ = -1;
    int port_ = 0;
    TlsContext& context_;
};

// Connects and verifies that the server presents `expected_identity`.
std::unique_ptr<TlsConnection> tls_connect(const std::string& host, int port,
                                           TlsContext& context,
                                           const std::string& expected_identity,
                                           Millis timeout);

// host:port parsing helper.
std::pair<std::string, int> parse_endpoint(const std::string& text);

// Raises the soft open-file limit (many simultaneous station connections).
void raise_file_descriptor_limit();

}  // namespace pps
