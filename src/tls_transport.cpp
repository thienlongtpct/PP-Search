#include "pps/tls_transport.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace pps {
namespace {

using Clock = std::chrono::steady_clock;

std::string openssl_error() {
    const unsigned long code = ERR_get_error();
    if (code == 0) {
        return "no OpenSSL error queued";
    }
    char buffer[256];
    ERR_error_string_n(code, buffer, sizeof buffer);
    ERR_clear_error();
    return buffer;
}

std::string common_name(X509* certificate) {
    if (certificate == nullptr) {
        throw TransportError(AbortCode::kUnauthorized, "peer presented no certificate");
    }
    X509_NAME* subject = X509_get_subject_name(certificate);
    const int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (index < 0 || X509_NAME_get_index_by_NID(subject, NID_commonName, index) >= 0) {
        throw TransportError(AbortCode::kUnauthorized,
                             "certificate must carry exactly one common name");
    }
    const ASN1_STRING* data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index));
    const auto* bytes = reinterpret_cast<const char*>(ASN1_STRING_get0_data(data));
    const int length = ASN1_STRING_length(data);
    std::string name(bytes, static_cast<std::size_t>(length));
    if (name.find('\0') != std::string::npos) {
        throw TransportError(AbortCode::kUnauthorized, "embedded NUL in common name");
    }
    return name;
}

void set_socket_options(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw TransportError(AbortCode::kInternal, "cannot make socket non-blocking");
    }
    const int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

Clock::time_point deadline_after(Millis timeout) { return Clock::now() + timeout; }

int remaining_ms(Clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<Millis>(deadline - Clock::now()).count();
    return left <= 0 ? 0 : static_cast<int>(std::min<long long>(left, 1 << 30));
}

}  // namespace

TlsContext::TlsContext(const TlsCredentials& credentials, bool server) {
    context_ = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (context_ == nullptr) {
        throw TransportError(AbortCode::kInternal, "SSL_CTX_new: " + openssl_error());
    }
    try {
        if (SSL_CTX_set_min_proto_version(context_, TLS1_3_VERSION) != 1) {
            throw TransportError(AbortCode::kInternal, "cannot require TLS 1.3");
        }
        if (SSL_CTX_use_certificate_chain_file(context_, credentials.certificate_file.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(context_, credentials.private_key_file.c_str(),
                                        SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(context_) != 1) {
            throw TransportError(AbortCode::kInternal,
                                 "cannot load certificate/key: " + openssl_error());
        }
        if (SSL_CTX_load_verify_locations(context_, credentials.ca_file.c_str(), nullptr) != 1) {
            throw TransportError(AbortCode::kInternal, "cannot load CA: " + openssl_error());
        }
        SSL_CTX_set_verify(context_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        SSL_CTX_set_verify_depth(context_, 2);
        SSL_CTX_set_mode(context_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_CTX_set_session_cache_mode(context_, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_num_tickets(context_, 0);
        identity_ = common_name(SSL_CTX_get0_certificate(context_));
    } catch (...) {
        SSL_CTX_free(context_);
        throw;
    }
}

TlsContext::~TlsContext() { SSL_CTX_free(context_); }

TlsConnection::TlsConnection(int socket_fd, TlsContext& context, bool server, Millis timeout)
    : fd_(socket_fd) {
    try {
        set_socket_options(fd_);
        ssl_ = SSL_new(context.native());
        if (ssl_ == nullptr || SSL_set_fd(ssl_, fd_) != 1) {
            throw TransportError(AbortCode::kInternal, "SSL_new: " + openssl_error());
        }
        const auto deadline = deadline_after(timeout);
        while (true) {
            const int result = server ? SSL_accept(ssl_) : SSL_connect(ssl_);
            if (result == 1) {
                break;
            }
            const int error = SSL_get_error(ssl_, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                throw TransportError(AbortCode::kUnauthorized,
                                     "TLS handshake failed: " + openssl_error());
            }
            wait_io(error, deadline, "TLS handshake");
        }
        if (SSL_get_verify_result(ssl_) != X509_V_OK) {
            throw TransportError(AbortCode::kUnauthorized, "peer certificate not verified");
        }
        X509* peer = SSL_get1_peer_certificate(ssl_);
        try {
            peer_identity_ = common_name(peer);
        } catch (...) {
            X509_free(peer);
            throw;
        }
        X509_free(peer);
    } catch (...) {
        if (ssl_ != nullptr) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        ::close(fd_);
        fd_ = -1;
        closed_ = true;
        throw;
    }
}

TlsConnection::~TlsConnection() { close(); }

void TlsConnection::close() {
    if (closed_) {
        return;
    }
    closed_ = true;
    // One non-blocking close_notify attempt; never wait for the peer.
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
    ssl_ = nullptr;
    ::close(fd_);
    fd_ = -1;
}

bool TlsConnection::wait_readable(Millis timeout) {
    if (closed_) {
        return false;
    }
    if (SSL_pending(ssl_) > 0) {
        return true;
    }
    pollfd descriptor{fd_, POLLIN, 0};
    const int ready = ::poll(&descriptor, 1, static_cast<int>(timeout.count()));
    return ready > 0;
}

void TlsConnection::wait_io(int ssl_error, Clock::time_point deadline, const char* what) {
    pollfd descriptor{fd_, static_cast<short>(ssl_error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN), 0};
    while (true) {
        const int timeout = remaining_ms(deadline);
        if (timeout == 0) {
            throw TimeoutError(std::string(what) + " timed out");
        }
        const int ready = ::poll(&descriptor, 1, timeout);
        if (ready > 0) {
            return;
        }
        if (ready == 0) {
            throw TimeoutError(std::string(what) + " timed out");
        }
        if (errno != EINTR) {
            throw PeerClosedError(std::string(what) + ": poll failed");
        }
    }
}

void TlsConnection::write_all(const std::uint8_t* data, std::size_t size,
                              Clock::time_point deadline) {
    if (closed_) {
        throw PeerClosedError("connection already closed");
    }
    std::size_t offset = 0;
    while (offset < size) {
        std::size_t written = 0;
        if (SSL_write_ex(ssl_, data + offset, size - offset, &written) == 1) {
            offset += written;
            continue;
        }
        const int error = SSL_get_error(ssl_, 0);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            wait_io(error, deadline, "send");
            continue;
        }
        ERR_clear_error();
        throw PeerClosedError("peer disconnected during send");
    }
}

void TlsConnection::read_exact(std::uint8_t* data, std::size_t size,
                               Clock::time_point deadline) {
    if (closed_) {
        throw PeerClosedError("connection already closed");
    }
    std::size_t offset = 0;
    while (offset < size) {
        std::size_t read = 0;
        if (SSL_read_ex(ssl_, data + offset, size - offset, &read) == 1) {
            offset += read;
            continue;
        }
        const int error = SSL_get_error(ssl_, 0);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            wait_io(error, deadline, "receive");
            continue;
        }
        ERR_clear_error();
        if (error == SSL_ERROR_ZERO_RETURN) {
            throw PeerClosedError("peer closed the connection");
        }
        throw PeerClosedError("connection lost during receive");
    }
}

void TlsConnection::send(wire::Frame frame, Millis timeout) {
    frame.sequence = next_send_sequence_;
    const auto header = wire::encode_header(frame);
    std::vector<std::uint8_t> bytes(header.begin(), header.end());
    bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());
    write_all(bytes.data(), bytes.size(), deadline_after(timeout));
    ++next_send_sequence_;
    counters_.bytes_sent += bytes.size();
    ++counters_.messages_sent;
}

void TlsConnection::send_raw_for_test(const std::vector<std::uint8_t>& bytes, Millis timeout) {
    write_all(bytes.data(), bytes.size(), deadline_after(timeout));
    counters_.bytes_sent += bytes.size();
}

wire::Frame TlsConnection::receive(Millis timeout) {
    const auto deadline = deadline_after(timeout);
    std::uint8_t header_bytes[wire::kHeaderSize];
    read_exact(header_bytes, sizeof header_bytes, deadline);
    const wire::Header header = wire::decode_header(header_bytes);
    if (header.sequence != next_receive_sequence_) {
        throw ProtocolError("unexpected frame sequence number");
    }
    wire::Frame frame;
    frame.type = header.type;
    frame.step = header.step;
    frame.session = header.session;
    frame.sequence = header.sequence;
    frame.payload.resize(header.payload_length);
    if (header.payload_length != 0) {
        read_exact(frame.payload.data(), frame.payload.size(), deadline);
    }
    ++next_receive_sequence_;
    counters_.bytes_received += wire::kHeaderSize + frame.payload.size();
    ++counters_.messages_received;
    return frame;
}

wire::Frame Transport::receive_expect(wire::MsgType type, const wire::SessionId& session,
                                      Millis timeout) {
    wire::Frame frame = receive(timeout);
    if (frame.type == wire::MsgType::kAbort) {
        const wire::Abort abort = wire::decode_abort(frame.payload);
        throw RemoteAbortError(abort.code, "peer aborted: " + abort.message);
    }
    if (frame.type != type) {
        throw ProtocolError("unexpected message type");
    }
    if (frame.session != session) {
        throw ProtocolError(AbortCode::kUnknownSession, "message for another session");
    }
    return frame;
}

void Transport::send_abort_noexcept(const wire::SessionId& session, AbortCode code,
                                    const std::string& message) noexcept {
    try {
        send(wire::make_frame(wire::MsgType::kAbort, session, wire::Abort{code, message}),
             Millis(500));
    } catch (...) {
    }
}

TlsListener::TlsListener(const std::string& host, int port, TlsContext& context)
    : context_(context) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
        throw TransportError(AbortCode::kInternal, "socket() failed");
    }
    const int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, host == "localhost" ? "127.0.0.1" : host.c_str(),
                  &address.sin_addr) != 1) {
        ::close(fd_);
        throw TransportError(AbortCode::kInternal, "listen address must be IPv4: " + host);
    }
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0 ||
        ::listen(fd_, 1024) != 0) {
        const std::string reason = std::strerror(errno);
        ::close(fd_);
        throw TransportError(AbortCode::kInternal, "cannot listen on " + host + ":" +
                                                       std::to_string(port) + ": " + reason);
    }
    socklen_t length = sizeof address;
    getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length);
    port_ = ntohs(address.sin_port);
}

TlsListener::~TlsListener() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

std::unique_ptr<TlsConnection> TlsListener::accept(Millis timeout, Millis handshake_timeout) {
    pollfd descriptor{fd_, POLLIN, 0};
    const auto deadline = deadline_after(timeout);
    while (true) {
        const int ready = ::poll(&descriptor, 1, remaining_ms(deadline));
        if (ready == 0) {
            return nullptr;
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw TransportError(AbortCode::kInternal, "poll on listener failed");
        }
        const int client = ::accept(fd_, nullptr, nullptr);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED) {
                continue;
            }
            throw TransportError(AbortCode::kInternal, "accept failed");
        }
        return std::make_unique<TlsConnection>(client, context_, true, handshake_timeout);
    }
}

std::unique_ptr<TlsConnection> tls_connect(const std::string& host, int port,
                                           TlsContext& context,
                                           const std::string& expected_identity,
                                           Millis timeout) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &results) != 0 ||
        results == nullptr) {
        throw TransportError(AbortCode::kInternal, "cannot resolve " + host);
    }
    const int fd = ::socket(results->ai_family, results->ai_socktype, results->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(results);
        throw TransportError(AbortCode::kInternal, "socket() failed");
    }
    set_socket_options(fd);
    const auto deadline = deadline_after(timeout);
    int status = ::connect(fd, results->ai_addr, results->ai_addrlen);
    freeaddrinfo(results);
    if (status != 0 && errno != EINPROGRESS) {
        ::close(fd);
        throw PeerClosedError("connect to " + host + ":" + std::to_string(port) + " failed");
    }
    if (status != 0) {
        pollfd descriptor{fd, POLLOUT, 0};
        const int ready = ::poll(&descriptor, 1, remaining_ms(deadline));
        int error = 0;
        socklen_t length = sizeof error;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length);
        if (ready <= 0 || error != 0) {
            ::close(fd);
            if (ready == 0) {
                throw TimeoutError("connect timed out");
            }
            throw PeerClosedError("connect to " + host + ":" + std::to_string(port) + " failed");
        }
    }
    auto connection = std::make_unique<TlsConnection>(
        fd, context, false, std::chrono::duration_cast<Millis>(deadline - Clock::now()));
    if (connection->peer_identity() != expected_identity) {
        throw TransportError(AbortCode::kUnauthorized,
                             "server identity '" + connection->peer_identity() +
                                 "' does not match expected '" + expected_identity + "'");
    }
    return connection;
}

std::pair<std::string, int> parse_endpoint(const std::string& text) {
    const auto colon = text.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 == text.size()) {
        throw std::invalid_argument("endpoint must be host:port: " + text);
    }
    const int port = std::stoi(text.substr(colon + 1));
    if (port < 0 || port > 65535) {
        throw std::invalid_argument("port out of range: " + text);
    }
    return {text.substr(0, colon), port};
}

void raise_file_descriptor_limit() {
    rlimit limit{};
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
        rlim_t wanted = 16384;
        if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < wanted) {
            wanted = limit.rlim_max;
        }
        if (limit.rlim_cur < wanted) {
            limit.rlim_cur = wanted;
            setrlimit(RLIMIT_NOFILE, &limit);
        }
    }
}

}  // namespace pps
