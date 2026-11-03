#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

namespace pps {

enum class AbortCode : std::uint32_t {
    kTimeout = 1,
    kMalformedMessage = 2,
    kUnauthorized = 3,
    kDuplicate = 4,
    kPeerFailure = 5,
    kPreprocessingExhausted = 6,
    kInternal = 7,
    kUnknownSession = 8,
    kPeerMismatch = 9,
    kDisconnected = 10,
    kSessionClosed = 11,  // the session already finished or aborted
};

// Base for all transport and message-level failures.
class TransportError : public std::runtime_error {
public:
    TransportError(AbortCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}
    AbortCode code() const { return code_; }

private:
    AbortCode code_;
};

class ProtocolError : public TransportError {
public:
    explicit ProtocolError(const std::string& message)
        : TransportError(AbortCode::kMalformedMessage, message) {}
    ProtocolError(AbortCode code, const std::string& message)
        : TransportError(code, message) {}
};

class TimeoutError : public TransportError {
public:
    explicit TimeoutError(const std::string& message)
        : TransportError(AbortCode::kTimeout, message) {}
};

class PeerClosedError : public TransportError {
public:
    explicit PeerClosedError(const std::string& message)
        : TransportError(AbortCode::kDisconnected, message) {}
};

// The remote side sent an explicit Abort frame.
class RemoteAbortError : public TransportError {
public:
    RemoteAbortError(AbortCode code, const std::string& message)
        : TransportError(code, message) {}
};

// A computation party ran out of preprocessed correlated randomness. There is
// no fallback: the session aborts without output.
class PreprocessingExhausted : public std::runtime_error {
public:
    explicit PreprocessingExhausted(const std::string& message)
        : std::runtime_error(message) {}
};

inline const char* abort_code_name(AbortCode code) {
    switch (code) {
    case AbortCode::kTimeout: return "timeout";
    case AbortCode::kMalformedMessage: return "malformed-message";
    case AbortCode::kUnauthorized: return "unauthorized";
    case AbortCode::kDuplicate: return "duplicate";
    case AbortCode::kPeerFailure: return "peer-failure";
    case AbortCode::kPreprocessingExhausted: return "preprocessing-exhausted";
    case AbortCode::kInternal: return "internal";
    case AbortCode::kUnknownSession: return "unknown-session";
    case AbortCode::kPeerMismatch: return "peer-mismatch";
    case AbortCode::kDisconnected: return "disconnected";
    case AbortCode::kSessionClosed: return "session-closed";
    }
    return "unknown";
}

}  // namespace pps
