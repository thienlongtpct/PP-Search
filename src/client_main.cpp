// pp_client: coordinator, requester and station roles.
//
//   pp_client new-session
//   pp_client coordinator --pki DIR --party0 H:P --party1 H:P --session HEX
//             --horizon D --mode binary|argmin --requester NAME
//             (--stations ID,ID,... | --stations-file FILE) [--timeout-ms MS]
//             [--result-timeout-ms MS]
//   pp_client requester --pki DIR --party0 H:P --party1 H:P --session HEX
//             --name NAME --x X --y Y [--timeout-ms MS]
//   pp_client station --pki DIR --party0 H:P --party1 H:P --session HEX
//             --id ID --x X --y Y --radius R [--timeout-ms MS]
//   pp_client stations --pki DIR --party0 H:P --party1 H:P --session HEX
//             --file CSV(id,x,y,radius) [--timeout-ms MS]
//
// Every command prints one JSON object on stdout. Input owners split each
// value into two fresh uniformly random additive shares modulo 2^128 and send
// exactly one share to each party over its own mutually authenticated TLS
// connection.

#include "pps/tls_transport.hpp"
#include "pps/util.hpp"
#include "pps/wire.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>

namespace {

using namespace pps;
using Clock = std::chrono::steady_clock;

constexpr Millis kConnectTimeout{5000};
constexpr Millis kRetryDelay{100};

Millis remaining(Clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<Millis>(deadline - Clock::now());
    return left.count() > 0 ? left : Millis(0);
}

struct Common {
    std::string pki;
    std::array<std::pair<std::string, int>, 2> parties;
    wire::SessionId session{};
    Clock::time_point deadline;
};

Common common(const Arguments& arguments, std::uint64_t default_timeout_ms) {
    Common result;
    result.pki = arguments.get("pki");
    result.parties = {parse_endpoint(arguments.get("party0")),
                      parse_endpoint(arguments.get("party1"))};
    result.session = wire::parse_session_hex(arguments.get("session"));
    result.deadline = Clock::now() + Millis(arguments.get_uint("timeout-ms", default_timeout_ms));
    return result;
}

std::unique_ptr<TlsContext> client_context(const std::string& pki, const std::string& identity) {
    const PkiFiles files = pki_files(pki, identity);
    auto context = std::make_unique<TlsContext>(TlsCredentials{files.ca, files.certificate, files.key}, false);
    if (context->identity() != identity) {
        throw std::runtime_error("certificate identity '" + context->identity() +
                                 "' does not match " + identity);
    }
    return context;
}

std::string aborted_json(const std::string& role, const TransportError& error) {
    return JsonObject()
        .add("role", role)
        .add("status", "aborted")
        .add("code", abort_code_name(error.code()))
        .add("message", error.what())
        .str();
}

// ---- Input owners -----------------------------------------------------------

struct Submission {
    wire::OwnerKind kind = wire::OwnerKind::kRequester;
    std::uint64_t station_id = 0;
    std::vector<std::pair<wire::Field, Word>> values;
};

struct Delivered {
    std::array<std::unique_ptr<TlsConnection>, 2> connections;
    TransportCounters counters;
};

// Sends one share of every field to each party and waits for both acks.
// Retries while a party reports that the session is not active yet.
Delivered submit(TlsContext& context, const Common& target, const Submission& submission) {
    std::vector<std::array<Word, 2>> shares;
    for (const auto& value : submission.values) {
        shares.push_back(share_value(value.second));  // fresh randomness per field
    }
    std::array<std::uint8_t, 16> submission_id{};
    random_bytes(submission_id.data(), submission_id.size());
    Delivered delivered;
    for (int party = 0; party < 2; ++party) {
        while (true) {
            std::unique_ptr<TlsConnection> connection;
            try {
                connection = tls_connect(target.parties[party].first, target.parties[party].second,
                                         context, wire::party_identity(party),
                                         std::min(kConnectTimeout, remaining(target.deadline)));
                for (std::size_t i = 0; i < submission.values.size(); ++i) {
                    wire::InputShare share;
                    share.owner = submission.kind;
                    share.field = submission.values[i].first;
                    share.station_id = submission.station_id;
                    share.share = shares[i][static_cast<std::size_t>(party)];
                    connection->send(wire::make_frame(wire::MsgType::kInputShare, target.session, share),
                                     remaining(target.deadline));
                }
                wire::InputDone done;
                done.owner = submission.kind;
                done.station_id = submission.station_id;
                done.field_count = static_cast<std::uint32_t>(submission.values.size());
                done.submission_id = submission_id;
                connection->send(wire::make_frame(wire::MsgType::kInputDone, target.session, done),
                                 remaining(target.deadline));
                connection->receive_expect(wire::MsgType::kInputAck, target.session,
                                           remaining(target.deadline));
                delivered.counters += connection->counters();
                delivered.connections[static_cast<std::size_t>(party)] = std::move(connection);
                break;
            } catch (const RemoteAbortError& error) {
                if (error.code() != AbortCode::kUnknownSession) {
                    throw;
                }
            } catch (const TimeoutError&) {
            } catch (const PeerClosedError&) {
            }
            if (Clock::now() >= target.deadline) {
                throw TimeoutError("party " + std::to_string(party) + " did not accept the inputs");
            }
            std::this_thread::sleep_for(kRetryDelay);
        }
    }
    return delivered;
}

struct StationOutcome {
    std::string status;  // selected | not-selected | aborted | inconsistent
    std::string detail;
    int share_frames = 0;
    std::optional<std::pair<std::int64_t, std::int64_t>> requester;
};

// Waits for each party's delivery and reconstructs the requester location
// only when both parties delivered output shares for this station.
StationOutcome await_output(Delivered& delivered, const wire::SessionId& session,
                            std::uint64_t station_id, Clock::time_point deadline) {
    StationOutcome outcome;
    std::array<std::map<wire::Field, Word>, 2> shares;
    int selected_by = 0;
    int unselected_by = 0;
    for (int party = 0; party < 2; ++party) {
        TlsConnection& connection = *delivered.connections[static_cast<std::size_t>(party)];
        try {
            while (true) {
                wire::Frame frame = connection.receive(remaining(deadline));
                if (frame.session != session) {
                    throw ProtocolError(AbortCode::kUnknownSession, "output for another session");
                }
                if (frame.type == wire::MsgType::kAbort) {
                    const wire::Abort abort = wire::decode_abort(frame.payload);
                    outcome.status = "aborted";
                    outcome.detail = abort_code_name(abort.code);
                    return outcome;
                }
                if (frame.type == wire::MsgType::kNoOutput) {
                    if (wire::decode_no_output(frame.payload).station_id != station_id) {
                        throw ProtocolError("no-output notice for another station");
                    }
                    ++unselected_by;
                    break;
                }
                if (frame.type != wire::MsgType::kOutputShare) {
                    throw ProtocolError("unexpected message while awaiting output");
                }
                ++outcome.share_frames;
                const wire::OutputShare share = wire::decode_output_share(frame.payload);
                if (share.station_id != station_id ||
                    !shares[static_cast<std::size_t>(party)].emplace(share.field, share.share).second) {
                    throw ProtocolError("invalid or duplicate output share");
                }
                if (shares[static_cast<std::size_t>(party)].size() == 2) {
                    ++selected_by;
                    break;
                }
            }
        } catch (const TransportError& error) {
            outcome.status = "aborted";
            outcome.detail = error.what();
            return outcome;
        }
        delivered.counters += connection.counters();
        connection.close();
    }
    if (selected_by == 2) {
        const auto reconstruct = [&](wire::Field field) {
            // semi2k shares carry no MACs: reconstruction is the sum mod 2^128,
            // exactly what MP-SPDZ's SemiMC does when opening.
            const SignedWord value = decode_signed(shares[0][field] + shares[1][field]);
            if (value < kCoordinateMin || value > kCoordinateMax) {
                throw ProtocolError("reconstructed coordinate outside the encoded domain");
            }
            return static_cast<std::int64_t>(value);
        };
        try {
            outcome.requester = {reconstruct(wire::Field::kX), reconstruct(wire::Field::kY)};
            outcome.status = "selected";
        } catch (const ProtocolError& error) {
            outcome.status = "inconsistent";
            outcome.detail = error.what();
        }
    } else if (unselected_by == 2) {
        outcome.status = "not-selected";
    } else {
        outcome.status = "inconsistent";
        outcome.detail = "parties disagree about the selected station";
    }
    return outcome;
}

std::string outcome_json(std::uint64_t station_id, const StationOutcome& outcome,
                         const TransportCounters& counters) {
    JsonObject json;
    json.add("role", "station").add("station_id", station_id).add("status", outcome.status);
    if (!outcome.detail.empty()) {
        json.add("detail", outcome.detail);
    }
    json.add("output_share_frames", outcome.share_frames);
    if (outcome.requester) {
        json.add("requester_x", outcome.requester->first).add("requester_y", outcome.requester->second);
    }
    json.add("bytes_sent", counters.bytes_sent).add("bytes_received", counters.bytes_received);
    return json.str();
}

int run_requester(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "name", "x", "y"});
    const Common target = common(arguments, 30000);
    const std::string name = arguments.get("name");
    if (!wire::valid_requester_name(name)) {
        throw std::invalid_argument("invalid requester name");
    }
    auto context = client_context(target.pki, wire::requester_identity(name));
    Submission submission;
    submission.kind = wire::OwnerKind::kRequester;
    submission.values = {{wire::Field::kX, encode_coordinate(arguments.get_int("x"))},
                         {wire::Field::kY, encode_coordinate(arguments.get_int("y"))}};
    try {
        Delivered delivered = submit(*context, target, submission);
        std::cout << JsonObject()
                         .add("role", "requester")
                         .add("status", "accepted")
                         .add("bytes_sent", delivered.counters.bytes_sent)
                         .add("bytes_received", delivered.counters.bytes_received)
                         .str()
                  << std::endl;
        return 0;
    } catch (const TransportError& error) {
        std::cout << aborted_json("requester", error) << std::endl;
        return 2;
    }
}

int run_station(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "id", "x", "y", "radius"});
    const Common target = common(arguments, 30000);
    const std::uint64_t id = arguments.get_uint("id");
    auto context = client_context(target.pki, wire::station_identity(id));
    Submission submission;
    submission.kind = wire::OwnerKind::kStation;
    submission.station_id = id;
    submission.values = {{wire::Field::kX, encode_coordinate(arguments.get_int("x"))},
                         {wire::Field::kY, encode_coordinate(arguments.get_int("y"))},
                         {wire::Field::kRadius, encode_radius(arguments.get_uint("radius"))}};
    try {
        Delivered delivered = submit(*context, target, submission);
        const StationOutcome outcome = await_output(delivered, target.session, id, target.deadline);
        std::cout << outcome_json(id, outcome, delivered.counters) << std::endl;
        return outcome.status == "aborted" || outcome.status == "inconsistent" ? 2 : 0;
    } catch (const TransportError& error) {
        std::cout << aborted_json("station", error) << std::endl;
        return 2;
    }
}

struct StationRecord {
    std::uint64_t id;
    std::int64_t x;
    std::int64_t y;
    std::uint64_t radius;
};

std::vector<StationRecord> read_station_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::invalid_argument("cannot read " + path);
    }
    std::vector<StationRecord> records;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::stringstream fields(line);
        std::string id, x, y, radius;
        if (!std::getline(fields, id, ',') || !std::getline(fields, x, ',') ||
            !std::getline(fields, y, ',') || !std::getline(fields, radius, ',')) {
            throw std::invalid_argument("station file lines must be id,x,y,radius");
        }
        records.push_back({parse_u64(id), parse_i64(x), parse_i64(y), parse_u64(radius)});
    }
    return records;
}

// Many stations from one process (benchmarks); each still uses its own
// certificate and its own pair of TLS connections.
int run_stations(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "file"});
    const Common target = common(arguments, 120000);
    const std::vector<StationRecord> records = read_station_file(arguments.get("file"));
    std::vector<std::pair<std::uint64_t, Delivered>> submitted;
    submitted.reserve(records.size());
    try {
        for (const StationRecord& record : records) {
            auto context = client_context(target.pki, wire::station_identity(record.id));
            Submission submission;
            submission.kind = wire::OwnerKind::kStation;
            submission.station_id = record.id;
            submission.values = {{wire::Field::kX, encode_coordinate(record.x)},
                                 {wire::Field::kY, encode_coordinate(record.y)},
                                 {wire::Field::kRadius, encode_radius(record.radius)}};
            submitted.emplace_back(record.id, submit(*context, target, submission));
        }
    } catch (const TransportError& error) {
        std::cout << aborted_json("stations", error) << std::endl;
        return 2;
    }
    JsonObject outputs;
    std::uint64_t not_selected = 0, aborted = 0, nonselected_share_frames = 0;
    TransportCounters total;
    std::string selected = "[";
    for (auto& [id, delivered] : submitted) {
        const StationOutcome outcome = await_output(delivered, target.session, id, target.deadline);
        total += delivered.counters;
        if (outcome.status == "selected") {
            selected += (selected.size() > 1 ? "," : "") + std::to_string(id);
            outputs.add_raw(std::to_string(id), JsonObject()
                                                    .add("x", outcome.requester->first)
                                                    .add("y", outcome.requester->second)
                                                    .str());
        } else {
            nonselected_share_frames += static_cast<std::uint64_t>(outcome.share_frames);
            if (outcome.status == "not-selected") {
                ++not_selected;
            } else {
                ++aborted;
            }
        }
    }
    selected += "]";
    std::cout << JsonObject()
                     .add("role", "stations")
                     .add("status", aborted == 0 ? "ok" : "aborted")
                     .add_raw("selected", selected)
                     .add_raw("outputs", outputs.str())
                     .add("not_selected", not_selected)
                     .add("aborted", aborted)
                     .add("output_share_frames_to_nonselected", nonselected_share_frames)
                     .add("bytes_sent", total.bytes_sent)
                     .add("bytes_received", total.bytes_received)
                     .str()
              << std::endl;
    return aborted == 0 ? 0 : 2;
}

// ---- Coordinator -------------------------------------------------------------

std::vector<std::uint64_t> parse_id_list(const std::string& text) {
    std::vector<std::uint64_t> ids;
    if (text.empty()) {
        return ids;
    }
    std::stringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ',')) {
        ids.push_back(parse_u64(item));
    }
    return ids;
}

int run_coordinator(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "horizon", "mode",
                          "requester", "stations", "stations-file", "result-timeout-ms",
                          "test-unchecked-station-list"});
    const Common target = common(arguments, 30000);
    wire::SessionOpen open;
    const std::uint64_t horizon = arguments.get_uint("horizon");
    if (horizon > kHorizonMax) {
        throw std::invalid_argument("horizon must fit in 32 bits");
    }
    open.horizon = static_cast<std::uint32_t>(horizon);
    const std::string mode = arguments.get("mode", "binary");
    if (mode != "binary" && mode != "argmin") {
        throw std::invalid_argument("--mode must be binary or argmin");
    }
    open.mode = mode == "binary" ? wire::Mode::kBinaryThenExact : wire::Mode::kDirectArgmin;
    open.timeout_ms = static_cast<std::uint32_t>(arguments.get_uint("timeout-ms", 30000));
    open.requester = arguments.get("requester");
    if (arguments.has("stations-file")) {
        for (const StationRecord& record : read_station_file(arguments.get("stations-file"))) {
            open.station_ids.push_back(record.id);
        }
    } else {
        open.station_ids = parse_id_list(arguments.get("stations", ""));
    }
    if (arguments.get("test-unchecked-station-list", "0") != "1") {
        // Canonical order: ascending station ID; duplicates are rejected.
        std::sort(open.station_ids.begin(), open.station_ids.end());
        if (std::adjacent_find(open.station_ids.begin(), open.station_ids.end()) !=
            open.station_ids.end()) {
            std::cout << JsonObject()
                             .add("role", "coordinator")
                             .add("status", "rejected")
                             .add("code", "duplicate")
                             .add("message", "duplicate station ID in request")
                             .str()
                      << std::endl;
            return 2;
        }
    }

    auto context = client_context(target.pki, wire::kCoordinatorIdentity);
    const auto result_deadline =
        Clock::now() + Millis(open.timeout_ms) + Millis(arguments.get_uint("result-timeout-ms", 600000));
    std::array<std::unique_ptr<TlsConnection>, 2> connections;
    std::array<std::optional<wire::SessionResult>, 2> results;
    try {
        for (int party = 0; party < 2; ++party) {
            while (!connections[static_cast<std::size_t>(party)]) {
                try {
                    connections[static_cast<std::size_t>(party)] =
                        tls_connect(target.parties[party].first, target.parties[party].second, *context,
                                    wire::party_identity(party),
                                    std::min(kConnectTimeout, remaining(target.deadline)));
                } catch (const TimeoutError&) {
                } catch (const PeerClosedError&) {
                }
                if (!connections[static_cast<std::size_t>(party)]) {
                    if (Clock::now() >= target.deadline) {
                        throw TimeoutError("cannot reach party " + std::to_string(party));
                    }
                    std::this_thread::sleep_for(kRetryDelay);
                }
            }
            connections[static_cast<std::size_t>(party)]->send(
                wire::make_frame(wire::MsgType::kSessionOpen, target.session, open), kConnectTimeout);
        }
        for (int party = 0; party < 2; ++party) {
            const wire::Frame frame = connections[static_cast<std::size_t>(party)]->receive_expect(
                wire::MsgType::kSessionResult, target.session, remaining(result_deadline));
            results[static_cast<std::size_t>(party)] = wire::decode_session_result(frame.payload);
        }
    } catch (const TransportError& error) {
        std::cout << aborted_json("coordinator", error) << std::endl;
        return 2;
    }
    if (results[0]->match != results[1]->match || results[0]->station_id != results[1]->station_id) {
        std::cout << JsonObject()
                         .add("role", "coordinator")
                         .add("status", "inconsistent")
                         .str()
                  << std::endl;
        return 3;
    }
    JsonObject json;
    json.add("role", "coordinator")
        .add("status", "ok")
        .add("session", wire::session_hex(target.session))
        .add("match", results[0]->match);
    if (results[0]->match) {
        json.add("station_id", results[0]->station_id);
    }
    std::cout << json.str() << std::endl;
    return 0;
}

// ---- Test-only misbehaving station --------------------------------------------

int run_inject(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "id", "kind",
                          "target-party"});
    const Common target = common(arguments, 30000);
    const std::uint64_t id = arguments.get_uint("id");
    const std::string kind = arguments.get("kind");
    const int party = static_cast<int>(arguments.get_uint("target-party", 0));
    auto context = client_context(target.pki, wire::station_identity(id));
    std::unique_ptr<TlsConnection> connection;
    // Wait until the party has opened the session (first frame is valid).
    while (!connection) {
        try {
            connection = tls_connect(target.parties[party].first, target.parties[party].second,
                                     *context, wire::party_identity(party), kConnectTimeout);
        } catch (const TransportError&) {
            if (Clock::now() >= target.deadline) {
                throw;
            }
            std::this_thread::sleep_for(kRetryDelay);
        }
    }
    const auto share = [&](wire::Field field, std::uint64_t station) {
        wire::InputShare value;
        value.owner = wire::OwnerKind::kStation;
        value.field = field;
        value.station_id = station;
        value.share = random_word();
        return wire::make_frame(wire::MsgType::kInputShare, target.session, value);
    };
    const Millis timeout = kConnectTimeout;
    try {
        if (kind == "bad-magic") {
            connection->send_raw_for_test(std::vector<std::uint8_t>(wire::kHeaderSize, 0xAB), timeout);
        } else if (kind == "oversize") {
            wire::Frame frame = share(wire::Field::kX, id);
            auto header = wire::encode_header(frame);
            const std::uint32_t too_large = wire::kMaxPayload + 1;
            for (int i = 0; i < 4; ++i) {
                header[32 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(too_large >> (8 * i));
            }
            connection->send_raw_for_test({header.begin(), header.end()}, timeout);
        } else if (kind == "bad-sequence") {
            connection->set_next_sequence_for_test(7);
            connection->send(share(wire::Field::kX, id), timeout);
        } else if (kind == "duplicate-field") {
            connection->send(share(wire::Field::kX, id), timeout);
            connection->send(share(wire::Field::kX, id), timeout);
        } else if (kind == "wrong-station") {
            connection->send(share(wire::Field::kX, id + 1), timeout);
        } else if (kind == "trailing-bytes") {
            wire::Frame frame = share(wire::Field::kX, id);
            frame.payload.push_back(0);
            connection->send(frame, timeout);
        } else if (kind == "incomplete-done") {
            connection->send(share(wire::Field::kX, id), timeout);
            wire::InputDone done{wire::OwnerKind::kStation, id, 3, {}};
            connection->send(wire::make_frame(wire::MsgType::kInputDone, target.session, done), timeout);
        } else if (kind == "disconnect") {
            connection->send(share(wire::Field::kX, id), timeout);
            connection->close();
            std::cout << JsonObject().add("role", "inject").add("status", "disconnected").str() << std::endl;
            return 0;
        } else if (kind == "stall") {
            connection->send(share(wire::Field::kX, id), timeout);
        } else {
            throw std::invalid_argument("unknown --kind " + kind);
        }
        const wire::Frame reply = connection->receive(remaining(target.deadline));
        if (reply.type == wire::MsgType::kAbort) {
            const wire::Abort abort = wire::decode_abort(reply.payload);
            std::cout << JsonObject()
                             .add("role", "inject")
                             .add("status", "rejected")
                             .add("code", abort_code_name(abort.code))
                             .add("message", abort.message)
                             .str()
                      << std::endl;
            return 0;
        }
        std::cout << JsonObject().add("role", "inject").add("status", "unexpected-reply").str() << std::endl;
        return 1;
    } catch (const TransportError& error) {
        std::cout << JsonObject()
                         .add("role", "inject")
                         .add("status", "connection-ended")
                         .add("code", abort_code_name(error.code()))
                         .add("message", error.what())
                         .str()
                  << std::endl;
        return 0;
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    pps::raise_file_descriptor_limit();
    if (argc < 2) {
        std::cerr << "usage: pp_client <new-session|coordinator|requester|station|stations> [options]\n";
        return 64;
    }
    const std::string command = argv[1];
    try {
        if (command == "new-session") {
            std::cout << pps::wire::session_hex(pps::random_session_id()) << std::endl;
            return 0;
        }
        const pps::Arguments arguments(argc, argv, 2);
        if (command == "coordinator") return run_coordinator(arguments);
        if (command == "requester") return run_requester(arguments);
        if (command == "station") return run_station(arguments);
        if (command == "stations") return run_stations(arguments);
        if (command == "test-inject") return run_inject(arguments);
        throw std::invalid_argument("unknown command " + command);
    } catch (const std::invalid_argument& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 64;
    } catch (const std::out_of_range& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << "\n";
        return 1;
    }
}
