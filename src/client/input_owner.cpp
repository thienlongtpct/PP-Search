// Requester and station commands: split inputs into additive shares, send one
// share to each party, and (stations) wait for the output.

#include "client/client_common.hpp"
#include "client/commands.hpp"
#include "common/crypto.hpp"
#include "common/json.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>
#include <optional>
#include <thread>

namespace pps::client {
namespace {

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
Delivered submit(TlsContext& context, const Target& target, const Submission& submission) {
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

Submission station_submission(std::uint64_t id, std::int64_t x, std::int64_t y, std::uint64_t radius) {
    Submission submission;
    submission.kind = wire::OwnerKind::kStation;
    submission.station_id = id;
    submission.values = {{wire::Field::kX, encode_coordinate(x)},
                         {wire::Field::kY, encode_coordinate(y)},
                         {wire::Field::kRadius, encode_radius(radius)}};
    return submission;
}

Word parse_hex_word(const std::string& text) {
    if (text.empty() || text.size() > 32) {
        throw std::invalid_argument("expected 1 to 32 hexadecimal digits");
    }
    Word value = 0;
    for (const char digit : text) {
        const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(digit)));
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw std::invalid_argument("expected hexadecimal digits");
        }
        value = (value << 4) | static_cast<Word>(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    return value;
}

}  // namespace

int run_requester(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "name", "x", "y"});
    const Target target = parse_target(arguments, 30000);
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
    const Target target = parse_target(arguments, 30000);
    const std::uint64_t id = arguments.get_uint("id");
    auto context = client_context(target.pki, wire::station_identity(id));
    const Submission submission = station_submission(id, arguments.get_int("x"), arguments.get_int("y"),
                                                     arguments.get_uint("radius"));
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

// Test-only dishonest station: submits raw ring elements without the range
// checks of encode_coordinate and encode_radius, so the integration tests can
// check that the parties' own check excludes it. Clients are untrusted, so this
// gives nothing a modified client could not do.
int run_unchecked_station(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "id", "x-word", "y-word",
                          "radius-word"});
    const Target target = parse_target(arguments, 30000);
    const std::uint64_t id = arguments.get_uint("id");
    auto context = client_context(target.pki, wire::station_identity(id));
    Submission submission;
    submission.kind = wire::OwnerKind::kStation;
    submission.station_id = id;
    submission.values = {{wire::Field::kX, parse_hex_word(arguments.get("x-word"))},
                         {wire::Field::kY, parse_hex_word(arguments.get("y-word"))},
                         {wire::Field::kRadius, parse_hex_word(arguments.get("radius-word"))}};
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

// Many stations from one process (benchmarks); each still uses its own
// certificate and its own pair of TLS connections.
int run_stations(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "file"});
    const Target target = parse_target(arguments, 120000);
    const std::vector<StationRecord> records = read_station_file(arguments.get("file"));
    std::vector<std::pair<std::uint64_t, Delivered>> submitted;
    submitted.reserve(records.size());
    try {
        for (const StationRecord& record : records) {
            auto context = client_context(target.pki, wire::station_identity(record.id));
            submitted.emplace_back(
                record.id,
                submit(*context, target, station_submission(record.id, record.x, record.y, record.radius)));
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

}  // namespace pps::client
