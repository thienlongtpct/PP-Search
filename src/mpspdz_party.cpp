// The only translation unit that includes MP-SPDZ. See include/pps/mpspdz_party.hpp.

#include "Machines/Semi2k.hpp"
#include "Processor/Machine.hpp"
#include "Processor/OnlineOptions.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/ProtocolSet.h"

#include "pps/errors.hpp"
#include "pps/mpspdz_party.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstring>

namespace pps {
namespace {

using Share = Semi2kShare<128>;
using Clear = SignedZ2<128>;
using Clock = std::chrono::steady_clock;

static_assert(Clear::N_BYTES == 16, "semi2k ring must be Z_(2^128)");

// Largest compiled vector size of the exported functions (mpc/pp_ops.py);
// every power of two from 1 to kMaxFunctionBatch is compiled.
constexpr std::size_t kMaxFunctionBatch = 4096;

Share to_backend(const LocalShare& share) {
    std::uint8_t bytes[16];
    store_le(share.value, bytes);
    Clear value;
    value.assign(bytes);
    return Share(value);
}

Word to_word(const Clear& value) {
    std::uint8_t bytes[16];
    std::memcpy(bytes, value.get_ptr(), sizeof bytes);
    return load_le(bytes);
}

LocalShare from_backend(const Share& share) { return {to_word(share)}; }

std::uint64_t rounds_initiated(const NamedCommStats& stats) {
    std::uint64_t rounds = 0;
    for (const auto& [name, entry] : stats) {
        if (name.rfind("Receiving", 0) != 0) {
            rounds += entry.rounds;
        }
    }
    return rounds;
}

double seconds_since(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

// Finite, consume-once store of Beaver triples for MP-SPDZ's Beaver protocol.
class TripleStore final : public Preprocessing<Share> {
public:
    explicit TripleStore(DataPositions& usage) : Preprocessing<Share>(usage) {}

    void replace(std::vector<std::array<Share, 3>> triples) {
        triples_ = std::move(triples);
        next_ = 0;
    }

    void get_three_no_count(Dtype dtype, Share& a, Share& b, Share& c) override {
        if (dtype != DATA_TRIPLE) {
            throw std::runtime_error("triple store only provides multiplication triples");
        }
        if (next_ >= triples_.size()) {
            throw PreprocessingExhausted("multiplication triples exhausted");
        }
        std::array<Share, 3>& triple = triples_[next_++];
        a = triple[0];
        b = triple[1];
        c = triple[2];
        triple = {};  // erase consumed material
        ++consumed_;
    }

    std::uint64_t remaining() const { return triples_.size() - next_; }
    std::uint64_t consumed() const { return consumed_; }

private:
    std::vector<std::array<Share, 3>> triples_;
    std::size_t next_ = 0;
    std::uint64_t consumed_ = 0;
};

}  // namespace

struct MpSpdzParty::Impl {
    explicit Impl(const MpSpdzConfig& config)
        : names(config.party_id, config.port_base, config.hosts),
          machine(names, true, OnlineOptions(Share())),
          player(machine.get_player()),
          usage(player.num_players()),
          store(usage),
          beaver(player) {
        beaver.init(store, mac_check);
    }

    Names names;
    Machine<Share> machine;
    Player& player;
    DataPositions usage;
    TripleStore store;
    Share::MAC_Check mac_check;
    Beaver<Share> beaver;

    PhaseCost connect;
    BackendStats stats;
    NamedCommStats online_start_comm;
    NamedCommStats online_start_worker_comm;
    Clock::time_point online_start = Clock::now();
    bool online = false;
    bool finished = false;
    std::uint64_t consumed_before_session = 0;

    // Cumulative traffic of MP-SPDZ's worker threads, published by each
    // thread after every job.
    NamedCommStats worker_comm() {
        NamedCommStats total;
        for (ThreadQueue* queue : machine.queues) {
            if (queue != nullptr) {
                total += queue->get_comm_stats();
            }
        }
        return total;
    }

    std::vector<LocalShare> run_elementwise(const std::string& name,
                                            std::vector<std::span<const LocalShare>> operands,
                                            int party) {
        const std::size_t n = operands.front().size();
        std::vector<LocalShare> output;
        output.reserve(n);
        for (std::size_t offset = 0; offset < n;) {
            const std::size_t chunk = std::min(n - offset, kMaxFunctionBatch);
            const std::size_t padded = std::bit_ceil(chunk);
            std::vector<std::vector<Share>> arguments(
                operands.size(), std::vector<Share>(padded, Share::constant(0, party)));
            for (std::size_t k = 0; k < operands.size(); ++k) {
                for (std::size_t i = 0; i < chunk; ++i) {
                    arguments[k][i] = to_backend(operands[k][offset + i]);
                }
            }
            std::vector<Share> results(padded);
            FunctionArgument result(results);
            std::vector<FunctionArgument> function_arguments;
            for (auto& argument : arguments) {
                function_arguments.emplace_back(argument);
            }
            machine.run_function(name, result, function_arguments);
            for (std::size_t i = 0; i < chunk; ++i) {
                output.push_back(from_backend(results[i]));
            }
            offset += chunk;
        }
        return output;
    }
};

MpSpdzParty::MpSpdzParty(const MpSpdzConfig& config) : party_id_(config.party_id) {
    if (config.party_id != 0 && config.party_id != 1) {
        throw std::invalid_argument("party ID must be 0 or 1");
    }
    if (config.hosts.size() != 2) {
        throw std::invalid_argument("exactly two computation parties are supported");
    }
    const auto start = Clock::now();
    impl_ = std::make_unique<Impl>(config);
    impl_->connect.seconds = seconds_since(start);
    const NamedCommStats comm = impl_->player.total_comm();
    impl_->connect.bytes_sent = comm.sent;
    impl_->connect.rounds = rounds_initiated(comm);
    start_session();
}

void MpSpdzParty::start_session() {
    impl_->store.replace({});
    impl_->stats = {};
    impl_->stats.connect = impl_->connect;
    impl_->online = false;
    impl_->finished = false;
    impl_->consumed_before_session = impl_->store.consumed();
}

MpSpdzParty::~MpSpdzParty() = default;

void MpSpdzParty::generate_triples(std::uint64_t count) {
    if (impl_->online) {
        throw std::logic_error("triples must be generated before the online phase");
    }
    const auto start = Clock::now();
    const NamedCommStats before = impl_->player.total_comm();
    std::vector<std::array<Share, 3>> triples;
    triples.reserve(count);
    {
        // MP-SPDZ's semi2k live preprocessing: OT-based (SoftSpokenOT via
        // libOTe) Gilboa-style multiplication, no dealer. Surplus triples in
        // the final batch are destroyed with the ProtocolSet.
        ProtocolSet<Share> set(impl_->player, impl_->machine);
        // Generate in batches of exactly the requested size where possible.
        set.preprocessing.buffer_size =
            static_cast<int>(std::clamp<std::uint64_t>(count, 1, 1u << 20));
        for (std::uint64_t i = 0; i < count; ++i) {
            triples.push_back(set.preprocessing.get_triple(-1));
        }
    }
    impl_->store.replace(std::move(triples));
    const NamedCommStats spent = impl_->player.total_comm() - before;
    impl_->stats.offline.seconds += seconds_since(start);
    impl_->stats.offline.bytes_sent += spent.sent;
    impl_->stats.offline.rounds += rounds_initiated(spent);
    impl_->stats.triples_requested += count;
}

std::uint64_t MpSpdzParty::triples_remaining() const { return impl_->store.remaining(); }

void MpSpdzParty::begin_online() {
    impl_->online = true;
    impl_->online_start = Clock::now();
    impl_->online_start_comm = impl_->player.total_comm();
    impl_->online_start_worker_comm = impl_->worker_comm();
}

std::vector<LocalShare> MpSpdzParty::multiply(std::span<const LocalShare> x,
                                              std::span<const LocalShare> y) {
    check_sizes(x.size(), y.size());
    if (x.empty()) {
        return {};
    }
    Beaver<Share>& beaver = impl_->beaver;
    beaver.init_mul();
    for (std::size_t i = 0; i < x.size(); ++i) {
        beaver.prepare_mul(to_backend(x[i]), to_backend(y[i]));
    }
    // Opens only the masked differences x - a and y - b.
    beaver.exchange();
    std::vector<LocalShare> result(x.size());
    for (std::size_t i = 0; i < x.size(); ++i) {
        result[i] = from_backend(beaver.finalize_mul());
    }
    impl_->stats.operations.multiplications += x.size();
    ++impl_->stats.operations.multiply_steps;
    return result;
}

std::vector<LocalShare> MpSpdzParty::less_equal(std::span<const LocalShare> x,
                                                std::span<const LocalShare> y) {
    check_sizes(x.size(), y.size());
    if (x.empty()) {
        return {};
    }
    impl_->stats.operations.comparisons += x.size();
    ++impl_->stats.operations.compare_steps;
    return impl_->run_elementwise("leq", {x, y}, party_id_);
}

std::vector<LocalShare> MpSpdzParty::halve(std::span<const LocalShare> x) {
    if (x.empty()) {
        return {};
    }
    impl_->stats.operations.halvings += x.size();
    ++impl_->stats.operations.halve_steps;
    return impl_->run_elementwise("half", {x}, party_id_);
}

AuthorizedSelection MpSpdzParty::reveal_selection(const LocalShare& match,
                                                  const LocalShare& station_id) {
    auto& mc = impl_->mac_check;
    mc.init_open(impl_->player);
    mc.prepare_open(to_backend(match));
    mc.prepare_open(to_backend(station_id));
    mc.exchange(impl_->player);
    const Word opened_match = to_word(mc.finalize_open());
    const Word opened_id = to_word(mc.finalize_open());
    if (opened_match > 1 || (opened_id >> 64) != 0 || (opened_match == 0 && opened_id != 0)) {
        throw std::runtime_error("authorized output is outside its domain");
    }
    ++impl_->stats.operations.reveal_steps;
    return {opened_match == 1, static_cast<std::uint64_t>(opened_id)};
}

BackendStats MpSpdzParty::finish() {
    if (impl_->finished) {
        return impl_->stats;
    }
    impl_->finished = true;
    BackendStats& stats = impl_->stats;
    if (impl_->online) {
        const NamedCommStats main_comm = impl_->player.total_comm() - impl_->online_start_comm;
        const NamedCommStats worker_comm = impl_->worker_comm() - impl_->online_start_worker_comm;
        stats.online.seconds = seconds_since(impl_->online_start);
        stats.online.bytes_sent = main_comm.sent + worker_comm.sent;
        stats.online.rounds = rounds_initiated(main_comm) + rounds_initiated(worker_comm);
    }
    stats.triples_consumed = impl_->store.consumed() - impl_->consumed_before_session;
    stats.triples_remaining = impl_->store.remaining();
    return stats;
}

#ifdef PPS_TEST_HARNESS
std::vector<std::array<Word, 3>> MpSpdzParty::open_triples_for_test_harness(std::uint64_t count) {
    std::vector<std::array<Share, 3>> taken(count);
    for (auto& triple : taken) {
        impl_->store.get_three_no_count(DATA_TRIPLE, triple[0], triple[1], triple[2]);
    }
    auto& mc = impl_->mac_check;
    mc.init_open(impl_->player);
    for (const auto& triple : taken) {
        for (const Share& value : triple) {
            mc.prepare_open(value);
        }
    }
    mc.exchange(impl_->player);
    std::vector<std::array<Word, 3>> opened(count);
    for (auto& triple : opened) {
        for (Word& value : triple) {
            value = to_word(mc.finalize_open());
        }
    }
    return opened;
}

std::vector<Word> MpSpdzParty::open_for_test_harness(std::span<const LocalShare> values) {
    auto& mc = impl_->mac_check;
    mc.init_open(impl_->player);
    for (const LocalShare& value : values) {
        mc.prepare_open(to_backend(value));
    }
    mc.exchange(impl_->player);
    std::vector<Word> opened(values.size());
    for (Word& value : opened) {
        value = to_word(mc.finalize_open());
    }
    return opened;
}
#endif

}  // namespace pps
