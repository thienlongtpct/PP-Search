# Architecture

This repository implements a privacy-preserving **nearest eligible station
search** as a real two-party computation (2PC). Two computation parties run as
separate operating-system processes, hold one additive share of every private
value, and evaluate the search with the MP-SPDZ `semi2k` protocol. Input
owners share their own inputs; no process ever holds both shares of a private
input or intermediate value.

The only plaintext evaluator is `tests/support/plaintext_reference_ops.hpp`,
which is labelled test-only, lives under `tests/`, and is never linked into a
deployed binary.

## Roles and processes

```
                      ┌───────────────────────── coordinator (pp_client coordinator)
                      │   SessionOpen (public parameters)      ▲ SessionResult (match, station ID)
                      ▼                                        │
 requester ──TLS──► ┌────────────┐  control channel (TLS)  ┌────────────┐ ◄──TLS── requester
 (share 0)          │  party 0   │◄───────────────────────►│  party 1   │          (share 1)
 station i ─TLS──►  │  pp_party  │  MP-SPDZ semi2k (TLS)   │  pp_party  │ ◄─TLS── station i
 (share 0)          └────────────┘◄───────────────────────►└────────────┘          (share 1)
                          │  OutputShare / NoOutput (TLS)       │
                          └──────────► stations ◄───────────────┘
```

| Role | Process | Holds |
|---|---|---|
| Requester | `pp_client requester` | Its encoded location `(A_x, A_y)`; splits it and sends one share to each party. |
| Station `i` | `pp_client station` (or `stations` for many) | Its location `(P_ix, P_iy)` and support radius `R_i`; shares them; receives output only if selected. |
| Computation party 0 / 1 | `pp_party --party-id 0|1` | Only its own shares, its own triples, its own TLS keys and MP-SPDZ channel state. |
| Coordinator / router | `pp_client coordinator` | Public session parameters; receives the authorised result (match flag, selected station ID). It never sees or forwards shares. |

The same `pp_party` program implements both computation parties; the role is
chosen with `--party-id` and each party is started as its own process with its
own runtime directory, certificate and key. In the demo and tests they run on
one host, bound to `127.0.0.1`, but nothing depends on that.

## MPC backend

### Selection

| Candidate | Outcome |
|---|---|
| cryptoTools (previous dependency) | A PRNG/utility library. It provides no MPC protocol and was removed. |
| libOTe binary-triple experiment | Produces GF(2) triples, not arithmetic triples over Z_(2^128). It was never validated as a multiplication backend, so it was removed from the active backend. The old disabled header is deleted and is not presented as preprocessing. |
| ABY | Arithmetic sharing is limited to 64-bit rings, but a squared 2-D distance of signed 32-bit coordinates needs 65 bits. Rejected. |
| EMP-sh2pc (garbled circuits) | Viable for semi-honest 2PC, but every addition and 65-bit squaring becomes a Boolean circuit, and it has no arithmetic preprocessing or output-sharing layer. Less actively maintained. |
| **MP-SPDZ `semi2k`** | **Selected.** Actively maintained (pinned commit dated 2026-09-21). Semi-honest, dishonest-majority 2PC over Z_(2^k). OT-based preprocessing with no dealer; exact comparison and truncation over rings; mutually authenticated TLS between parties; a documented C++ API for calling compiled functions (`Machine::run_function`). |

MP-SPDZ is pinned in `third_party/mp-spdz.lock`: commit
`e0ee04674ac7ff1fbd4377508fdd349f95dbb7f3`, every recursive submodule revision
(libOTe/SoftSpokenOT, SimplestOT, simde, sse2neon, …), and one recorded patch
(`third_party/patches/mp-spdz-0001-clang21-dependent-template.patch`: two
missing `template` keywords that Apple clang 21 rejects). The patch does not
touch any cryptographic code. `scripts/build_mpspdz.sh` checks out and verifies
these revisions, applies the patch, builds MP-SPDZ, and archives exactly the
object files `semi2k` needs into `libpps_mpspdz.a`. It also records MP-SPDZ's
compiler and linker flags, so CMake compiles `src/backend/mpspdz_party.cpp`, the only
translation unit that includes MP-SPDZ headers, with identical settings. Our
build never defines `NDEBUG`, because mixing it with MP-SPDZ's objects would be
an ODR violation, and assertions stay active in release builds.

### How the backend is used

`MpSpdzParty` (`src/backend/mpspdz_party.hpp`) implements the common
`SecureOps` interface for one party:

| Operation | Implementation | Communication |
|---|---|---|
| `add`, `sub`, `constant` | local on the `LocalShare` (party 0 adds public constants) | none |
| `multiply` (batched) | MP-SPDZ's `Beaver<Semi2kShare<128>>` protocol. It opens only `x - a` and `y - b` | one round per batch |
| `less_equal` (batched) | exported MP-SPDZ function `leq` (`mpc/pp_ops.py`): `a <= b` with bit length 67 | MP-SPDZ-internal rounds |
| `fits_u32` (batched) | exported MP-SPDZ function `fits_u32` (`mpc/pp_ops.py`): `[0 ≤ v < 2^32]` over all 128 ring bits | MP-SPDZ-internal rounds |
| `and_bits`, `not_bit`, `select` | composed from the above: AND = product, NOT = 1 − a, select = f + c(t − f) | as composed |
| `reveal_selection` | MP-SPDZ `SemiMC` opening of exactly the match bit and `match · station_id` | one round |

There is no generic "open" or "reconstruct" operation in `SecureOps`.

The exported functions are compiled by CMake with
`compile.py -E semi2k -R 128 mpc/pp_ops.py`, for every power-of-two vector
size from 1 to 4096. A batch of `n` operations is split into chunks of at most
4096 and each chunk is padded to the next power of two with public zeros.
MP-SPDZ compiles the comparison for `semi2k` into its
two-party "split" technique: each party decomposes its own arithmetic share
into binary shares, and an exact binary adder circuit is evaluated on them. It
uses binary triples and daBits generated with OT (DEK20-style ring
techniques), so there is no statistical error. These arithmetic↔binary
conversions run inside the exported functions and are counted in their online
cost.

MP-SPDZ keeps process-wide singletons (`BaseMachine`), and its TLS connection
IDs cannot be reused. Each `pp_party` process therefore creates one MP-SPDZ
virtual machine and one TLS player at start-up and runs sessions on it
sequentially.

### Arithmetic domain and bounds

All private values are elements of the ring Z_(2^128) (`Semi2kShare<128>`).

| Quantity | Encoding / bound |
|---|---|
| Coordinates `A_x, A_y, P_ix, P_iy` | Signed 32-bit integers in a Cartesian frame (for example metres in a local projected ENU/UTM frame, **not** raw latitude/longitude), encoded in two's complement mod 2^128. |
| Support radius `R_i` | Unsigned 32-bit integer in the same unit. |
| Horizon `D` | Public unsigned 32-bit integer. |
| `dx, dy` | in (−2^32, 2^32) |
| `q_i = dx² + dy²` | ≤ 2·(2^32 − 1)² < 2^65. This needs 65 bits and is never truncated to 64 bits. |
| `R_i²`, `D²` | < 2^64 |
| Comparison operands | unsigned, < 2^66 (`kComparisonOperandBits = 66`) |

For inputs in their domains, no intermediate value approaches 2^128, so ring
arithmetic equals integer arithmetic for every quantity above. MP-SPDZ ring
comparisons take the sign of the operands' difference, read from its low
`bit_length + 1` = 68 bits. Operands in [0, 2^66) are therefore compared exactly as
unsigned integers. The largest difference magnitude is < 2^66, which is inside that
width and far below the 128-bit ring.

Those bounds only hold for inputs in their domains, because a comparison cannot see
the ring bits above its width. Honest owners check their own values
(`encode_coordinate`, `encode_radius`), but the parties cannot rely on that, so the
search excludes out-of-domain inputs inside the MPC; see "Search functionality"
and the threat model.

## Search functionality

```
q_i        = (A_x − P_ix)² + (A_y − P_iy)²          computed once per request
eligible_i = [q_i ≤ R_i²] AND [q_i ≤ D²]            inclusive boundaries
result     = eligible station minimising (q_i, station_id), or "no match"
```

Stations are processed in ascending public station ID order. The coordinator
sorts IDs and rejects duplicates, and the parties reject any non-increasing
list. This makes the result independent of the order in which inputs arrive.
An empty station set is public knowledge and yields "no match" without MPC.

**Exact private argmin (tournament).** A balanced tournament pairs adjacent
candidates `(valid, q, id)`. Because leaves are in ascending ID order and pairs
are always contiguous ranges, every ID in a left subtree is smaller than every
ID in the right subtree. The right candidate wins only if it is valid and
(the left one is invalid or `q_right < q_left`), so ties resolve to the smaller
ID without comparing IDs. Each level costs one batched comparison and three
multiplication rounds. The root's ID is multiplied by its valid bit, so a
no-match run opens ID 0.

**Direct selection (the only mode).** The eligibility bits directly initialise
the tournament's validity bits, `w_i = eligible_i`, and the tournament runs over
all `N` stations. The horizon `D` is only the public operand of `[q_i ≤ D²]`; it
does not change the schedule. No comparison bit, intermediate winner or eligibility bit is
ever opened, and invalid leaves stay in the schedule.

Input owners choose their own shares, so the parties cannot assume inputs are in
their domains, and comparisons with bit length 67 ignore the higher ring bits.
Each session therefore computes `[0 ≤ v < 2^32]` for every station's `P_x + 2^31`,
`P_y + 2^31` and `R`, and for the requester's `A_x + 2^31` and `A_y + 2^31`, with no
opening. Those five bits are ANDed into every station's eligibility bit. An
out-of-domain station is never eligible, and an out-of-domain requester gives no
match. Distances computed from such inputs are still evaluated, because the
schedule cannot depend on them, but they cannot affect the result: comparisons
always return bits, and the tournament ignores the distance of an invalid candidate.

Operation counts are functions of `N` only for `N ≥ 1` (`plan_search`, verified
in `tests/unit/test_search.cpp`, and against the real backend in
`tests/integration/test_processes.py`):

| phase | multiplications | comparisons | range checks |
|---|---|---|---|
| distances and radii | 3N | 0 | 0 |
| eligibility and input domains (three AND batches) | 5N + 1 | 2N | 3N + 2 |
| tournament (N − 1 pairs, 5 products and 1 comparison each) | 5(N − 1) | N − 1 | 0 |
| output mask | 1 | 0 | 0 |
| **total** | **M = 13N − 3** | **C = 3N − 1** | **K = 3N + 2** |

Each range check is two comparisons over 128 bits inside MP-SPDZ. There are
one reveal. The dependency depth is
`O(1 + log N)`: one batch of squares, one batched comparison, one batched range
check and three AND batches, then
one comparison and three multiplication batches on each of `⌈log₂ N⌉` tournament
levels, then the mask and the reveal. These are application-level counts:
MP-SPDZ's own comparison preprocessing and rounds are additional and are
measured, not counted, in `docs/BENCHMARKS.md`. An empty station list is public
and runs no secure operations, so the formulas apply from `N = 1`.

Each party logs the plan and the operations its backend actually executed
(`plan` and `operations` in `--stats`), and aborts the session if the executed
multiplications differ from the plan. The tests check that the two are equal
and that sessions with the same `N` but different data or horizons run identical
operations.

## Preprocessing

* **Beaver triples.** Before a session goes online, each party runs
  `CostPlanner` over the public control flow to compute the exact number of
  multiplications `M`. It then generates exactly `M` fresh triples with the
  peer using MP-SPDZ's `semi2k` live preprocessing (`SemiPrep2k` →
  `OTTripleGenerator`: OT-extension-based multiplication with no dealer, where
  each party receives only its own shares of `a`, `b`, `c = a·b`). The triples
  go into a party-local `TripleStore` that hands each triple to MP-SPDZ's
  `Beaver` protocol exactly once and erases it. An empty store throws
  `PreprocessingExhausted` and the session aborts; there is no fallback. The
  store is emptied at the start of every session. Each session asserts that
  `triples_consumed == M` and `triples_remaining == 0`.
* **Comparison preprocessing** (binary triples, daBits) is
  generated on demand by MP-SPDZ inside the exported functions. It is held in
  MP-SPDZ's own consume-once buffers in the party's worker thread for the life
  of the process. Leftover elements of a batch may serve a later session, but
  no element is used twice.
* **Test harness.** `tests/integration/preprocessing_party.cpp` runs as two processes and
  links a separately compiled backend with `PPS_TEST_HARNESS`. It opens
  triples to check `c = a·b`, checks that consumption is exact, that
  exhaustion is reported, that regenerated triples are fresh, and that
  comparison is correct at the edges of the 66-bit domain. The
  opening routine does not exist in `pp_party` (verified with `nm`).

## Session protocol

All non-MPC channels use one framed message format (`src/net/wire.hpp`):

```
magic "PPS1" | version u16 | type u16 | session_id[16] | step u32 |
sequence u32 | payload_length u32 (≤ 1 MiB) | reserved u32 = 0 | payload
```

Every message type is valid in exactly one protocol step, sequence numbers
start at 0 and increase by 1 per direction, and payload decoders reject
truncation, trailing bytes, unknown enums and non-zero padding. Input shares
carry `(session_id, owner kind, station_id, field, sequence)`.

1. **Open.** The coordinator connects to both parties and sends
   `SessionOpen{horizon, mode, timeout, requester name, strictly increasing
   station IDs}`. The only mode is `2` (direct selection); any other value is rejected.
2. **Agree.** The parties exchange a SHA-256 digest of the session parameters
   over their control channel and abort on mismatch.
3. **Inputs.** Each owner splits each field with fresh CSPRNG randomness
   (OpenSSL `RAND_bytes`) into `s0 + s1 mod 2^128`. It sends `s0` only to
   party 0 and `s1` only to party 1, over separate mutually authenticated TLS
   connections, followed by `InputDone` with a random 16-byte submission ID.
   A party accepts a submission only if:
   * the certificate identity (`requester:<name>` / `station:<id>`) belongs
     to the session;
   * every field arrives exactly once;
   * the owner fields match the authenticated identity.

   Unknown identities and duplicate submissions are rejected without
   disturbing the session. Malformed, incomplete or stalled submissions abort
   the session.
4. **Agree on inputs.** The parties compare a digest over the station set and
   every owner's submission ID. This guarantees both hold shares of the *same*
   submission; for example, racing duplicate submissions abort the session.
   Whatever a dishonest owner sends, its two shares add up to one ring element,
   which the in-MPC range check covers.
5. **Offline, then online MPC** as described above.
6. **Output.** Both parties open `(match, match·id)` to each other. If there is
   a match, each party sends its own share of `(A_x, A_y)` to the selected
   station over that station's authenticated connection
   (`OutputShare{station_id, field, share}`, bound to the session). Every other
   station receives `NoOutput` and no share. Each party sends
   `SessionResult{match, station_id}` to the coordinator, which checks that
   the two agree. The selected station reconstructs `s0 + s1 mod 2^128`. That
   is exactly MP-SPDZ's `SemiMC` opening, since `semi2k` shares carry no MACs.
   It then decodes the signed coordinates.

### Transport

`TlsConnection` (`src/net/tls_transport.cpp`) uses OpenSSL 3, TLS 1.3 only, and
mutual authentication: `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`
against the deployment CA, plus an exact check of the peer certificate's
single common name against the expected role. It provides exact reads and
writes over non-blocking sockets, per-call deadlines (`TimeoutError`),
`PeerClosedError` on EOF/reset, `SIGPIPE`-safe sends, and byte and message
counters per direction. Nothing logs inputs, shares, triples or reconstructed
values. The test suite checks party logs and statistics for a distinctive
requester coordinate.

The MPC channel between the parties is MP-SPDZ's `CryptoPlayer`: TLS with
per-party certificates `P0`/`P1`, verified by host-name check against each
party's own trust directory. MP-SPDZ sets 10-second send/receive timeouts and
TCP keep-alive on these sockets. The test PKI is created by
`scripts/provision_test_pki.py` (fresh ECDSA P-256 keys, a 30-day test CA).
`scripts/prepare_party_runtime.py` gives each party a runtime directory
containing only its own MP-SPDZ key and its peer's certificate.

### Errors, timeouts and aborts

* Every wait has a deadline: the session input deadline (from `SessionOpen`,
  capped by `--max-input-timeout-ms`), a per-owner submission deadline
  (`--owner-timeout-ms`), control-channel timeouts, and an MPC watchdog
  (`--mpc-timeout-ms`).
* A party that aborts notifies its peer over the control channel. The peer
  polls that channel while it collects inputs, so both abort promptly. Both
  send `Abort{code}` to the coordinator and to every connected owner, and no
  output is released.
* A party remembers the last 256 finished sessions. Owners that reconnect for
  a finished session get `session-closed`; owners that arrive before their
  session opens get `unknown-session` and retry.
* Preprocessing exhaustion is a clean abort: both parties hit it at the same
  public point, before any exchange, and keep serving later sessions.
* Any other failure inside the MPC phase is **fail-stop**: the party process
  exits (or the watchdog terminates it) because MP-SPDZ channel state cannot
  be resumed. A supervisor restarts it. Losing the control channel is also
  fail-stop.

## Repository layout

```
src/
  common/        ring arithmetic and bounds, errors, deadlines, CSPRNG/hash/sharing,
                 argument parsing, JSON output
  protocol/      the algorithm, independent of any backend or network:
                 secure_ops.hpp (LocalShare, SecureOps), search.hpp, cost_planner.hpp
  net/           wire.* (framing), transport.hpp, tls_transport.*
  backend/       mpspdz_party.* (SecureOps on MP-SPDZ; the only code that includes it)
  party/         pp_party: main.cpp, party_server*.cpp (session phases), session.hpp,
                 peer_channel.*, session_stats.*, watchdog.hpp
  client/        pp_client: main.cpp, input_owner.cpp, coordinator.cpp,
                 fault_injection.cpp (tests only), client_common.*
mpc/pp_ops.py    exported MP-SPDZ functions (leq, fits_u32)
cmake/           MpSpdz.cmake (locates and verifies the pinned backend)
scripts/         build_mpspdz.sh, provision_test_pki.py, prepare_party_runtime.py, demo_local.sh
tests/
  support/       CHECK macros, plaintext oracle, plaintext reference evaluator
  unit/          no second party: encoding, wire validation, search logic
  integration/   real processes: harness.py, test_processes.py, test_preprocessing.py,
                 preprocessing_party.cpp
docs/            architecture, threat model, benchmarks
benchmarks/      run_benchmarks.py, results/
third_party/     mp-spdz.lock, patches/, mp-spdz/ (checkout, not versioned)
```

Dependencies point one way: `common` ← `protocol` and `net` ← `backend` ← `party`;
`client` uses only `common` and `net`, so it cannot link the MPC backend, and
`protocol` depends on neither the network nor MP-SPDZ.
