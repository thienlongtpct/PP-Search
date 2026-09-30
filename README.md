# Privacy-preserving nearest eligible station search (two-party MPC)

A requester finds the nearest **eligible** station without revealing its
location to anyone except the selected station. Stations do not reveal their
locations or support radii. The search runs as a real two-party computation:
two separate computation-party processes, each holding one additive share per
value, execute MP-SPDZ's `semi2k` protocol over Z_(2^128). The model is
semi-honest with non-colluding parties, at most one of them corrupted.

```
q_i        = (A_x − P_ix)² + (A_y − P_iy)²
eligible_i = (q_i ≤ R_i²) AND (q_i ≤ D²)
result     = eligible station minimising (q_i, station_id), or "no match"
```

* The coordinator and both parties learn only match/no-match and the
  selected station ID.
* The search is fully oblivious: its control flow, round count and message
  sizes depend only on the public station count and horizon. No distance,
  eligibility bit or candidate set is ever opened.
* The selected station receives the requester's exact encoded coordinates.
* All other stations receive nothing.

Details:

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): processes, backend choice,
  arithmetic domain and bounds, algorithms, session protocol.
* [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): security model, output
  policy, leakage, limitations.
* [docs/BENCHMARKS.md](docs/BENCHMARKS.md): measured two-process
  performance.

## Build

Requirements (tested on macOS 26 / Apple M1 Pro, Apple clang 21, CMake 4.2):

* git, CMake ≥ 3.20, Python 3 with the `cryptography` package (test PKI);
* OpenSSL 3, Boost, GMP, libsodium (for example
  `brew install openssl@3 boost gmp libsodium yasm cmake`).

```sh
# 1. Fetch and build MP-SPDZ at the pinned revision (third_party/mp-spdz.lock).
#    This verifies every submodule SHA and applies the recorded patch.
scripts/build_mpspdz.sh

# 2. Build the parties, the client, the MP-SPDZ bytecode and the tests.
cmake -S . -B build-mpc -DCMAKE_BUILD_TYPE=Release
cmake --build build-mpc -j

# 3. Unit, two-process preprocessing and process-level integration tests.
ctest --test-dir build-mpc --output-on-failure
```

## Run

`scripts/demo_local.sh` performs all of the following steps on one host.

```sh
# Test PKI: CA plus certificates for parties, coordinator, requester, stations,
# and MP-SPDZ's P0/P1 player certificates.
python3 scripts/provision_test_pki.py --out pki --stations 10,20 --requesters alice

# Each party gets a runtime directory with only its own MP-SPDZ key.
python3 scripts/prepare_party_runtime.py --party 0 --pki pki --programs build-mpc/mpc/Programs --out run/p0
python3 scripts/prepare_party_runtime.py --party 1 --pki pki --programs build-mpc/mpc/Programs --out run/p1

# Launch both computation parties as separate processes (or on separate hosts).
build-mpc/pp_party --party-id 0 --listen 127.0.0.1:15700 --peer 127.0.0.1:15710 \
    --mpc-hosts 127.0.0.1,127.0.0.1 --mpc-port-base 15720 --pki pki --runtime run/p0 &
build-mpc/pp_party --party-id 1 --listen 127.0.0.1:15701 --peer 127.0.0.1:15710 \
    --mpc-hosts 127.0.0.1,127.0.0.1 --mpc-port-base 15720 --pki pki --runtime run/p1 &

# One search. Every command is a separate process and prints JSON.
S=$(build-mpc/pp_client new-session)
C="--pki pki --party0 127.0.0.1:15700 --party1 127.0.0.1:15701 --session $S"
build-mpc/pp_client coordinator $C --horizon 100 --requester alice --stations 10,20 &
build-mpc/pp_client requester   $C --name alice --x 0 --y 0 &
build-mpc/pp_client station     $C --id 10 --x 2 --y 0 --radius 10 &
build-mpc/pp_client station     $C --id 20 --x 1 --y 1 --radius 10 &
wait
# coordinator: {"status":"ok","match":true,"station_id":20}
# station 20:  {"status":"selected","requester_x":0,"requester_y":0,...}
# station 10:  {"status":"not-selected","output_share_frames":0,...}
```

Useful `pp_party` options:

| Option | Purpose |
|---|---|
| `--stats FILE` | Append per-session JSON with offline/online time, bytes and rounds. |
| `--sessions N` | Exit after N sessions. |
| `--max-input-timeout-ms` | Upper bound on the input-collection timeout. |
| `--owner-timeout-ms` | Timeout for one owner's submission. |
| `--mpc-timeout-ms` | MPC-phase watchdog. |

`pp_client stations --file stations.csv` submits many stations from one
process, each with its own certificate and connections.

Coordinates are signed 32-bit integers in a Cartesian frame (for example
metres in a local projected frame), not raw latitude/longitude. Support radii
and the horizon are unsigned 32-bit integers in the same unit.

## Status

Implemented and tested:

* separate party processes with party-local `LocalShare`s;
* independent input sharing by every owner over mutually authenticated TLS;
* MP-SPDZ Beaver multiplication with OT-generated, consume-once triples;
* MP-SPDZ exact comparison and truncation;
* oblivious private binary search with a fixed, padded round count, then an
  exact oblivious tournament for the minimum `(q, id)`;
* recipient-specific output delivery;
* timeouts and coordinated aborts;
* process-level tests and real two-process benchmarks.

The security claims are limited to those in the threat model. The tests are
functional tests, not a security proof.
