# Benchmarks

All numbers below were measured by executing the real two-party protocol. Two
`pp_party` processes ran the MP-SPDZ `semi2k` protocol over TLS. The
coordinator, the requester and the stations were separate client processes
that shared their own inputs. Nothing is modelled: bytes and rounds come from
MP-SPDZ's per-party counters and from the transport counters of each party.

## How to reproduce

```sh
python3 benchmarks/run_benchmarks.py --build-dir build-mpc \
    --repetitions 3 --station-counts 1,4,16,64,256,1024 \
    --horizons 100,10000,1000000,4294967295 --fixed-stations 64 --fixed-horizon 10000
```

The script provisions a test PKI and runs every repetition on **fresh party
processes**. MP-SPDZ generates comparison preprocessing in batches, and fresh
processes ensure a session is charged for the batches it triggers. The script
compares every result with the plaintext oracle, including the output
reconstructed by the selected station and the absence of shares at
non-selected stations. It also fails if the triple or operation counts differ
between runs with the same `(N, D)`, since the search is oblivious. It writes
`runs.csv`, `summary.csv`, `summary.md` and `environment.json`.

## Environment of the recorded run

`benchmarks/results/2026-09-29-loopback/`:

| | |
|---|---|
| Hardware | Apple M1 Pro, 10 logical CPUs, 16 GiB RAM |
| OS / compiler | macOS 26.6.2 (arm64), Apple clang 21.0.0, `-O3` |
| Backend | MP-SPDZ `e0ee04674ac7ff1fbd4377508fdd349f95dbb7f3` (+ recorded clang-21 patch), `semi2k`, Z_(2^128) |
| Security model | semi-honest, two non-colluding computation parties, at most one corrupted; fully oblivious search |
| Network | loopback `127.0.0.1`, **no** latency or bandwidth shaping. Both parties and all clients shared one machine. |
| Repetitions | 3 per configuration, 39 runs, **39/39 correct** |

## Metric definitions

* **Offline**: input-independent work before the online phase. That is base
  OTs, plus OT-based generation of exactly the planned number of Beaver
  triples. Time is the maximum over the two parties. Bytes are per direction:
  P0→P1 is party 0's sent bytes and P1→P0 is party 1's.
* **Online**: from the moment inputs are loaded until the authorised selection
  is opened. It **includes** the comparison and truncation preprocessing
  (binary triples, daBits) that MP-SPDZ generates on demand inside the
  exported comparison functions. This can't be separated through MP-SPDZ's
  function-export API, so it is attributed to online rather than
  under-reported.
* **MP-SPDZ rounds**: the number of send or exchange operations party 0
  initiated (MP-SPDZ's own counter), a proxy for communication rounds.
* **Triples, comparisons, sync steps mul/cmp/half**: the operations the
  backend executed (batched multiplications, batched comparisons and
  halvings). They are exact, equal the public plan, and depend only on N and D.
* **Input/output cost** (per party, from `runs.csv`): an input share frame is
  68 bytes and an `InputDone` frame 72 bytes. A requester therefore sends 208
  bytes to each party and a station 276 bytes. The selected station receives
  2 × 72 bytes from each party; every other station receives one 48-byte
  `NoOutput`. TLS record overhead is not included.
* **End-to-end**: wall clock in the harness, from launching the coordinator
  process to the last client exiting. It includes process start-up, 2(N + 1)
  TLS handshakes and input submission. It excludes party start-up (the MP-SPDZ
  connection is made once per party process).

## Results

Mean ± standard deviation over 3 repetitions.

### Station count (D = 10 000, uniform placement)

| N | online s | offline s | online MiB P0→P1 / P1→P0 | offline MiB each way | MP-SPDZ rounds | triples | comparisons | sync steps mul/cmp/half | end-to-end s |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 0.821 ± 0.083 | 0.038 ± 0.011 | 0.26 / 0.26 | 0.28 | 519 | 91 | 31 | 61/16/14 | 0.91 ± 0.11 |
| 4 | 0.806 ± 0.020 | 0.033 ± 0.000 | 0.42 / 0.43 | 0.61 | 586 | 205 | 85 | 95/18/14 | 0.89 ± 0.04 |
| 16 | 0.863 ± 0.014 | 0.038 ± 0.001 | 1.04 / 1.06 | 1.95 | 659 | 661 | 301 | 129/20/14 | 1.00 ± 0.03 |
| 64 | 0.917 ± 0.010 | 0.061 ± 0.001 | 3.49 / 3.56 | 7.29 | 759 | 2485 | 1165 | 163/22/14 | 1.22 ± 0.03 |
| 256 | 1.260 ± 0.061 | 0.234 ± 0.065 | 13.32 / 13.36 | 28.66 | 904 | 9781 | 4621 | 197/24/14 | 2.42 ± 0.25 |
| 1024 | 1.732 ± 0.049 | 0.961 ± 0.108 | 52.69 / 52.55 | 114.16 | 1344 | 38965 | 18445 | 231/26/14 | 6.29 ± 0.10 |

### Search horizon (N = 64, uniform placement)

| D | online s | offline s | online MiB P0→P1 / P1→P0 | offline MiB each way | MP-SPDZ rounds | triples | comparisons | sync steps mul/cmp/half | end-to-end s |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 0.596 ± 0.011 | 0.049 ± 0.000 | 1.97 / 2.02 | 4.58 | 458 | 1561 | 710 | 93/15/7 | 0.90 ± 0.02 |
| 10 000 | 0.945 ± 0.015 | 0.059 ± 0.000 | 3.49 / 3.56 | 7.29 | 759 | 2485 | 1165 | 163/22/14 | 1.24 ± 0.00 |
| 1 000 000 | 1.238 ± 0.017 | 0.071 ± 0.002 | 4.79 / 4.89 | 9.61 | 1017 | 3277 | 1555 | 223/28/20 | 1.54 ± 0.02 |
| 2^32 − 1 | 1.911 ± 0.025 | 0.090 ± 0.001 | 7.59 / 7.75 | 14.64 | 1571 | 4993 | 2400 | 353/41/33 | 2.25 ± 0.05 |

### Station distribution (N = 64, D = 10 000)

| placement | online s | offline s | online MiB P0→P1 / P1→P0 | offline MiB each way | MP-SPDZ rounds | triples | comparisons | sync steps mul/cmp/half | end-to-end s |
|---|---|---|---|---|---|---|---|---|---|
| uniform in the horizon square | 0.955 ± 0.019 | 0.060 ± 0.000 | 3.49 / 3.56 | 7.29 | 759 | 2485 | 1165 | 163/22/14 | 1.28 ± 0.01 |
| clustered near the requester | 0.947 ± 0.017 | 0.060 ± 0.001 | 3.49 / 3.56 | 7.29 | 759 | 2485 | 1165 | 163/22/14 | 1.25 ± 0.03 |
| all beyond the horizon (no match) | 0.961 ± 0.049 | 0.060 ± 0.001 | 3.49 / 3.56 | 7.29 | 759 | 2485 | 1165 | 163/22/14 | 1.27 ± 0.07 |

## Interpretation

* **Placement has no effect**, as intended: triples, comparisons, sync steps,
  bytes and MP-SPDZ rounds are identical for uniform, clustered and
  no-match placements. Control flow and communication are independent of the
  data. The residual variation in time is timing noise.
* **Horizon** sets the number of binary-search rounds, `bit_width(D + 1)`
  (7 at D = 100, 33 at D = 2^32 − 1). Each round adds N + 1 secure
  comparisons, so online time and bytes grow with `log D`.
* **Station count** scales bytes and triples linearly in N. Rounds grow with
  `log N` (OR tree and tournament depth), so online time grows slowly.
* **Offline cost** is Beaver-triple generation. It grows linearly in the
  number of multiplications (≈ 3 KiB per direction per Z_(2^128) triple) and
  dominates bytes for large N.
* **Binary search does not make the oblivious search cheaper.** It cannot
  open candidate masks, so it cannot shrink the final tournament; it only adds
  its rounds before it. For comparison, the direct tournament argmin that was
  measured on the same host in `benchmarks/results/2026-09-24-loopback/`
  (commit `c73cb96`, since removed) had about 3–14× lower online time at the same
  N and D. That run's `binary` rows used the same algorithm as this one and
  match these byte, round and step counts exactly.
* End-to-end time at large N is dominated by 2(N + 1) sequential TLS
  handshakes during input submission, not by the MPC.

## Limitations of these measurements

* **Loopback only.** No latency or bandwidth was emulated, because this host
  had no unprivileged traffic shaping. Wide-area run time cannot be derived by
  multiplying one latency by a round count or by adding a guessed byte count.
  The rounds and bytes are reported so the protocol can be re-measured under
  real network conditions: run the parties on separate hosts, or shape the
  loopback interface with `tc netem` or `dnctl` where permitted.
* Both parties and all clients shared one 10-core machine, so CPU contention
  affects the timings. One earlier attempt of the N = 1024 configuration
  aborted with a transient `ENOBUFS` on the loopback socket; the recorded run
  is a clean rerun of the whole suite.
* Three repetitions per configuration are enough to show the trends and their
  variation, not for fine-grained statistical claims.
* Online figures include MP-SPDZ's on-demand comparison preprocessing; see
  the metric definitions.
