# Benchmarks

All numbers below were measured by executing the real two-party protocol. Two
`pp_party` processes ran the MP-SPDZ `semi2k` protocol over TLS. The
coordinator, the requester and the stations were separate client processes
that shared their own inputs. Nothing is modelled: bytes and rounds come from
MP-SPDZ's per-party counters and from the transport counters of each party.

`benchmarks/historical/simulator-only-benchmark.csv` is **not** comparable. It
holds timings from the removed single-process simulator, which performed no
secure computation and no communication, and a latency/bandwidth *model* that
this repository no longer uses.

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
non-selected stations. It writes `runs.csv`, `summary.csv`, `summary.md` and
`environment.json`.

## Environment of the recorded run

`benchmarks/results/2026-09-24-loopback/`:

| | |
|---|---|
| Hardware | Apple M1 Pro, 10 logical CPUs, 16 GiB RAM |
| OS / compiler | macOS 26.6.2 (arm64), Apple clang 21.0.0, `-O3` |
| Backend | MP-SPDZ `e0ee04674ac7ff1fbd4377508fdd349f95dbb7f3` (+ recorded clang-21 patch), `semi2k`, Z_(2^128) |
| Security model | semi-honest, two non-colluding computation parties, at most one corrupted |
| Network | loopback `127.0.0.1`, **no** latency or bandwidth shaping. Both parties and all clients shared one machine. |
| Repetitions | 3 per configuration and mode, 78 runs, **78/78 correct** |

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
* **Sync steps mul/cmp/half**: the protocol-level synchronisation phases of
  our algorithm, meaning batched multiplications, batched comparisons and
  halvings. They are exact, and depend only on N, D and the mode.
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

| N | mode | online s | offline s | online MiB P0→P1 / P1→P0 | offline MiB each way | MP-SPDZ rounds | sync steps mul/cmp/half | end-to-end s |
|---|---|---|---|---|---|---|---|---|
| 1 | binary | 0.844 ± 0.122 | 0.033 ± 0.001 | 0.26 / 0.26 | 0.28 | 519 | 61/16/14 | 0.91 ± 0.13 |
| 1 | argmin | 0.059 ± 0.001 | 0.031 ± 0.000 | 0.01 / 0.02 | 0.02 | 26 | 3/1/0 | 0.11 ± 0.00 |
| 4 | binary | 0.841 ± 0.017 | 0.033 ± 0.000 | 0.42 / 0.43 | 0.61 | 586 | 95/18/14 | 0.93 ± 0.03 |
| 4 | argmin | 0.109 ± 0.002 | 0.032 ± 0.001 | 0.04 / 0.04 | 0.10 | 62 | 9/3/0 | 0.22 ± 0.00 |
| 16 | binary | 0.945 ± 0.041 | 0.044 ± 0.001 | 1.04 / 1.06 | 1.95 | 659 | 129/20/14 | 1.09 ± 0.04 |
| 16 | argmin | 0.160 ± 0.002 | 0.032 ± 0.000 | 0.11 / 0.11 | 0.42 | 98 | 15/5/0 | 0.27 ± 0.00 |
| 64 | binary | 1.030 ± 0.047 | 0.067 ± 0.007 | 3.49 / 3.56 | 7.29 | 759 | 163/22/14 | 1.35 ± 0.04 |
| 64 | argmin | 0.218 ± 0.010 | 0.038 ± 0.001 | 0.35 / 0.36 | 1.69 | 137 | 21/7/0 | 0.52 ± 0.03 |
| 256 | binary | 1.217 ± 0.058 | 0.230 ± 0.046 | 13.32 / 13.36 | 28.66 | 904 | 197/24/14 | 2.39 ± 0.04 |
| 256 | argmin | 0.283 ± 0.023 | 0.059 ± 0.000 | 1.31 / 1.32 | 6.75 | 181 | 27/9/0 | 1.22 ± 0.01 |
| 1024 | binary | 1.730 ± 0.128 | 0.929 ± 0.089 | 52.69 / 52.55 | 114.16 | 1344 | 231/26/14 | 6.26 ± 0.33 |
| 1024 | argmin | 0.362 ± 0.011 | 0.186 ± 0.069 | 5.14 / 5.14 | 27.00 | 253 | 33/11/0 | 4.00 ± 0.03 |

### Search horizon (N = 64, uniform placement)

| D | mode | online s | offline s | online MiB P0→P1 / P1→P0 | offline MiB each way | MP-SPDZ rounds | sync steps | end-to-end s |
|---|---|---|---|---|---|---|---|---|
| 100 | binary | 0.606 ± 0.005 | 0.050 ± 0.002 | 1.97 / 2.02 | 4.58 | 458 | 93/15/7 | 0.91 ± 0.01 |
| 100 | argmin | 0.212 ± 0.002 | 0.037 ± 0.000 | 0.35 / 0.36 | 1.69 | 137 | 21/7/0 | 0.48 ± 0.00 |
| 10 000 | binary | 0.996 ± 0.018 | 0.066 ± 0.006 | 3.49 / 3.56 | 7.29 | 759 | 163/22/14 | 1.31 ± 0.03 |
| 10 000 | argmin | 0.223 ± 0.015 | 0.039 ± 0.001 | 0.35 / 0.36 | 1.69 | 137 | 21/7/0 | 0.54 ± 0.05 |
| 1 000 000 | binary | 1.295 ± 0.018 | 0.072 ± 0.001 | 4.79 / 4.89 | 9.61 | 1017 | 223/28/20 | 1.62 ± 0.03 |
| 1 000 000 | argmin | 0.216 ± 0.006 | 0.038 ± 0.001 | 0.35 / 0.36 | 1.69 | 137 | 21/7/0 | 0.52 ± 0.06 |
| 2^32 − 1 | binary | 1.991 ± 0.033 | 0.095 ± 0.004 | 7.59 / 7.75 | 14.64 | 1571 | 353/41/33 | 2.35 ± 0.05 |
| 2^32 − 1 | argmin | 0.217 ± 0.007 | 0.038 ± 0.001 | 0.35 / 0.36 | 1.69 | 137 | 21/7/0 | 0.54 ± 0.05 |

### Station distribution (N = 64, D = 10 000)

| placement | mode | online s | offline s | online MiB P0→P1 / P1→P0 | MP-SPDZ rounds | end-to-end s |
|---|---|---|---|---|---|---|
| uniform in the horizon square | binary | 0.976 ± 0.020 | 0.062 ± 0.000 | 3.49 / 3.56 | 759 | 1.31 ± 0.03 |
| uniform in the horizon square | argmin | 0.221 ± 0.010 | 0.039 ± 0.003 | 0.35 / 0.36 | 137 | 0.52 ± 0.06 |
| clustered near the requester | binary | 1.017 ± 0.005 | 0.062 ± 0.000 | 3.49 / 3.56 | 759 | 1.34 ± 0.04 |
| clustered near the requester | argmin | 0.219 ± 0.004 | 0.038 ± 0.000 | 0.35 / 0.36 | 137 | 0.52 ± 0.03 |
| all beyond the horizon (no match) | binary | 0.990 ± 0.022 | 0.062 ± 0.000 | 3.49 / 3.56 | 759 | 1.30 ± 0.03 |
| all beyond the horizon (no match) | argmin | 0.224 ± 0.018 | 0.040 ± 0.003 | 0.35 / 0.36 | 137 | 0.52 ± 0.04 |

## Interpretation

* **Binary search plus exact selection is slower than direct exact argmin in
  every measured configuration.**
  * Online time is 3–14× higher.
  * Online communication is 5–26× higher.
  * MP-SPDZ rounds are 3–20× higher.
  * The binary search cannot open its candidate masks, so it cannot shrink
    the final tournament. It only adds `bit_width(D + 1)` rounds, each with
    N + 1 secure comparisons, before an argmin whose cost is unchanged.
  * The direct argmin therefore dominates under this security policy. The
    binary-search mode is kept because it was requested and is fully
    supported, not because it is faster.
* **Horizon** affects only binary mode: the number of rounds grows with
  `bit_width(D + 1)` (7 at D = 100, 33 at D = 2^32 − 1). Argmin is flat in D.
* **Placement has no effect** on either mode, as intended: control flow and
  communication are independent of the data, including match versus
  no-match. The residual variation is timing noise.
* **Offline cost** is Beaver-triple generation. It grows linearly in the
  number of multiplications (≈ 3 KiB per direction per Z_(2^128) triple) and
  dominates bytes for large N.
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
  affects the timings.
* Three repetitions per configuration are enough to show the trends and their
  variation, not for fine-grained statistical claims.
* Online figures include MP-SPDZ's on-demand comparison preprocessing; see
  the metric definitions.
