# Benchmarks

All numbers below were measured by executing the real two-party protocol. Two
`pp_party` processes ran the MP-SPDZ `semi2k` protocol over TLS. The
coordinator, the requester and the stations were separate client processes
that shared their own inputs. Nothing is modelled: bytes and rounds come from
MP-SPDZ's per-party counters and from the transport counters of each party.

**These results are single-host loopback measurements. No separate-host
experiment has been run.**

## How to reproduce

On the recorded host, Homebrew's default OpenSSL is now version 4, which
Boost.Asio's headers do not compile against, and the default `python3` has no
`cryptography` package, so the build selects these explicitly:

```sh
PY=/opt/homebrew/Frameworks/Python.framework/Versions/3.14/bin/python3.14
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPython3_EXECUTABLE="$PY" \
    -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 \
    "-DCMAKE_CXX_FLAGS=-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/boost@1.85/include" \
    "-DCMAKE_EXE_LINKER_FLAGS=-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/boost@1.85/lib"
cmake --build build -j 8
ctest --test-dir build --output-on-failure

"$PY" benchmarks/run_benchmarks.py --build-dir build \
    --out benchmarks/results/<new-directory> --repetitions 10 \
    --station-counts 1,4,16,64,256,1024 --horizons 100,10000,1000000,4294967295 \
    --fixed-stations 64 --fixed-horizon 10000
```

The script refuses to overwrite a directory that already holds results. It
starts fresh party processes for every repetition, because MP-SPDZ generates
comparison preprocessing in batches and a session should be charged for the
batches it triggers. It compares every result with the plaintext oracle,
including the output reconstructed by the selected station and the absence of
shares at non-selected stations. It fails if the operation counts differ from
`M = 13N − 3`, `C = 3N − 1`, `K = 3N + 2` or vary across horizons and placements at
fixed `N`.

## Recorded run

`benchmarks/results/2026-11-02-range-check-loopback/`:

| | |
|---|---|
| `runs.csv` / `attempts.jsonl` | one row per run / every attempt in order (130 attempted, 130 completed, 0 failed, none rerun) |
| `summary.csv` / `summary.md` | mean, sample SD, median, min and max per configuration / readable table |
| `config.json` | command, configurations and every run's seed and input file |
| `environment.json` | software revision, binary hashes, hardware, toolchain, load average, power source, network |
| `source.diff` | uncommitted changes to tracked files when the run started; apply to the recorded `git_head` |
| `source-snapshot.tar.gz` | the source the binaries were built from, because the reorganized source files are untracked and `source.diff` does not contain them |
| `final-ctest.log` | the test run after the benchmark |
| `work/` | raw party logs, per-session statistics, client outputs, station inputs, test PKI |

| | |
|---|---|
| Hardware | MacBookPro18,1, Apple M1 Pro (8 performance + 2 efficiency cores), 16 GiB RAM, on AC power |
| OS / compiler | macOS 26.6.2 (arm64), Apple clang 21.0.0 (clang-2100.4.1.1), `-O3` |
| Libraries | OpenSSL 3 and Boost 1.85 from Homebrew, as selected above |
| Backend | MP-SPDZ `e0ee04674ac7ff1fbd4377508fdd349f95dbb7f3` (+ recorded clang-21 patch), `semi2k`, Z_(2^128) |
| Source | `e754831` plus uncommitted changes, in `source-snapshot.tar.gz` (the implementation was not committed when measured) |
| Security model | semi-honest, two non-colluding computation parties, at most one corrupted |
| Network | loopback `127.0.0.1`, **no** latency or bandwidth shaping; both parties and all clients shared one machine |
| Repetitions | 10 per configuration, 130 runs, **130/130 correct**: 13 sweep configurations covering 11 distinct `(N, D, placement)` settings, because `(64, 10 000, uniform)` is in all three sweeps with different seeds |
| Seeds | `random.Random("<sweep>-<N>-<D>-<placement>-<repetition>")`, for public placements only; shares use the CSPRNG |
| Conditions | an ordinary desktop session, not an isolated machine; file edits ran on it during the horizon and distribution sweeps; load averages are in `environment.json` |

`pp_party` and `pp_client` were not rebuilt after the run. Their SHA-256 hashes match
`environment.json`, and `final-ctest.log` passed with them. After the run, only documentation,
comments, tests and one label in `run_benchmarks.py` changed, so the recorded
`run_benchmarks_sha256` and `harness_sha256` may differ from the final files.

## Metric definitions

* **Application operation counts**: secure products `M`, comparisons `C` and
  input range checks `K`, counted by the backend wrapper in the code
  that ran. For `N ≥ 1`, `M = 13N − 3`, `C = 3N − 1`, and `K = 3N + 2`. An empty station list is public and runs nothing, so the formulas
  do not apply at `N = 0`. These exclude MP-SPDZ's internal preprocessing.
* **Offline**: input-independent work before the online phase, namely base OTs and
  OT-based generation of exactly `M` Beaver triples. Time is the maximum over
  the two parties.
* **Online**: from when inputs are loaded until the authorised selection is
  opened, as the maximum over the two parties. It **includes** the comparison
  preprocessing (binary triples, daBits) that MP-SPDZ generates on demand inside
  the exported comparison and range check functions. MP-SPDZ's function-export API does not
  separate it, so it is attributed to online rather than under-reported.
* **Communication direction**: P0→P1 is party 0's sent bytes, and P1→P0 is party
  1's, each from that party's own counter.
* **Total backend MiB**: offline plus online MP-SPDZ traffic, summed over **both
  directions**. It excludes input, output and control traffic, reported
  separately in `runs.csv`. 1 MiB = 2^20 bytes. This is the manuscript's
  "communication".
* **MP-SPDZ rounds**: the number of send or exchange operations party 0
  initiated (MP-SPDZ's own counter), a proxy for communication rounds.
* **End-to-end**: wall clock in the harness, from launching the coordinator
  process to the last client exiting. It includes client start-up, 2(N + 1)
  TLS handshakes, input submission, offline, online and output delivery. It
  excludes party start-up and the MP-SPDZ connection. This is the manuscript's
  "runtime".
* **Summary statistics and error bars**: mean ± sample standard deviation
  (n − 1) over 10 fresh-process runs. Figure error bars are ±1 sample SD.

## Results

### Station count (D = 10 000, uniform placement)

| N | online s | offline s | end-to-end s | online MiB P0→P1 / P1→P0 | offline MiB each way | total backend MiB | MP-SPDZ rounds (P0) | M | C | K | sync steps mul/cmp |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0.107 ± 0.008 | 0.032 ± 0.002 | 0.177 ± 0.024 | 0.064 / 0.069 | 0.039 | 0.211 | 44 | 10 | 2 | 5 | 5/1 |
| 4 | 0.170 ± 0.004 | 0.031 ± 0.000 | 0.271 ± 0.003 | 0.137 / 0.141 | 0.153 | 0.585 | 80 | 49 | 11 | 14 | 11/3 |
| 16 | 0.250 ± 0.015 | 0.034 ± 0.001 | 0.384 ± 0.016 | 0.493 / 0.497 | 0.610 | 2.211 | 116 | 205 | 47 | 50 | 17/5 |
| 64 | 0.320 ± 0.004 | 0.041 ± 0.002 | 0.617 ± 0.024 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |
| 256 | 0.442 ± 0.023 | 0.075 ± 0.004 | 1.402 ± 0.033 | 7.503 / 7.511 | 9.751 | 34.515 | 242 | 3325 | 767 | 770 | 29/9 |
| 1024 | 0.798 ± 0.074 | 0.268 ± 0.047 | 4.618 ± 0.308 | 29.931 / 29.909 | 39.001 | 137.842 | 484 | 13309 | 3071 | 3074 | 35/11 |

### Search horizon (N = 64, uniform placement)

| D | online s | offline s | end-to-end s | online MiB P0→P1 / P1→P0 | offline MiB each way | total backend MiB | MP-SPDZ rounds (P0) | M | C | K | sync steps mul/cmp |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 100 | 0.326 ± 0.019 | 0.041 ± 0.001 | 0.624 ± 0.034 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |
| 10 000 | 0.325 ± 0.018 | 0.042 ± 0.002 | 0.618 ± 0.037 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |
| 1 000 000 | 0.326 ± 0.012 | 0.041 ± 0.001 | 0.615 ± 0.025 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |
| 2^32 − 1 | 0.332 ± 0.017 | 0.041 ± 0.002 | 0.638 ± 0.048 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |

### Station distribution (N = 64, D = 10 000)

| placement | online s | offline s | end-to-end s | online MiB P0→P1 / P1→P0 | offline MiB each way | total backend MiB | MP-SPDZ rounds (P0) | M | C | K | sync steps mul/cmp |
|---|---|---|---|---|---|---|---|---|---|---|---|
| uniform in the horizon square | 0.329 ± 0.016 | 0.042 ± 0.002 | 0.642 ± 0.047 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |
| clustered, all 64 eligible | 0.386 ± 0.056 | 0.046 ± 0.006 | 0.711 ± 0.076 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |
| beyond the horizon, none eligible | 0.344 ± 0.031 | 0.043 ± 0.002 | 0.667 ± 0.045 | 1.905 / 1.917 | 2.438 | 8.698 | 168 | 829 | 191 | 194 | 23/7 |

## Interpretation

* **Operation counts match the formulas.** Every run executed exactly
  `M = 13N − 3` products, `C = 3N − 1` comparisons and `K = 3N + 2` range checks. No
  discrepancy was found for `N ≥ 1`.
* **Range checks cost more than comparisons.** Each check is two comparisons over 128
  bits, against one over 68 bits for a `C` comparison.
* **Horizon has no effect on the schedule.** At `N = 64`, operation counts,
  backend bytes and rounds are byte-identical at all four horizons. Mean
  end-to-end time differs by less than one standard deviation.
* **Placement has no effect on the schedule.** At `N = 64` the same holds for
  placements with all, some and none of the stations eligible. Only output
  delivery differs: 7820 bytes per party with a match, 7732 without. A schedule
  observation like this is not an implementation-security proof. Mean times do differ
  across placements (0.64 s uniform, 0.71 s clustered, 0.67 s beyond the horizon, with
  standard deviations of 0.05 to 0.08 s) although backend bytes and rounds are identical.
  They were measured on a machine that was not isolated, so this is not evidence of a
  dependence on the data, nor does it rule one out; see the implementation side channel
  limitation in `docs/THREAT_MODEL.md`.
* **Station count** scales bytes linearly; rounds grow with `log N`.
* **Offline traffic exceeds online traffic**: about 3 KiB per direction per
  Z_(2^128) triple, compared with 32 bytes per direction for the Beaver openings.
* **End-to-end time at large N is dominated by input admission.** At N = 1024 the
  input phase averages 3.36 s of 4.62 s, compared with
  0.80 s online and 0.27 s offline, because of 2(N + 1) sequential TLS handshakes.

## One computation party per host

`pp_party` takes its addresses on the command line, and each party needs only its
own key material, so one party can run per host. `run_benchmarks.py` drives this
over ssh, starting fresh party processes on both hosts for each repetition. It
measures RTT with `ping` and TCP throughput with `iperf3` before and after the
suite, and **never changes network settings**. It refuses to run if both targets
report the same host name.

**Status:** the launcher ran end-to-end only with `--host0 local --host1 local`
(two runs, correct), which exercises the plumbing and is labelled
`local-plumbing-test` in its output. The ssh path, `ping`/`iperf3` measurement and
same-host check have **not** been run, because no authorised hosts were available.

Prerequisites on each host: the same source and toolchain built with the commands
above, and `iperf3`. The machine running the script needs ssh keys for both hosts,
`rsync`, and the clients built. Clients run on that machine, so end-to-end time
includes its path to both parties; say so when reporting it, and prefer a third
machine. These ports must be open between the machines: `--port-base` to
`--port-base + 4`, and 5201 for `iperf3`.

```sh
"$PY" benchmarks/run_benchmarks.py --build-dir build \
    --out benchmarks/results/<date>-direct-selection-lan --repetitions 10 \
    --station-counts 1,4,16,64,256,1024 --horizons 100,10000,1000000,4294967295 \
    --fixed-stations 64 --fixed-horizon 10000 \
    --host0 user@party0-host --addr0 <party0-ip> \
    --host1 user@party1-host --addr1 <party1-ip> \
    --remote-dir /path/on/hosts/pp-search-run --remote-build-dir /path/on/hosts/build \
    --network-label "<LAN description, including any delay or bandwidth limit already applied>"
```

Only the host owner should apply controlled delay or bandwidth limits, and the
exact settings belong in `--network-label`. For reference, with permission and
root on the host, and with `<dev>` and `<delay>` filled in:

```sh
# Linux, on each party host; remove afterwards with: tc qdisc del dev <dev> root
sudo tc qdisc add dev <dev> root netem delay <delay>ms rate <rate>mbit
```

Shaping one machine's loopback interface is network emulation on a single host. It
must never be reported as a separate-host evaluation.

## Limitations of these measurements

* **Loopback only.** Wide-area or LAN run time cannot be derived by multiplying
  one latency by a round count or by adding a guessed byte count.
* Both parties and all clients shared one machine, which was also running a normal
  desktop session, so CPU contention affects the timings. Byte, round and operation
  counts are unaffected: they were identical in all 10 repetitions.
* Fresh processes charge every run for base OTs and a full comparison-preprocessing
  batch. A long-lived deployment would have a different per-session cost.
* Online figures include MP-SPDZ's on-demand comparison preprocessing; see the
  metric definitions.
