# Two-process MPC benchmark summary

Direct selection. Apple M1 Pro, 10 logical CPUs, macOS-26.6.2-arm64-arm-64bit-Mach-O; Apple clang version 21.0.0 (clang-2100.4.1.1); MP-SPDZ e0ee04674ac7; source e7548315f8e0+uncommitted; network: single-host-loopback: both parties and all clients on one host over 127.0.0.1; no latency or bandwidth shaping applied.

10 repetitions per configuration, fresh party processes per run. Values are mean ± sample standard deviation. Times are max(party0, party1); bytes per direction come from each party's own counters. Total backend MiB sums offline and online traffic in both directions (1 MiB = 2^20 bytes). Online includes MP-SPDZ's on-demand comparison preprocessing; offline is base OTs plus Beaver-triple generation.

| sweep | N | D | placement | correct | matches | M | C | sync steps mul/cmp | online s | offline s | end-to-end s | online MiB p0→p1 / p1→p0 | offline MiB p0→p1 / p1→p0 | total backend MiB | MP-SPDZ rounds (p0) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stations | 1 | 10000 | uniform | yes | 6/10 | 10 | 2 | 5/1 | 0.107 ± 0.008 | 0.032 ± 0.002 | 0.177 ± 0.024 | 0.064 / 0.069 | 0.039 / 0.039 | 0.211 | 44 |
| stations | 4 | 10000 | uniform | yes | 5/10 | 49 | 11 | 11/3 | 0.170 ± 0.004 | 0.031 ± 0.000 | 0.271 ± 0.003 | 0.137 / 0.141 | 0.153 / 0.153 | 0.585 | 80 |
| stations | 16 | 10000 | uniform | yes | 10/10 | 205 | 47 | 17/5 | 0.250 ± 0.015 | 0.034 ± 0.001 | 0.384 ± 0.016 | 0.493 / 0.497 | 0.610 / 0.610 | 2.211 | 116 |
| stations | 64 | 10000 | uniform | yes | 10/10 | 829 | 191 | 23/7 | 0.320 ± 0.004 | 0.041 ± 0.002 | 0.617 ± 0.024 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| stations | 256 | 10000 | uniform | yes | 10/10 | 3325 | 767 | 29/9 | 0.442 ± 0.023 | 0.075 ± 0.004 | 1.402 ± 0.033 | 7.503 / 7.511 | 9.751 / 9.751 | 34.515 | 242 |
| stations | 1024 | 10000 | uniform | yes | 10/10 | 13309 | 3071 | 35/11 | 0.798 ± 0.074 | 0.268 ± 0.047 | 4.618 ± 0.308 | 29.931 / 29.909 | 39.001 / 39.001 | 137.842 | 484 |
| horizon | 64 | 100 | uniform | yes | 10/10 | 829 | 191 | 23/7 | 0.326 ± 0.019 | 0.041 ± 0.001 | 0.624 ± 0.034 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| horizon | 64 | 10000 | uniform | yes | 10/10 | 829 | 191 | 23/7 | 0.325 ± 0.018 | 0.042 ± 0.002 | 0.618 ± 0.037 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| horizon | 64 | 1000000 | uniform | yes | 10/10 | 829 | 191 | 23/7 | 0.326 ± 0.012 | 0.041 ± 0.001 | 0.615 ± 0.025 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| horizon | 64 | 4294967295 | uniform | yes | 10/10 | 829 | 191 | 23/7 | 0.332 ± 0.017 | 0.041 ± 0.002 | 0.638 ± 0.048 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| distribution | 64 | 10000 | uniform | yes | 10/10 | 829 | 191 | 23/7 | 0.329 ± 0.016 | 0.042 ± 0.002 | 0.642 ± 0.047 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| distribution | 64 | 10000 | clustered | yes | 10/10 | 829 | 191 | 23/7 | 0.386 ± 0.056 | 0.046 ± 0.006 | 0.711 ± 0.076 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
| distribution | 64 | 10000 | beyond-horizon | yes | 0/10 | 829 | 191 | 23/7 | 0.344 ± 0.031 | 0.043 ± 0.002 | 0.667 ± 0.045 | 1.905 / 1.917 | 2.438 / 2.438 | 8.698 | 168 |
