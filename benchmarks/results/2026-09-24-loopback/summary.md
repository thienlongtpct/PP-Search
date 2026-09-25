# Two-process MPC benchmark summary

Environment: Apple M1 Pro, 10 logical CPUs, macOS-26.6.2-arm64-arm-64bit-Mach-O; Apple clang version 21.0.0 (clang-2100.3.34.2); MP-SPDZ e0ee04674ac7; loopback (127.0.0.1); no latency or bandwidth shaping applied.

3 repetitions per configuration, fresh party processes per run. Times are max(party0, party1); bytes are per direction from each party's own counters. Online includes MP-SPDZ's on-demand comparison preprocessing; offline is base OTs plus Beaver-triple generation.

| sweep | N | D | placement | mode | correct | online s (mean ± sd) | offline s | online MiB p0→p1 / p1→p0 | offline MiB p0→p1 / p1→p0 | MP-SPDZ rounds (p0) | sync steps mul/cmp/half | end-to-end s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stations | 1 | 10000 | uniform | binary | yes | 0.844 ± 0.122 | 0.033 ± 0.001 | 0.26 / 0.26 | 0.28 / 0.28 | 519 | 61/16/14 | 0.91 ± 0.13 |
| stations | 1 | 10000 | uniform | argmin | yes | 0.059 ± 0.001 | 0.031 ± 0.000 | 0.01 / 0.02 | 0.02 / 0.02 | 26 | 3/1/0 | 0.11 ± 0.00 |
| stations | 4 | 10000 | uniform | binary | yes | 0.841 ± 0.017 | 0.033 ± 0.000 | 0.42 / 0.43 | 0.61 / 0.61 | 586 | 95/18/14 | 0.93 ± 0.03 |
| stations | 4 | 10000 | uniform | argmin | yes | 0.109 ± 0.002 | 0.032 ± 0.001 | 0.04 / 0.04 | 0.10 / 0.10 | 62 | 9/3/0 | 0.22 ± 0.00 |
| stations | 16 | 10000 | uniform | binary | yes | 0.945 ± 0.041 | 0.044 ± 0.001 | 1.04 / 1.06 | 1.95 / 1.95 | 659 | 129/20/14 | 1.09 ± 0.04 |
| stations | 16 | 10000 | uniform | argmin | yes | 0.160 ± 0.002 | 0.032 ± 0.000 | 0.11 / 0.11 | 0.42 / 0.42 | 98 | 15/5/0 | 0.27 ± 0.00 |
| stations | 64 | 10000 | uniform | binary | yes | 1.030 ± 0.047 | 0.067 ± 0.007 | 3.49 / 3.56 | 7.29 / 7.29 | 759 | 163/22/14 | 1.35 ± 0.04 |
| stations | 64 | 10000 | uniform | argmin | yes | 0.218 ± 0.010 | 0.038 ± 0.001 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.52 ± 0.03 |
| stations | 256 | 10000 | uniform | binary | yes | 1.217 ± 0.058 | 0.230 ± 0.046 | 13.32 / 13.36 | 28.66 / 28.66 | 904 | 197/24/14 | 2.39 ± 0.04 |
| stations | 256 | 10000 | uniform | argmin | yes | 0.283 ± 0.023 | 0.059 ± 0.000 | 1.31 / 1.32 | 6.75 / 6.75 | 181 | 27/9/0 | 1.22 ± 0.01 |
| stations | 1024 | 10000 | uniform | binary | yes | 1.730 ± 0.128 | 0.929 ± 0.089 | 52.69 / 52.55 | 114.16 / 114.16 | 1344 | 231/26/14 | 6.26 ± 0.33 |
| stations | 1024 | 10000 | uniform | argmin | yes | 0.362 ± 0.011 | 0.186 ± 0.069 | 5.14 / 5.14 | 27.00 / 27.00 | 253 | 33/11/0 | 4.00 ± 0.03 |
| horizon | 64 | 100 | uniform | binary | yes | 0.606 ± 0.005 | 0.050 ± 0.002 | 1.97 / 2.02 | 4.58 / 4.58 | 458 | 93/15/7 | 0.91 ± 0.01 |
| horizon | 64 | 100 | uniform | argmin | yes | 0.212 ± 0.002 | 0.037 ± 0.000 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.48 ± 0.00 |
| horizon | 64 | 10000 | uniform | binary | yes | 0.996 ± 0.018 | 0.066 ± 0.006 | 3.49 / 3.56 | 7.29 / 7.29 | 759 | 163/22/14 | 1.31 ± 0.03 |
| horizon | 64 | 10000 | uniform | argmin | yes | 0.223 ± 0.015 | 0.039 ± 0.001 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.54 ± 0.05 |
| horizon | 64 | 1000000 | uniform | binary | yes | 1.295 ± 0.018 | 0.072 ± 0.001 | 4.79 / 4.89 | 9.61 / 9.61 | 1017 | 223/28/20 | 1.62 ± 0.03 |
| horizon | 64 | 1000000 | uniform | argmin | yes | 0.216 ± 0.006 | 0.038 ± 0.001 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.52 ± 0.06 |
| horizon | 64 | 4294967295 | uniform | binary | yes | 1.991 ± 0.033 | 0.095 ± 0.004 | 7.59 / 7.75 | 14.64 / 14.64 | 1571 | 353/41/33 | 2.35 ± 0.05 |
| horizon | 64 | 4294967295 | uniform | argmin | yes | 0.217 ± 0.007 | 0.038 ± 0.001 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.54 ± 0.05 |
| distribution | 64 | 10000 | uniform | binary | yes | 0.976 ± 0.020 | 0.062 ± 0.000 | 3.49 / 3.56 | 7.29 / 7.29 | 759 | 163/22/14 | 1.31 ± 0.03 |
| distribution | 64 | 10000 | uniform | argmin | yes | 0.221 ± 0.010 | 0.039 ± 0.003 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.52 ± 0.06 |
| distribution | 64 | 10000 | clustered | binary | yes | 1.017 ± 0.005 | 0.062 ± 0.000 | 3.49 / 3.56 | 7.29 / 7.29 | 759 | 163/22/14 | 1.34 ± 0.04 |
| distribution | 64 | 10000 | clustered | argmin | yes | 0.219 ± 0.004 | 0.038 ± 0.000 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.52 ± 0.03 |
| distribution | 64 | 10000 | beyond-horizon | binary | yes | 0.990 ± 0.022 | 0.062 ± 0.000 | 3.49 / 3.56 | 7.29 / 7.29 | 759 | 163/22/14 | 1.30 ± 0.03 |
| distribution | 64 | 10000 | beyond-horizon | argmin | yes | 0.224 ± 0.018 | 0.040 ± 0.003 | 0.35 / 0.36 | 1.69 / 1.69 | 137 | 21/7/0 | 0.52 ± 0.04 |
