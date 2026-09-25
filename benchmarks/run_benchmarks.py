#!/usr/bin/env python3
"""Two-process MPC benchmarks for the nearest eligible station search.

Every repetition starts two fresh pp_party processes (so MP-SPDZ's batched
preprocessing is attributed to the session that generated it), then runs one
session with a separate coordinator, requester and station-client process
over TLS on the loopback interface. Reported numbers come from the parties'
own per-session statistics (MP-SPDZ byte/round counters and transport
counters), not from a network model.

Sweeps (each varies one parameter; both search modes):
  stations      N in --station-counts at fixed horizon and uniform placement
  horizon       D in --horizons at fixed N and uniform placement
  distribution  uniform / clustered / beyond-horizon at fixed N and D

Outputs, in --out (default benchmarks/results/<timestamp>):
  runs.csv      one row per repetition
  summary.csv   mean and standard deviation per configuration
  summary.md    human-readable summary table
  environment.json
"""

import argparse
import csv
import datetime
import json
import math
import os
import pathlib
import platform
import random
import statistics
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests" / "integration"))
from harness import Deployment, Paths, add_path_arguments, plaintext_oracle, provision_pki  # noqa: E402

INT32_MIN, INT32_MAX = -2**31, 2**31 - 1


def clamp32(value):
    return max(INT32_MIN, min(INT32_MAX, value))


def make_stations(rng, count, horizon, distribution, requester):
    """Public benchmark placement (deterministic seed; not secret material)."""
    ax, ay = requester
    ids = rng.sample(range(1, 100000), count)
    stations = []
    for station_id in ids:
        if distribution == "uniform":
            span = max(1, horizon)
            x, y = ax + rng.randint(-span, span), ay + rng.randint(-span, span)
            radius = rng.randint(max(0, span // 4), span)
        elif distribution == "clustered":
            span = max(1, horizon // 10)
            x, y = ax + rng.randint(-span, span), ay + rng.randint(-span, span)
            radius = max(1, horizon)
        elif distribution == "beyond-horizon":
            angle = rng.random() * 2 * math.pi
            distance = horizon + 1 + rng.randint(0, max(1, horizon))
            x = ax + int(math.ceil(distance * math.cos(angle)))
            y = ay + int(math.ceil(distance * math.sin(angle)))
            radius = 2 * horizon + 2
        else:
            raise ValueError(distribution)
        stations.append((station_id, clamp32(x), clamp32(y), min(radius, 2**32 - 1)))
    return stations


def environment(paths):
    def run(command):
        try:
            return subprocess.run(command, capture_output=True, text=True, check=False).stdout.strip()
        except FileNotFoundError:
            return ""
    info = {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": run(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor(),
        "logical_cpus": os.cpu_count(),
        "memory_bytes": run(["sysctl", "-n", "hw.memsize"]),
        "compiler": run(["c++", "--version"]).splitlines()[0] if run(["c++", "--version"]) else "",
        "mpspdz_commit": run(["git", "-C", str(paths.mpspdz), "rev-parse", "HEAD"]),
        "protocol": "MP-SPDZ semi2k, additive sharing over Z_2^128, two parties",
        "security_model": "semi-honest, non-colluding computation parties, at most one corrupted",
        "network": "loopback (127.0.0.1); no latency or bandwidth shaping applied",
        "transport": "TLS 1.3 (OpenSSL) for inputs/outputs/control; MP-SPDZ CryptoPlayer TLS between parties",
    }
    return info


def run_one(paths, work, pki, stations, horizon, mode, requester, seed_label):
    stations_file = work / f"stations-{seed_label}.csv"
    stations_file.write_text("".join(f"{s[0]},{s[1]},{s[2]},{s[3]}\n" for s in stations))
    deployment = Deployment(paths, work / f"run-{seed_label}", pki=pki)
    deployment.start()
    try:
        result = deployment.run_session(("bench", *requester), stations, horizon, mode=mode,
                                        timeout_ms=600000, batch_stations_file=str(stations_file))
        stats = [deployment.stats_lines(0), deployment.stats_lines(1)]
    finally:
        deployment.stop()
    expected = plaintext_oracle(requester, stations, horizon)
    coordinator = result["coordinator"]
    correct = (coordinator.get("status") == "ok" and
               (coordinator.get("match") is False if expected is None
                else coordinator.get("station_id") == expected))
    batch = result["stations"]["batch"]
    if expected is not None:
        correct &= batch.get("selected") == [expected] and \
            batch.get("outputs", {}).get(str(expected)) == {"x": requester[0], "y": requester[1]}
    correct &= batch.get("output_share_frames_to_nonselected", 1) == 0
    if not (stats[0] and stats[1]):
        raise RuntimeError(f"no party statistics for run {seed_label}: {result}")
    s0, s1 = stats[0][-1], stats[1][-1]
    empty = {"seconds": 0, "bytes_sent": 0, "rounds": 0}
    row = {
        "correct": correct,
        "end_to_end_s": result["seconds"],
        "offline_s": max(s0.get("offline", empty)["seconds"], s1.get("offline", empty)["seconds"]),
        "offline_bytes_p0_to_p1": s0.get("offline", empty)["bytes_sent"],
        "offline_bytes_p1_to_p0": s1.get("offline", empty)["bytes_sent"],
        "offline_rounds_p0": s0.get("offline", empty)["rounds"],
        "online_s": max(s0.get("online", empty)["seconds"], s1.get("online", empty)["seconds"]),
        "online_bytes_p0_to_p1": s0.get("online", empty)["bytes_sent"],
        "online_bytes_p1_to_p0": s1.get("online", empty)["bytes_sent"],
        "online_rounds_p0": s0.get("online", empty)["rounds"],
        "online_rounds_p1": s1.get("online", empty)["rounds"],
        "input_bytes_to_p0": s0["transport"]["inputs"]["bytes_received"],
        "input_bytes_to_p1": s1["transport"]["inputs"]["bytes_received"],
        "output_bytes_from_p0": s0["transport"]["outputs"]["bytes_sent"],
        "output_bytes_from_p1": s1["transport"]["outputs"]["bytes_sent"],
        "control_bytes_p0_to_p1": s0["transport"]["peer_control"]["bytes_sent"],
        "control_bytes_p1_to_p0": s1["transport"]["peer_control"]["bytes_sent"],
        "input_phase_s": max(s0["input_phase_s"], s1["input_phase_s"]),
        "triples": s0.get("triples_consumed", 0),
        "comparisons": s0.get("plan", {}).get("comparisons", 0),
        "multiply_steps": s0.get("plan", {}).get("multiply_steps", 0),
        "compare_steps": s0.get("plan", {}).get("compare_steps", 0),
        "halve_steps": s0.get("plan", {}).get("halve_steps", 0),
        "match": coordinator.get("match"),
    }
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_path_arguments(parser)
    parser.add_argument("--out", default=None)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--station-counts", default="1,4,16,64,256")
    parser.add_argument("--horizons", default="100,10000,1000000,4294967295")
    parser.add_argument("--fixed-stations", type=int, default=64)
    parser.add_argument("--fixed-horizon", type=int, default=10000)
    parser.add_argument("--modes", default="binary,argmin")
    parser.add_argument("--sweeps", default="stations,horizon,distribution")
    args = parser.parse_args()

    paths = Paths(args.build_dir, args.source_dir, args.mpspdz_dir)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = pathlib.Path(args.out or REPO / "benchmarks" / "results" / stamp)
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work"
    work.mkdir(exist_ok=True)

    modes = args.modes.split(",")
    configs = []
    sweeps = args.sweeps.split(",")
    if "stations" in sweeps:
        for n in map(int, args.station_counts.split(",")):
            configs.append(("stations", n, args.fixed_horizon, "uniform"))
    if "horizon" in sweeps:
        for d in map(int, args.horizons.split(",")):
            configs.append(("horizon", args.fixed_stations, d, "uniform"))
    if "distribution" in sweeps:
        for distribution in ("uniform", "clustered", "beyond-horizon"):
            configs.append(("distribution", args.fixed_stations, args.fixed_horizon, distribution))

    # One PKI with certificates for every station ID any run may use.
    rng_ids = set()
    plans = []
    for sweep, n, horizon, distribution in configs:
        for rep in range(args.repetitions):
            rng = random.Random(f"{sweep}-{n}-{horizon}-{distribution}-{rep}")
            requester = (rng.randint(-1000, 1000), rng.randint(-1000, 1000))
            stations = make_stations(rng, n, horizon, distribution, requester)
            rng_ids.update(s[0] for s in stations)
            plans.append((sweep, n, horizon, distribution, rep, requester, stations))
    pki = work / "pki"
    print(f"provisioning {len(rng_ids)} station certificates ...", flush=True)
    provision_pki(paths, pki, sorted(rng_ids), ["bench"])

    env = environment(paths)
    env.update({"repetitions": args.repetitions, "configs": len(configs), "modes": modes})
    (out / "environment.json").write_text(json.dumps(env, indent=2))

    rows = []
    fields = None
    with open(out / "runs.csv", "w", newline="") as handle:
        for sweep, n, horizon, distribution, rep, requester, stations in plans:
            for mode in modes:
                label = f"{sweep}-{n}-{horizon}-{distribution}-{mode}-{rep}"
                started = time.time()
                row = {"sweep": sweep, "stations": n, "horizon": horizon,
                       "distribution": distribution, "mode": mode, "repetition": rep}
                row.update(run_one(paths, work, pki, stations, horizon, mode, requester, label))
                rows.append(row)
                if fields is None:
                    fields = list(row.keys())
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                writer.writerow(row)
                handle.flush()
                print(f"{label}: correct={row['correct']} online={row['online_s']:.3f}s "
                      f"offline={row['offline_s']:.3f}s "
                      f"bytes p0->p1={row['online_bytes_p0_to_p1'] + row['offline_bytes_p0_to_p1']} "
                      f"({time.time() - started:.1f}s)", flush=True)

    # Aggregate.
    keys = ["sweep", "stations", "horizon", "distribution", "mode"]
    metrics = ["end_to_end_s", "offline_s", "online_s", "offline_bytes_p0_to_p1",
               "offline_bytes_p1_to_p0", "online_bytes_p0_to_p1", "online_bytes_p1_to_p0",
               "online_rounds_p0", "input_bytes_to_p0", "input_bytes_to_p1",
               "output_bytes_from_p0", "output_bytes_from_p1"]
    groups = {}
    for row in rows:
        groups.setdefault(tuple(row[k] for k in keys), []).append(row)
    summary = []
    for key, group in groups.items():
        entry = dict(zip(keys, key))
        entry["runs"] = len(group)
        entry["all_correct"] = all(r["correct"] for r in group)
        for fixed in ("triples", "comparisons", "multiply_steps", "compare_steps", "halve_steps"):
            entry[fixed] = group[0][fixed]
        for metric in metrics:
            values = [r[metric] for r in group]
            entry[f"{metric}_mean"] = statistics.fmean(values)
            entry[f"{metric}_stdev"] = statistics.stdev(values) if len(values) > 1 else 0.0
        summary.append(entry)
    with open(out / "summary.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)

    def mib(value):
        return value / 2**20

    lines = ["# Two-process MPC benchmark summary", "",
             f"Environment: {env['cpu']}, {env['logical_cpus']} logical CPUs, {env['platform']}; "
             f"{env['compiler']}; MP-SPDZ {env['mpspdz_commit'][:12]}; {env['network']}.", "",
             f"{args.repetitions} repetitions per configuration, fresh party processes per run. "
             "Times are max(party0, party1); bytes are per direction from each party's own "
             "counters. Online includes MP-SPDZ's on-demand comparison preprocessing; offline is "
             "base OTs plus Beaver-triple generation.", "",
             "| sweep | N | D | placement | mode | correct | online s (mean ± sd) | offline s | "
             "online MiB p0→p1 / p1→p0 | offline MiB p0→p1 / p1→p0 | MP-SPDZ rounds (p0) | "
             "sync steps mul/cmp/half | end-to-end s |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for e in summary:
        lines.append(
            f"| {e['sweep']} | {e['stations']} | {e['horizon']} | {e['distribution']} | {e['mode']} | "
            f"{'yes' if e['all_correct'] else 'NO'} | {e['online_s_mean']:.3f} ± {e['online_s_stdev']:.3f} | "
            f"{e['offline_s_mean']:.3f} ± {e['offline_s_stdev']:.3f} | "
            f"{mib(e['online_bytes_p0_to_p1_mean']):.2f} / {mib(e['online_bytes_p1_to_p0_mean']):.2f} | "
            f"{mib(e['offline_bytes_p0_to_p1_mean']):.2f} / {mib(e['offline_bytes_p1_to_p0_mean']):.2f} | "
            f"{e['online_rounds_p0_mean']:.0f} | {e['multiply_steps']}/{e['compare_steps']}/{e['halve_steps']} | "
            f"{e['end_to_end_s_mean']:.2f} ± {e['end_to_end_s_stdev']:.2f} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    incorrect = [r for r in rows if not r["correct"]]
    print(f"\n{len(rows) - len(incorrect)}/{len(rows)} runs correct; results in {out}")
    return 1 if incorrect else 0


if __name__ == "__main__":
    sys.exit(main())
