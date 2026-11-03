#!/usr/bin/env python3
"""Two-process MPC benchmarks for the direct-selection nearest station search.

Every repetition starts two fresh pp_party processes (so MP-SPDZ's batched
preprocessing is attributed to the session that generated it), then runs one
session with a separate coordinator, requester and station-client process
over TLS. Reported numbers come from the parties' own per-session statistics
(MP-SPDZ byte/round counters and transport counters), not from a network model.

By default both parties share this host over loopback. With --host0/--host1,
each party runs on its own host over ssh; the script measures the path between
them and never changes network settings. docs/BENCHMARKS.md defines every metric.

Sweeps (each varies one parameter):
  stations      N in --station-counts at fixed horizon and uniform placement
  horizon       D in --horizons at fixed N and uniform placement
  distribution  uniform / clustered / beyond-horizon at fixed N and D

Outputs, in --out (default benchmarks/results/<timestamp>):
  runs.csv         one row per completed repetition
  attempts.jsonl   every attempt in order, including failed ones
  summary.csv      statistics per configuration
  summary.md       human-readable summary table
  config.json      command line, configurations and the seed of every run
  environment.json software revision, hardware, toolchain, network
  source.diff      uncommitted changes to the tracked source at run time
  work/            raw party logs, per-session statistics and station inputs
"""

import argparse
import csv
import datetime
import hashlib
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
from harness import (Deployment, Paths, SeparateHostDeployment, add_path_arguments,  # noqa: E402
                     plaintext_oracle, provision_pki)

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


def run_text(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False).stdout.strip()
    except FileNotFoundError:
        return ""


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def software_revision(paths, out):
    """HEAD alone does not identify an uncommitted tree, so keep the diff too."""
    source = str(paths.source)
    diff = run_text(["git", "-C", source, "diff", "HEAD", "--binary"])
    (out / "source.diff").write_text(diff + "\n" if diff else "")
    untracked = run_text(["git", "-C", source, "ls-files", "--others", "--exclude-standard",
                          ":!archive"]).splitlines()
    return {
        "git_head": run_text(["git", "-C", source, "rev-parse", "HEAD"]),
        "git_dirty": bool(diff or untracked),
        "source_diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "untracked_files": untracked,
        "run_benchmarks_sha256": sha256(__file__),
        "harness_sha256": sha256(REPO / "tests" / "integration" / "harness.py"),
        "pp_party_sha256": sha256(paths.party),
        "pp_client_sha256": sha256(paths.client),
        "pp_ops_bytecode_sha256": sha256(paths.programs / "Bytecode" / "pp_ops-0.bc"),
    }


def build_settings(paths):
    wanted = ("CMAKE_BUILD_TYPE", "CMAKE_CXX_FLAGS", "CMAKE_CXX_FLAGS_RELEASE",
              "CMAKE_EXE_LINKER_FLAGS", "OPENSSL_ROOT_DIR")
    settings = {}
    cache = paths.build / "CMakeCache.txt"
    for line in cache.read_text().splitlines() if cache.exists() else []:
        key = line.split(":", 1)[0]
        if key in wanted:
            settings[key] = line.split("=", 1)[1]
    return settings


def environment(paths, out, args, network):
    def sysctl(name):
        return run_text(["sysctl", "-n", name])
    return {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": sys.argv,
        "working_directory": os.getcwd(),
        "software": software_revision(paths, out),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "hardware_model": sysctl("hw.model"),
        "cpu": sysctl("machdep.cpu.brand_string") or platform.processor(),
        "logical_cpus": os.cpu_count(),
        "performance_cores": sysctl("hw.perflevel0.physicalcpu"),
        "efficiency_cores": sysctl("hw.perflevel1.physicalcpu"),
        "memory_bytes": sysctl("hw.memsize"),
        "power_source": (run_text(["pmset", "-g", "batt"]).splitlines() or [""])[0],
        "load_average_at_start": os.getloadavg(),
        "compiler": (run_text(["c++", "--version"]).splitlines() or [""])[0],
        "python": platform.python_version(),
        "build_settings": build_settings(paths),
        "linked_libraries": run_text(["otool", "-L", str(paths.party)]).splitlines()[1:],
        "mpspdz_commit": run_text(["git", "-C", str(paths.mpspdz), "rev-parse", "HEAD"]),
        "mpspdz_patches": run_text(["git", "-C", str(paths.mpspdz), "status", "--short",
                                    "--untracked-files=no", "--ignore-submodules=all"]).splitlines(),
        "protocol": "MP-SPDZ semi2k, additive sharing over Z_2^128, two parties",
        "security_model": "semi-honest, non-colluding computation parties, at most one corrupted",
        "search": "direct selection: tournament validity w_i = v_i",
        "transport": "TLS 1.3 (OpenSSL) for inputs/outputs/control; MP-SPDZ CryptoPlayer TLS between parties",
        "repetitions": args.repetitions,
        "network": network,
    }


# ---- separate hosts ---------------------------------------------------------

def ssh(target, command):
    return ["ssh", "-o", "BatchMode=yes", target, command]


def path_measurements(target, peer_address, seconds):
    """RTT and TCP throughput from `target` to `peer_address`. Read-only."""
    result = {"ping": run_text(ssh(target, f"ping -c 50 -i 0.2 {peer_address}")).splitlines()[-2:],
              "iperf3": None}
    client = run_text(ssh(target, f"iperf3 -c {peer_address} -t {seconds} -J"))
    reverse = run_text(ssh(target, f"iperf3 -c {peer_address} -t {seconds} -R -J"))
    for label, text in (("forward", client), ("reverse", reverse)):
        try:
            summary = json.loads(text)["end"]
            result[f"iperf3_{label}_received_bits_per_second"] = \
                summary["sum_received"]["bits_per_second"]
            result["iperf3"] = "measured"
        except (ValueError, KeyError):
            result[f"iperf3_{label}_received_bits_per_second"] = None
    return result


def measure_network(args):
    (target0, target1), (address0, address1) = (args.host0, args.host1), (args.addr0, args.addr1)
    result = {"host_descriptions": {}}
    for label, target in (("host0", target0), ("host1", target1)):
        result["host_descriptions"][label] = run_text(ssh(
            target, "uname -a; (sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>/dev/null "
                    "|| (lscpu; free -b)); hostname"))
    if result["host_descriptions"]["host0"].splitlines()[-1:] == \
            result["host_descriptions"]["host1"].splitlines()[-1:]:
        raise SystemExit("--host0 and --host1 report the same host name: not a separate-host run")
    server = subprocess.Popen(ssh(target1, "iperf3 -s -1"), stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    time.sleep(1)
    result["host0_to_host1"] = path_measurements(target0, address1, args.iperf_seconds)
    server.terminate()
    return result


def describe_network(args):
    if not args.host0:
        return {"kind": "single-host-loopback",
                "description": "both parties and all clients on one host over 127.0.0.1; "
                               "no latency or bandwidth shaping applied"}
    if "local" in (args.host0, args.host1):
        return {"kind": "local-plumbing-test",
                "description": "party launcher exercised on one host; NOT a separate-host evaluation"}
    return {"kind": "separate-hosts", "description": args.network_label,
            "host0": args.host0, "host1": args.host1, "addr0": args.addr0, "addr1": args.addr1,
            "before": measure_network(args)}


def party_deployment(args, paths, directory, pki):
    if not args.host0:
        return Deployment(paths, directory, pki=pki)
    deployment = SeparateHostDeployment(
        paths, directory, pki, (args.host0, args.host1), (args.addr0, args.addr1),
        (f"{args.remote_dir}/p0", f"{args.remote_dir}/p1"),
        (args.remote_build_dir, args.remote_build_dir),
        args.port_base)
    return deployment.install()


# ---- one repetition ---------------------------------------------------------

def run_one(args, paths, work, pki, stations, horizon, requester, seed_label):
    stations_file = work / f"stations-{seed_label}.csv"
    stations_file.write_text("".join(f"{s[0]},{s[1]},{s[2]},{s[3]}\n" for s in stations))
    deployment = party_deployment(args, paths, work / f"run-{seed_label}", pki)
    deployment.start()
    try:
        result = deployment.run_session(("bench", *requester), stations, horizon,
                                        timeout_ms=600000, batch_stations_file=str(stations_file))
    finally:
        deployment.stop()
    stats = [deployment.stats_lines(0), deployment.stats_lines(1)]
    (work / f"run-{seed_label}" / "clients.json").write_text(json.dumps(result, indent=1))
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
    if s0.get("operations") != s1.get("operations") or s0.get("operations") != s0.get("plan"):
        raise RuntimeError(f"executed operations differ from the plan in {seed_label}")
    empty = {"seconds": 0, "bytes_sent": 0, "rounds": 0}
    return {
        "correct": correct,
        "expected_match": expected is not None,
        "match": coordinator.get("match"),
        "eligible_stations": sum(
            1 for _, x, y, r in stations
            if (requester[0] - x) ** 2 + (requester[1] - y) ** 2 <= min(r, horizon) ** 2),
        "end_to_end_s": result["seconds"],
        "mpc_connect_s": max(s0["mpc_connect"]["seconds"], s1["mpc_connect"]["seconds"]),
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
        "output_phase_s": max(s0["output_phase_s"], s1["output_phase_s"]),
        "triples": s0.get("triples_consumed", 0),
        # Direct selection: these depend only on N, never on the data or D.
        "multiplications": s0["operations"]["multiplications"],
        "comparisons": s0["operations"]["comparisons"],
        "range_checks": s0["operations"]["range_checks"],
        "multiply_steps": s0["operations"]["multiply_steps"],
        "compare_steps": s0["operations"]["compare_steps"],
        "reveal_steps": s0["operations"]["reveal_steps"],
    }


# Derived quantities and fixed columns of the summary.
FIXED = ("triples", "multiplications", "comparisons", "range_checks", "multiply_steps", "compare_steps",
         "reveal_steps")
METRICS = ("end_to_end_s", "mpc_connect_s", "offline_s", "online_s", "input_phase_s",
           "output_phase_s", "offline_bytes_p0_to_p1", "offline_bytes_p1_to_p0",
           "online_bytes_p0_to_p1", "online_bytes_p1_to_p0", "online_rounds_p0",
           "input_bytes_to_p0", "input_bytes_to_p1", "output_bytes_from_p0",
           "output_bytes_from_p1", "control_bytes_p0_to_p1", "control_bytes_p1_to_p0",
           "backend_bytes_both_directions")


def summarize(rows):
    keys = ["sweep", "stations", "horizon", "distribution"]
    groups = {}
    for row in rows:
        groups.setdefault(tuple(row[k] for k in keys), []).append(row)
    summary = []
    by_n = {}
    for key, group in groups.items():
        entry = dict(zip(keys, key))
        entry["runs"] = len(group)
        entry["all_correct"] = all(r["correct"] for r in group)
        entry["matches"] = sum(1 for r in group if r["match"])
        for fixed in FIXED:
            values = {r[fixed] for r in group}
            if len(values) != 1:
                raise SystemExit(f"{fixed} varies within {key}: the search is not oblivious")
            entry[fixed] = values.pop()
        for metric in METRICS:
            values = [r[metric] for r in group]
            entry[f"{metric}_mean"] = statistics.fmean(values)
            entry[f"{metric}_stdev"] = statistics.stdev(values) if len(values) > 1 else 0.0
            entry[f"{metric}_median"] = statistics.median(values)
            entry[f"{metric}_min"] = min(values)
            entry[f"{metric}_max"] = max(values)
        summary.append(entry)
        by_n.setdefault(entry["stations"], []).append(tuple(entry[f] for f in FIXED))
    for n, fixed_values in by_n.items():
        if len(set(fixed_values)) != 1:
            raise SystemExit(f"operation counts differ across horizons or placements at N = {n}")
        if n >= 1 and fixed_values[0][1:4] != (13 * n - 3, 3 * n - 1, 3 * n + 2):
            raise SystemExit(f"operation counts at N = {n} are not M = 13N - 3, C = 3N - 1, K = 3N + 2")
    return summary


def write_summary(out, env, summary, repetitions):
    with open(out / "summary.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)

    def mib(value):
        return value / 2**20

    lines = ["# Two-process MPC benchmark summary", "",
             f"Direct selection. {env['cpu']}, {env['logical_cpus']} logical CPUs, {env['platform']}; "
             f"{env['compiler']}; MP-SPDZ {env['mpspdz_commit'][:12]}; "
             f"source {env['software']['git_head'][:12]}{'+uncommitted' if env['software']['git_dirty'] else ''}; "
             f"network: {env['network']['kind']}: {env['network']['description']}.", "",
             f"{repetitions} repetitions per configuration, fresh party processes per run. Values are "
             "mean ± sample standard deviation. Times are max(party0, party1); bytes per direction "
             "come from each party's own counters. Total backend MiB sums offline and online traffic "
             "in both directions (1 MiB = 2^20 bytes). Online includes MP-SPDZ's on-demand comparison "
             "preprocessing; offline is base OTs plus Beaver-triple generation.", "",
             "| sweep | N | D | placement | correct | matches | M | C | sync steps mul/cmp | "
             "online s | offline s | end-to-end s | online MiB p0→p1 / p1→p0 | "
             "offline MiB p0→p1 / p1→p0 | total backend MiB | MP-SPDZ rounds (p0) |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for e in summary:
        lines.append(
            f"| {e['sweep']} | {e['stations']} | {e['horizon']} | {e['distribution']} | "
            f"{'yes' if e['all_correct'] else 'NO'} | {e['matches']}/{e['runs']} | "
            f"{e['multiplications']} | {e['comparisons']} | {e['multiply_steps']}/{e['compare_steps']} | "
            f"{e['online_s_mean']:.3f} ± {e['online_s_stdev']:.3f} | "
            f"{e['offline_s_mean']:.3f} ± {e['offline_s_stdev']:.3f} | "
            f"{e['end_to_end_s_mean']:.3f} ± {e['end_to_end_s_stdev']:.3f} | "
            f"{mib(e['online_bytes_p0_to_p1_mean']):.3f} / {mib(e['online_bytes_p1_to_p0_mean']):.3f} | "
            f"{mib(e['offline_bytes_p0_to_p1_mean']):.3f} / {mib(e['offline_bytes_p1_to_p0_mean']):.3f} | "
            f"{mib(e['backend_bytes_both_directions_mean']):.3f} | {e['online_rounds_p0_mean']:.0f} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_path_arguments(parser)
    parser.add_argument("--out", default=None)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--station-counts", default="1,4,16,64,256")
    parser.add_argument("--horizons", default="100,10000,1000000,4294967295")
    parser.add_argument("--fixed-stations", type=int, default=64)
    parser.add_argument("--fixed-horizon", type=int, default=10000)
    parser.add_argument("--sweeps", default="stations,horizon,distribution")
    hosts = parser.add_argument_group("one computation party per host")
    hosts.add_argument("--host0", help="ssh target of party 0, or 'local' for a plumbing test")
    hosts.add_argument("--host1", help="ssh target of party 1, or 'local' for a plumbing test")
    hosts.add_argument("--addr0", help="IPv4 address of party 0 reachable from party 1 and the clients")
    hosts.add_argument("--addr1", help="IPv4 address of party 1 reachable from party 0 and the clients")
    hosts.add_argument("--remote-dir", help="directory on each host for its party's material")
    hosts.add_argument("--remote-build-dir", help="build directory with pp_party on each host")
    hosts.add_argument("--port-base", type=int, default=15700, help="uses this port and the next four")
    hosts.add_argument("--network-label", help="how the path is set up, including any delay or "
                                               "bandwidth limit already applied by its administrator")
    hosts.add_argument("--iperf-seconds", type=int, default=10)
    args = parser.parse_args()
    if bool(args.host0) != bool(args.host1):
        parser.error("--host0 and --host1 go together")
    if args.host0:
        for name in ("addr0", "addr1", "remote_dir", "remote_build_dir", "network_label"):
            if not getattr(args, name):
                parser.error(f"separate-host runs need --{name.replace('_', '-')}")

    paths = Paths(args.build_dir, args.source_dir, args.mpspdz_dir)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = pathlib.Path(args.out or REPO / "benchmarks" / "results" / stamp)
    if (out / "runs.csv").exists():
        raise SystemExit(f"{out} already holds results; historical data is never overwritten")
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work"
    work.mkdir(exist_ok=True)

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
            seed = f"{sweep}-{n}-{horizon}-{distribution}-{rep}"
            rng = random.Random(seed)
            requester = (rng.randint(-1000, 1000), rng.randint(-1000, 1000))
            stations = make_stations(rng, n, horizon, distribution, requester)
            rng_ids.update(s[0] for s in stations)
            plans.append((sweep, n, horizon, distribution, rep, seed, requester, stations))
    pki = work / "pki"
    print(f"provisioning {len(rng_ids)} station certificates ...", flush=True)
    provision_pki(paths, pki, sorted(rng_ids), ["bench"])

    env = environment(paths, out, args, describe_network(args))
    (out / "environment.json").write_text(json.dumps(env, indent=2))
    (out / "config.json").write_text(json.dumps({
        "command": sys.argv, "repetitions": args.repetitions, "configurations": configs,
        "seed_scheme": "random.Random(f'{sweep}-{n}-{horizon}-{distribution}-{repetition}'), "
                       "public benchmark placement only; shares use the CSPRNG",
        "runs": [{"seed": p[5], "requester": p[6], "stations_file": f"work/stations-{p[5]}.csv"}
                 for p in plans]}, indent=1))

    rows = []
    fields = None
    failures = 0
    with open(out / "runs.csv", "w", newline="") as handle, open(out / "attempts.jsonl", "w") as attempts:
        for sweep, n, horizon, distribution, rep, seed, requester, stations in plans:
            started = time.time()
            row = {"sweep": sweep, "stations": n, "horizon": horizon, "distribution": distribution,
                   "repetition": rep, "seed": seed,
                   "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
            try:
                row.update(run_one(args, paths, work, pki, stations, horizon, requester, seed))
            except Exception as error:  # noqa: BLE001 - recorded; never silently rerun
                failures += 1
                attempts.write(json.dumps({"seed": seed, "started_at": row["started_at"],
                                           "status": "failed", "error": str(error)}) + "\n")
                attempts.flush()
                print(f"{seed}: FAILED {error}", flush=True)
                continue
            row["backend_bytes_both_directions"] = sum(
                row[k] for k in ("offline_bytes_p0_to_p1", "offline_bytes_p1_to_p0",
                                 "online_bytes_p0_to_p1", "online_bytes_p1_to_p0"))
            rows.append(row)
            attempts.write(json.dumps({"seed": seed, "started_at": row["started_at"],
                                       "status": "completed", "correct": row["correct"]}) + "\n")
            attempts.flush()
            if fields is None:
                fields = list(row.keys())
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
            writer.writerow(row)
            handle.flush()
            print(f"{seed}: correct={row['correct']} online={row['online_s']:.3f}s "
                  f"offline={row['offline_s']:.3f}s "
                  f"bytes p0->p1={row['online_bytes_p0_to_p1'] + row['offline_bytes_p0_to_p1']} "
                  f"({time.time() - started:.1f}s)", flush=True)

    env["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    env["load_average_at_end"] = os.getloadavg()
    if env["network"]["kind"] == "separate-hosts":
        env["network"]["after"] = measure_network(args)
    (out / "environment.json").write_text(json.dumps(env, indent=2))
    if not rows:
        print(f"no run completed; {failures} failed attempts recorded in {out}/attempts.jsonl")
        return 1
    summary = summarize(rows)
    write_summary(out, env, summary, args.repetitions)
    incorrect = [r for r in rows if not r["correct"]]
    print(f"\n{len(rows) - len(incorrect)}/{len(rows)} completed runs correct; "
          f"{failures} failed attempts; results in {out}")
    return 1 if incorrect or failures else 0


if __name__ == "__main__":
    sys.exit(main())
