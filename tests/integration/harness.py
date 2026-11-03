"""Process-level harness: two computation-party processes plus independently
launched coordinator, requester and station processes, all talking over
mutually authenticated TLS, on localhost unless SeparateHostDeployment is used.

Used by tests/integration/test_*.py and benchmarks/run_benchmarks.py.
"""

import json
import os
import pathlib
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[2]


class Paths:
    def __init__(self, build_dir, source_dir=REPO, mpspdz_dir=None):
        self.build = pathlib.Path(build_dir).resolve()
        self.source = pathlib.Path(source_dir).resolve()
        self.mpspdz = pathlib.Path(mpspdz_dir or self.source / "third_party" / "mp-spdz").resolve()
        self.party = self.build / "pp_party"
        self.client = self.build / "pp_client"
        self.programs = self.build / "mpc" / "Programs"
        for required in (self.party, self.client, self.programs):
            if not required.exists():
                raise SystemExit(f"missing build output: {required}")


def add_path_arguments(parser):
    parser.add_argument("--build-dir", default=str(REPO / "build"))
    parser.add_argument("--source-dir", default=str(REPO))
    parser.add_argument("--mpspdz-dir", default=None)


def free_port_block(count):
    """A base port such that base..base+count-1 are currently free."""
    for _ in range(200):
        base = 20000 + secrets.randbelow(30000)
        sockets = []
        try:
            for offset in range(count):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", base + offset))
                sockets.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in sockets:
                s.close()
    raise RuntimeError("no free port block")


def provision_pki(paths, directory, station_ids=(), requesters=(), stations_file=None):
    command = [sys.executable, str(paths.source / "scripts" / "provision_test_pki.py"),
               "--out", str(directory),
               "--stations", ",".join(str(s) for s in station_ids),
               "--requesters", ",".join(requesters)]
    if stations_file:
        command += ["--stations-file", str(stations_file)]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def prepare_runtime(paths, party, pki, out):
    subprocess.run([sys.executable, str(paths.source / "scripts" / "prepare_party_runtime.py"),
                    "--party", str(party), "--pki", str(pki), "--programs", str(paths.programs),
                    "--out", str(out)], check=True, stdout=subprocess.DEVNULL)


def parse_json_line(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    return None


class Deployment:
    """Two pp_party processes with their own runtime directories and keys."""

    def __init__(self, paths, work, station_ids=(), requesters=("alice",), stations_file=None,
                 party_args=(), pki=None):
        self.paths = paths
        self.work = pathlib.Path(work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.pki = pathlib.Path(pki) if pki else self.work / "pki"
        if pki is None:
            provision_pki(paths, self.pki, station_ids, requesters, stations_file)
        base = free_port_block(5)
        self.listen = [base, base + 1]
        self.peer_port = base + 2
        self.mpc_port_base = base + 3  # uses base+3 and base+4
        self.party_args = list(party_args)
        self.processes = [None, None]
        self.logs = [self.work / "party0.log", self.work / "party1.log"]
        self.stats = [self.work / "party0-stats.jsonl", self.work / "party1-stats.jsonl"]
        for party in (0, 1):
            prepare_runtime(paths, party, self.pki, self.work / f"p{party}")

    def endpoint(self, party):
        return f"127.0.0.1:{self.listen[party]}"

    def start(self, timeout=90):
        for party in (0, 1):
            command = [str(self.paths.party), "--party-id", str(party),
                       "--listen", self.endpoint(party),
                       "--peer", f"127.0.0.1:{self.peer_port}",
                       "--mpc-hosts", "127.0.0.1,127.0.0.1",
                       "--mpc-port-base", str(self.mpc_port_base),
                       "--pki", str(self.pki), "--runtime", str(self.work / f"p{party}"),
                       "--stats", str(self.stats[party])] + self.party_args
            self.processes[party] = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=open(self.logs[party], "ab"), text=True)
        deadline = time.time() + timeout
        for party in (0, 1):
            process = self.processes[party]
            line = ""
            while time.time() < deadline:
                line = process.stdout.readline()
                if line or process.poll() is not None:
                    break
            event = json.loads(line) if line.startswith("{") else None
            if not event or event.get("event") != "ready":
                self.stop()
                raise RuntimeError(f"party {party} failed to start; see {self.logs[party]}")
        return self

    def alive(self):
        return all(p is not None and p.poll() is None for p in self.processes)

    def stop(self):
        for process in self.processes:
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in self.processes:
            if process is not None:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ---- clients -------------------------------------------------------------

    def client_command(self, role, session, *args):
        return [str(self.paths.client), role, "--pki", str(self.pki),
                "--party0", self.endpoint(0), "--party1", self.endpoint(1),
                "--session", session] + [str(a) for a in args]

    def spawn(self, role, session, *args):
        return subprocess.Popen(self.client_command(role, session, *args),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def _wait_clients(self, processes, timeout=1800):
        """Waits for client processes; kills them if a party process dies."""
        deadline = time.time() + timeout
        party_dead_since = None
        while any(p.poll() is None for p in processes):
            if not self.alive():
                party_dead_since = party_dead_since or time.time()
                if time.time() - party_dead_since > 3:
                    break
            if time.time() > deadline:
                break
            time.sleep(0.05)
        for p in processes:
            if p.poll() is None:
                p.kill()

    @staticmethod
    def collect(process, timeout=600):
        stdout, stderr = process.communicate(timeout=timeout)
        result = parse_json_line(stdout)
        if result is None:
            result = {"status": "no-output", "returncode": process.returncode,
                      "stderr": stderr.strip()[-500:]}
        result["returncode"] = process.returncode
        return result

    def stats_lines(self, party):
        path = self.stats[party]
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def run_session(self, requester, stations, horizon, timeout_ms=30000,
                    station_order=None, stagger=0.0, batch_stations_file=None,
                    coordinator_args=(), station_ids_override=None, extra=None):
        """requester = (name, x, y); stations = [(id, x, y, radius)].

        Returns {"coordinator": {...}, "requester": {...}, "stations": {id: {...}},
                 "extra": [...], "session": hex, "seconds": wall time}.
        """
        session = secrets.token_hex(16)
        ids = station_ids_override if station_ids_override is not None else [s[0] for s in stations]
        started = time.time()
        coordinator = self.spawn("coordinator", session, "--horizon", horizon,
                                 "--requester", requester[0], "--timeout-ms", timeout_ms,
                                 *(["--stations-file", batch_stations_file] if batch_stations_file
                                   else ["--stations", ",".join(str(i) for i in ids)]),
                                 *coordinator_args)
        requester_process = self.spawn("requester", session, "--name", requester[0],
                                       "--x", requester[1], "--y", requester[2],
                                       "--timeout-ms", timeout_ms)
        station_processes = {}
        if batch_stations_file:
            station_processes["batch"] = self.spawn("stations", session, "--file",
                                                    batch_stations_file,
                                                    "--timeout-ms", timeout_ms + 600000)
        else:
            ordered = stations if station_order is None else [
                next(s for s in stations if s[0] == i) for i in station_order]
            for station in ordered:
                station_processes[station[0]] = self.spawn(
                    "station", session, "--id", station[0], "--x", station[1], "--y", station[2],
                    "--radius", station[3], "--timeout-ms", timeout_ms + 600000)
                if stagger:
                    time.sleep(stagger)
        extra_processes = [self.spawn(role, session, *args) for role, args in (extra or [])]
        self._wait_clients([coordinator, requester_process, *station_processes.values(),
                            *extra_processes])
        result = {"session": session,
                  "coordinator": self.collect(coordinator),
                  "requester": self.collect(requester_process),
                  "stations": {key: self.collect(p) for key, p in station_processes.items()},
                  "extra": [self.collect(p) for p in extra_processes]}
        result["seconds"] = time.time() - started
        return result


class SeparateHostDeployment(Deployment):
    """One pp_party per host, started over ssh; clients run on this machine.

    Every target holds only its own party's key material. Each host must
    already have the same pp_party and bytecode build at `remote_build`.
    Nothing here changes network settings.

    A target of "local" runs that party on this machine instead of over ssh,
    which only exercises the plumbing: it is not a separate-host deployment.
    """

    def __init__(self, paths, work, pki, targets, addresses, remote_dirs, remote_builds, port_base):
        self.paths = paths
        self.work = pathlib.Path(work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.pki = pathlib.Path(pki)
        self.targets = targets
        self.addresses = addresses
        self.remote_dirs = remote_dirs
        self.remote_builds = remote_builds
        self.listen = [port_base, port_base + 1]
        self.peer_port = port_base + 2
        self.mpc_port_base = port_base + 3  # uses base+3 and base+4
        self.party_args = []
        self.processes = [None, None]
        self.logs = [self.work / "party0.log", self.work / "party1.log"]
        self.stats = [self.work / "party0-stats.jsonl", self.work / "party1-stats.jsonl"]

    def endpoint(self, party):
        return f"{self.addresses[party]}:{self.listen[party]}"

    def _shell(self, party, command):
        prefix = ["sh", "-c"] if self.targets[party] == "local" else \
            ["ssh", "-o", "BatchMode=yes", self.targets[party]]
        return prefix + [command]

    def _copy_command(self, party, source, destination, pull=False):
        target = self.targets[party]
        remote = destination if target == "local" else f"{target}:{destination}"
        if pull:
            remote = source if target == "local" else f"{target}:{source}"
            return ["rsync", "-a", remote, destination]
        return ["rsync", "-a", "--delete", source, remote]

    def party_command(self, party):
        directory = self.remote_dirs[party]
        return (f"cd {directory}/runtime && echo $$ > {directory}/party.pid && "
                f"exec {self.remote_builds[party]}/pp_party --party-id {party} "
                f"--listen {self.endpoint(party)} "
                f"--peer {self.addresses[0]}:{self.peer_port} "
                f"--mpc-hosts {self.addresses[0]},{self.addresses[1]} "
                f"--mpc-port-base {self.mpc_port_base} "
                f"--pki {directory}/pki --runtime {directory}/runtime "
                f"--stats {directory}/stats.jsonl 2> {directory}/party.log")

    def install_commands(self, party):
        """Commands that ship this party's own material, and no one else's."""
        bundle = self.work / f"bundle-p{party}"
        directory = self.remote_dirs[party]
        return bundle, [self._shell(party, f"mkdir -p {directory}"),
                        self._copy_command(party, f"{bundle}/", f"{directory}/")]

    def install(self):
        for party in (0, 1):
            bundle, commands = self.install_commands(party)
            prepare_runtime(self.paths, party, self.pki, bundle / "runtime")
            programs = bundle / "runtime" / "Programs"
            programs.unlink()
            programs.symlink_to(f"{self.remote_builds[party]}/mpc/Programs", target_is_directory=True)
            pki = bundle / "pki"
            pki.mkdir(exist_ok=True)
            for name in ("ca.pem", f"party{party}.pem", f"party{party}.key"):
                shutil.copy2(self.pki / name, pki / name)
            for command in commands:
                subprocess.run(command, check=True)
        return self

    def start(self, timeout=90):
        for party in (0, 1):
            directory = self.remote_dirs[party]
            subprocess.run(self._shell(party, f"rm -f {directory}/stats.jsonl {directory}/party.log"),
                           check=True)
            self.processes[party] = subprocess.Popen(
                self._shell(party, self.party_command(party)), stdout=subprocess.PIPE, text=True)
        deadline = time.time() + timeout
        for party in (0, 1):
            line = ""
            while time.time() < deadline and not line and self.processes[party].poll() is None:
                line = self.processes[party].stdout.readline()
            event = json.loads(line) if line.startswith("{") else None
            if not event or event.get("event") != "ready":
                self.stop()
                raise RuntimeError(f"party {party} on {self.targets[party]} failed to start")
        return self

    def stop(self):
        for party in (0, 1):
            if self.processes[party] is None:
                continue
            directory = self.remote_dirs[party]
            subprocess.run(self._shell(party, f"kill $(cat {directory}/party.pid) 2>/dev/null; true"),
                           check=False)
            try:
                self.processes[party].wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.processes[party].kill()
                self.processes[party].wait()
            for name, local in (("stats.jsonl", self.stats[party]), ("party.log", self.logs[party])):
                subprocess.run(self._copy_command(party, f"{directory}/{name}", str(local), pull=True),
                               check=False)


def run_parallel(functions):
    """Runs callables in threads; returns their results in order."""
    results = [None] * len(functions)
    errors = []

    def wrap(index, function):
        try:
            results[index] = function()
        except Exception as error:  # noqa: BLE001 - reported to the caller
            errors.append(error)

    threads = [threading.Thread(target=wrap, args=(i, f)) for i, f in enumerate(functions)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise errors[0]
    return results


def plaintext_oracle(requester, stations, horizon):
    """Eligible station minimising (q, id); None for no match."""
    ax, ay = requester
    best = None
    for station_id, x, y, radius in stations:
        q = (ax - x) ** 2 + (ay - y) ** 2
        if q <= radius * radius and q <= horizon * horizon:
            if best is None or (q, station_id) < best:
                best = (q, station_id)
    return None if best is None else best[1]
