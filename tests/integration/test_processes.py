#!/usr/bin/env python3
"""Process-level integration tests.

Two pp_party processes (party 0 and party 1) run as separate OS processes
with separate keys and runtime directories. The coordinator, the requester and
every station are separate pp_client processes that share their own inputs.
Functional results are compared with a plaintext oracle.

These are functional and robustness tests. Passing them (or finding no
plaintext in a packet capture) is not a proof of cryptographic security.
"""

import argparse
import json
import pathlib
import random
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from harness import Deployment, Paths, add_path_arguments, plaintext_oracle, run_parallel  # noqa: E402

MIN32, MAX32, MAXU32 = -2**31, 2**31 - 1, 2**32 - 1
STATION_IDS = [1, 2, 3, 4, 5, 9, 10, 20, 30, 77, 78] + list(range(101, 131))
REQUESTERS = ["alice", "bob", "carol"]
SECRET_MARKERS = ("1234567", "7654321")


class Failure(AssertionError):
    pass


def expect(condition, message, context=None):
    if not condition:
        detail = f"\n  context: {json.dumps(context, default=str)[:1500]}" if context else ""
        raise Failure(message + detail)


def check_selection(result, expected_id, requester_xy):
    coordinator = result["coordinator"]
    expect(coordinator.get("status") == "ok", "coordinator did not succeed", result)
    if expected_id is None:
        expect(coordinator.get("match") is False and "station_id" not in coordinator,
               "expected no match", result)
    else:
        expect(coordinator.get("match") is True and coordinator.get("station_id") == expected_id,
               f"expected station {expected_id}", result)
    expect(result["requester"].get("status") == "accepted", "requester not accepted", result)
    for station_id, outcome in result["stations"].items():
        if station_id == expected_id:
            expect(outcome.get("status") == "selected", "selected station got no output", result)
            expect((outcome.get("requester_x"), outcome.get("requester_y")) == tuple(requester_xy),
                   "selected station reconstructed wrong coordinates", result)
            expect(outcome.get("output_share_frames") == 4, "expected 2 shares from each party", result)
        else:
            expect(outcome.get("status") == "not-selected", "non-selected station status", result)
            expect(outcome.get("output_share_frames") == 0,
                   "output shares delivered to a non-selected station", result)


def oracle_session(deployment, requester, stations, horizon, **kwargs):
    expected = plaintext_oracle(requester[1:], stations, horizon)
    result = deployment.run_session(requester, stations, horizon, **kwargs)
    check_selection(result, expected, requester[1:])
    return expected


def expect_abort(result, code):
    coordinator = result["coordinator"]
    expect(coordinator.get("status") == "aborted" and coordinator.get("code") == code,
           f"expected coordinator abort '{code}'", result)
    for outcome in result["stations"].values():
        expect(outcome.get("output_share_frames", 0) == 0, "shares delivered in an aborted session",
               result)


# ---- scenarios ----------------------------------------------------------------

def test_specification_example(d):
    oracle_session(d, ("alice", 0, 0), [(10, 2, 0, 10), (20, 1, 1, 10)], 100)
    expect(plaintext_oracle((0, 0), [(10, 2, 0, 10), (20, 1, 1, 10)], 100) == 20, "oracle")


def test_horizon_boundaries(d):
    expect(oracle_session(d, ("alice", 0, 0), [(1, 100, 0, 100)], 100) == 1, "station at D")
    expect(oracle_session(d, ("alice", 0, 0), [(1, 101, 0, 1000)], 100) is None, "station at D+1")


def test_insufficient_support_radius(d):
    expect(oracle_session(d, ("alice", 0, 0), [(1, 1, 0, 0), (2, 5, 0, 10)], 100) == 2, "radius")


def test_ties_are_independent_of_arrival_order(d):
    stations = [(9, 3, 4, 5), (4, -3, -4, 5)]
    for order in ([9, 4], [4, 9]):
        result = d.run_session(("alice", 0, 0), stations, 10, station_order=order, stagger=0.4)
        check_selection(result, 4, (0, 0))


def test_empty_and_all_ineligible(d):
    check_selection(d.run_session(("alice", 0, 0), [], 100), None, (0, 0))
    expect(oracle_session(d, ("alice", 0, 0), [(1, 5, 5, 1), (2, 6, 6, 2)], 100) is None, "ineligible")


def test_zero_distance_and_zero_radius(d):
    expect(oracle_session(d, ("alice", 7, 7), [(3, 7, 7, 0)], 0) == 3, "zero")


def test_near_ties_and_ties(d):
    # q = 2500, 2500, 2401, 2500: the same radius r* = 50 covers all four.
    stations = [(1, 30, 40, 100), (2, -50, 0, 100), (3, 0, 49, 100), (4, 48, 14, 100)]
    expect(oracle_session(d, ("alice", 0, 0), stations, 1000) == 3, "near tie")
    # Three stations tie at q = 2500: the smallest ID wins.
    expect(oracle_session(d, ("alice", 0, 0), [s for s in stations if s[0] != 3], 1000) == 1, "tie")


def test_negative_and_extreme_coordinates(d):
    expect(oracle_session(d, ("alice", -50, -60), [(1, -53, -64, 5), (2, -40, -60, 20)], 1000) == 1,
           "negative")
    extreme = [(1, MAX32, MAX32, MAXU32), (2, MAX32 - 1, MIN32, MAXU32)]
    expect(oracle_session(d, ("alice", MIN32, MIN32), extreme, MAXU32) == 2, "extreme")


def test_repeated_requests_different_requesters(d):
    stations = [(1, 10, 0, 50), (2, 90, 0, 50)]
    for requester, expected in ((("alice", 0, 0), 1), (("bob", 100, 0), 2), (("carol", 50, 1), 1)):
        result = d.run_session(requester, stations, 1000)
        check_selection(result, expected, requester[1:])


def test_randomised_against_oracle(d):
    rng = random.Random(20260924)  # public seed for test data only; shares use the CSPRNG
    for trial in range(12):
        count = rng.randint(1, 7)
        ids = rng.sample(range(101, 131), count)
        stations = [(i, rng.randint(-40, 40), rng.randint(-40, 40), rng.randint(0, 60)) for i in ids]
        requester = (rng.choice(REQUESTERS), rng.randint(-40, 40), rng.randint(-40, 40))
        horizon = rng.randint(0, 80)
        oracle_session(d, requester, stations, horizon)


def test_log_hygiene_session(d):
    # Distinctive requester coordinates; checked against logs at the end.
    stations = [(1, 1234560, 7654320, 100)]
    oracle_session(d, ("alice", 1234567, 7654321), stations, 1000)


def test_duplicate_station_ids(d):
    session_ok = d.spawn("coordinator", "00" * 16, "--horizon", 10, "--requester", "alice",
                         "--stations", "5,5")
    result = d.collect(session_ok)
    expect(result.get("status") == "rejected" and result.get("code") == "duplicate",
           "coordinator must reject duplicate station IDs", result)
    for ids in ("5,5", "9,5"):
        # Bypass the coordinator's own check to exercise the parties' validation.
        coordinator = d.spawn("coordinator", "ab" * 16, "--horizon", 10, "--requester", "alice",
                              "--stations", ids, "--test-unchecked-station-list", "1",
                              "--timeout-ms", 4000)
        result = d.collect(coordinator)
        expect(result.get("status") == "aborted" and result.get("code") == "duplicate",
               f"parties must reject station list {ids}", result)
    check_selection(d.run_session(("alice", 0, 0), [(5, 1, 0, 5)], 10), 5, (0, 0))


def test_duplicate_and_unauthorised_submissions(d):
    import secrets
    session = secrets.token_hex(16)
    coordinator = d.spawn("coordinator", session, "--horizon", 100, "--requester", "alice",
                          "--stations", "5,30", "--timeout-ms", 20000)
    requester = d.spawn("requester", session, "--name", "alice", "--x", 0, "--y", 0)
    first = d.spawn("station", session, "--id", 5, "--x", 3, "--y", 0, "--radius", 10)
    time.sleep(1.5)
    duplicate = d.spawn("station", session, "--id", 5, "--x", 1, "--y", 0, "--radius", 10,
                        "--timeout-ms", 8000)
    outsider = d.spawn("station", session, "--id", 78, "--x", 0, "--y", 0, "--radius", 10,
                       "--timeout-ms", 8000)
    duplicate_result = d.collect(duplicate)
    outsider_result = d.collect(outsider)
    last = d.spawn("station", session, "--id", 30, "--x", 50, "--y", 0, "--radius", 100)
    result = {"coordinator": d.collect(coordinator), "requester": d.collect(requester),
              "stations": {5: d.collect(first), 30: d.collect(last)}}
    expect(duplicate_result.get("status") == "aborted" and duplicate_result.get("code") == "duplicate",
           "duplicate submission must be rejected", duplicate_result)
    expect(outsider_result.get("status") == "aborted" and outsider_result.get("code") == "unauthorized",
           "station outside the session must be rejected", outsider_result)
    check_selection(result, 5, (0, 0))


def test_timeout(d):
    import secrets
    session = secrets.token_hex(16)
    coordinator = d.spawn("coordinator", session, "--horizon", 100, "--requester", "alice",
                          "--stations", "1,2", "--timeout-ms", 3000)
    requester = d.spawn("requester", session, "--name", "alice", "--x", 0, "--y", 0)
    present = d.spawn("station", session, "--id", 1, "--x", 1, "--y", 0, "--radius", 10)
    result = {"coordinator": d.collect(coordinator), "requester": d.collect(requester),
              "stations": {1: d.collect(present)}}
    expect_abort(result, "timeout")
    expect(result["stations"][1].get("status") == "aborted", "present station must see the abort",
           result)
    check_selection(d.run_session(("alice", 0, 0), [(1, 1, 0, 10)], 100), 1, (0, 0))


def test_disconnect_and_malformed_messages(d):
    cases = [("disconnect", "disconnected", 0), ("stall", "timeout", 1),
             ("bad-magic", "malformed-message", 0), ("oversize", "malformed-message", 1),
             ("bad-sequence", "malformed-message", 0), ("duplicate-field", "duplicate", 1),
             ("wrong-station", "unauthorized", 0), ("trailing-bytes", "malformed-message", 1),
             ("incomplete-done", "malformed-message", 0)]
    for kind, code, target in cases:
        result = d.run_session(("alice", 0, 0), [(1, 1, 0, 10)], 100,
                               station_ids_override=[1, 77], timeout_ms=4000,
                               extra=[("test-inject", ["--id", 77, "--kind", kind,
                                                       "--target-party", target,
                                                       "--timeout-ms", 15000])])
        expect_abort(result, code)
        injected = result["extra"][0]
        expect(injected.get("status") in ("rejected", "connection-ended", "disconnected"),
               f"{kind}: party must reject the malformed input", result)
    check_selection(d.run_session(("alice", 0, 0), [(1, 1, 0, 10)], 100), 1, (0, 0))


def test_statistics_consistency(d):
    lines = [d.stats_lines(0), d.stats_lines(1)]
    expect(len(lines[0]) == len(lines[1]) and lines[0], "both parties record every session")
    by_shape = {}
    for a, b in zip(*lines):
        expect(a["session"] == b["session"] and a["status"] == b["status"], "session logs differ", [a, b])
        if a["status"] == "ok" and "operations" in a:
            for s in (a, b):
                expect(s["triples_remaining"] == 0 and
                       s["triples_consumed"] == s["triples_requested"] ==
                       s["plan"]["multiplications"],
                       "every generated triple consumed exactly once", s)
                # Obliviousness: what ran is exactly the public plan for (N, D).
                expect(s["operations"] == s["plan"], "executed operations differ from the plan", s)
            expect(a.get("selected_station") == b.get("selected_station"), "parties disagree", [a, b])
            shape = (a["stations"], a["horizon"])
            expect(by_shape.setdefault(shape, a["operations"]) == a["operations"],
                   "operation counts depend on more than (N, D)", [shape, a])


def test_no_secrets_in_logs(d):
    texts = [p.read_text() for p in (*d.logs, *d.stats) if p.exists()]
    for marker in SECRET_MARKERS:
        expect(all(marker not in t for t in texts), f"requester coordinate {marker} found in logs")


def run_exhaustion_test(paths, work):
    with Deployment(paths, work / "exhaustion", station_ids=[1, 2], requesters=["alice"],
                    party_args=["--test-triple-shortfall", "1"]) as d:
        for _ in range(2):
            result = d.run_session(("alice", 0, 0), [(1, 1, 0, 10), (2, 2, 0, 10)], 100)
            expect_abort(result, "preprocessing-exhausted")
            expect(all(o.get("status") == "aborted" for o in result["stations"].values()),
                   "stations must see the abort", result)
            expect(d.alive(), "parties must survive a clean preprocessing abort")
        for party in (0, 1):
            expect(all(s["status"] == "aborted:preprocessing-exhausted" for s in d.stats_lines(party)),
                   "stats must record the exhaustion abort")


def run_concurrency_test(paths, work, pki):
    deployments = [Deployment(paths, work / f"concurrent{i}", pki=pki).start() for i in (0, 1)]
    try:
        jobs = [
            lambda: deployments[0].run_session(("alice", 0, 0), [(1, 5, 0, 10), (2, 3, 0, 10)], 50),
            lambda: deployments[1].run_session(("bob", 100, 100), [(1, 90, 100, 20), (2, 97, 100, 1)], 50),
        ]
        first, second = run_parallel(jobs)
        check_selection(first, 2, (0, 0))
        check_selection(second, 1, (100, 100))
    finally:
        for deployment in deployments:
            deployment.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_path_arguments(parser)
    parser.add_argument("--keep", action="store_true", help="keep the work directory")
    args = parser.parse_args()
    paths = Paths(args.build_dir, args.source_dir, args.mpspdz_dir)
    work = pathlib.Path(tempfile.mkdtemp(prefix="pps-it-"))
    results = []

    def run(name, function, *fargs):
        start = time.time()
        try:
            function(*fargs)
            results.append((name, True, time.time() - start, ""))
            print(f"PASS {name} ({time.time() - start:.1f}s)", flush=True)
        except Exception as error:  # noqa: BLE001
            results.append((name, False, time.time() - start, str(error)))
            print(f"FAIL {name}: {error}", flush=True)
            if not isinstance(error, Failure):
                traceback.print_exc()

    main_deployment = Deployment(paths, work / "main", STATION_IDS, REQUESTERS)
    with main_deployment as d:
        for test in (test_specification_example, test_horizon_boundaries,
                     test_insufficient_support_radius, test_ties_are_independent_of_arrival_order,
                     test_empty_and_all_ineligible, test_zero_distance_and_zero_radius,
                     test_near_ties_and_ties, test_negative_and_extreme_coordinates,
                     test_repeated_requests_different_requesters, test_randomised_against_oracle,
                     test_log_hygiene_session, test_duplicate_station_ids,
                     test_duplicate_and_unauthorised_submissions, test_timeout,
                     test_disconnect_and_malformed_messages):
            run(test.__name__, test, d)
            if not d.alive():
                results.append(("party processes alive", False, 0, "a party process exited"))
                print("FAIL a party process exited; see", d.logs)
                break
        run("both party processes still running", lambda: expect(d.alive(), "party exited"))
    run(test_statistics_consistency.__name__, test_statistics_consistency, main_deployment)
    run(test_no_secrets_in_logs.__name__, test_no_secrets_in_logs, main_deployment)
    run("preprocessing_exhaustion", run_exhaustion_test, paths, work)
    run("concurrent_independent_sessions", run_concurrency_test, paths, work, work / "main" / "pki")

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} process-level tests passed "
          f"(work dir: {work})")
    if not args.keep and not failed:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
