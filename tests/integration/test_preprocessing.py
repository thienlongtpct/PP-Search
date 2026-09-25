#!/usr/bin/env python3
"""Runs tests/test_preprocessing.cpp as two separate processes (party 0 and 1),
each in its own runtime directory with only its own MP-SPDZ key."""

import argparse
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import harness  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    harness.add_path_arguments(parser)
    args = parser.parse_args()
    paths = harness.Paths(args.build_dir, args.source_dir, args.mpspdz_dir)
    binary = paths.build / "test_preprocessing"
    with tempfile.TemporaryDirectory(prefix="pps-prep-") as work:
        work = pathlib.Path(work)
        harness.provision_pki(paths, work / "pki")
        for party in (0, 1):
            harness.prepare_runtime(paths, party, work / "pki", work / f"p{party}")
        port = harness.free_port_block(2)
        processes = [subprocess.Popen([str(binary), str(party), str(port)], cwd=work / f"p{party}",
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                     for party in (0, 1)]
        failed = False
        for party, process in enumerate(processes):
            output, _ = process.communicate(timeout=600)
            lines = [l for l in output.splitlines() if "unused" not in l]
            for line in lines:
                print(f"[party {party}] {line}")
            failed |= process.returncode != 0
    if failed:
        print("preprocessing harness FAILED")
        return 1
    print("preprocessing harness passed in two separate processes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
