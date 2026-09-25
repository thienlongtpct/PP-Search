#!/usr/bin/env python3
"""Create the MP-SPDZ runtime directory of ONE computation party.

The directory receives only what that party may hold:
  Programs/            -> compiled MP-SPDZ functions (build/mpc/Programs)
  Player-Data/P<i>.key    this party's MP-SPDZ TLS key
  Player-Data/P<i>.pem    this party's certificate
  Player-Data/P<1-i>.pem  the peer's certificate (trusted, hashed for OpenSSL)

Usage: prepare_party_runtime.py --party 0 --pki DIR --programs BUILD/mpc/Programs --out RUNDIR
"""

import argparse
import os
import pathlib
import shutil
import subprocess


def openssl_binary():
    candidates = [os.environ.get("OPENSSL")]
    try:
        prefix = subprocess.run(["brew", "--prefix", "openssl@3"], capture_output=True,
                                text=True, check=False).stdout.strip()
        if prefix:
            candidates.append(f"{prefix}/bin/openssl")
    except FileNotFoundError:
        pass
    candidates.append(shutil.which("openssl"))
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).exists():
            return candidate
    raise SystemExit("openssl not found; set OPENSSL")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--party", type=int, choices=(0, 1), required=True)
    parser.add_argument("--pki", required=True)
    parser.add_argument("--programs", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    player_data = out / "Player-Data"
    if player_data.exists():
        shutil.rmtree(player_data)
    player_data.mkdir(parents=True)
    source = pathlib.Path(args.pki) / "mpspdz"
    me, peer = f"P{args.party}", f"P{1 - args.party}"
    shutil.copy2(source / f"{me}.key", player_data / f"{me}.key")
    shutil.copy2(source / f"{me}.pem", player_data / f"{me}.pem")
    shutil.copy2(source / f"{peer}.pem", player_data / f"{peer}.pem")
    subprocess.run([openssl_binary(), "rehash", str(player_data)], check=True)

    programs = out / "Programs"
    if programs.is_symlink() or programs.exists():
        if programs.is_symlink() or programs.is_file():
            programs.unlink()
        else:
            shutil.rmtree(programs)
    programs.symlink_to(pathlib.Path(args.programs).resolve(), target_is_directory=True)
    print(f"party {args.party} runtime ready in {out}")


if __name__ == "__main__":
    main()
