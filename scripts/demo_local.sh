#!/usr/bin/env bash
# End-to-end local demonstration with separate processes:
#   two computation parties, one coordinator, one requester, three stations.
#
# Usage: scripts/demo_local.sh [build-dir]   (default: build-mpc)
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
build="$(cd "${1:-$repo/build-mpc}" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/pps-demo.XXXXXX")"
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

# 1. Test PKI: CA, party/coordinator/requester/station certificates, and the
#    MP-SPDZ player certificates P0/P1.
python3 "$repo/scripts/provision_test_pki.py" --out "$work/pki" \
    --stations 10,20,30 --requesters alice

# 2. Each party's runtime directory holds only its own MP-SPDZ key.
for party in 0 1; do
    python3 "$repo/scripts/prepare_party_runtime.py" --party "$party" --pki "$work/pki" \
        --programs "$build/mpc/Programs" --out "$work/p$party"
done

# 3. Launch the two computation parties as separate processes.
for party in 0 1; do
    "$build/pp_party" --party-id "$party" --listen "127.0.0.1:1570$party" \
        --peer 127.0.0.1:15710 --mpc-hosts 127.0.0.1,127.0.0.1 --mpc-port-base 15720 \
        --pki "$work/pki" --runtime "$work/p$party" --stats "$work/party$party-stats.jsonl" \
        2> "$work/party$party.log" > "$work/party$party.out" &
done
until grep -q ready "$work/party0.out" 2>/dev/null && grep -q ready "$work/party1.out" 2>/dev/null; do
    sleep 0.2
done

client() { "$build/pp_client" "$1" --pki "$work/pki" --party0 127.0.0.1:15700 \
               --party1 127.0.0.1:15701 --session "$session" "${@:2}"; }

# 4. One search: requester at (0,0); stations 10 at (2,0), 20 at (1,1), 30 at (500,0).
session="$("$build/pp_client" new-session)"
client coordinator --horizon 100 --mode binary --requester alice --stations 10,20,30 \
    > "$work/coordinator.json" &
client requester --name alice --x 0 --y 0 > "$work/requester.json" &
client station --id 10 --x 2 --y 0 --radius 10 > "$work/station10.json" &
client station --id 20 --x 1 --y 1 --radius 10 > "$work/station20.json" &
client station --id 30 --x 500 --y 0 --radius 1000 > "$work/station30.json" &
wait %3 %4 %5 %6 %7

for file in coordinator requester station10 station20 station30; do
    printf '%-12s %s\n' "$file" "$(cat "$work/$file.json")"
done
echo "logs and per-session statistics: $work"
