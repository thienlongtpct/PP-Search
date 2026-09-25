#!/usr/bin/env bash
# Fetch MP-SPDZ at the pinned revision (third_party/mp-spdz.lock), apply the
# recorded patches, and build the static archive used by pp_party.
#
# Usage: scripts/build_mpspdz.sh [checkout-dir]   (default: third_party/mp-spdz)
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
lock="$repo_root/third_party/mp-spdz.lock"
dest="${1:-$repo_root/third_party/mp-spdz}"
jobs="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

url="$(awk '$1 == "repository" {print $2}' "$lock")"
commit="$(awk '$1 == "commit" {print $2}' "$lock")"

if [ ! -d "$dest/.git" ]; then
    git clone "$url" "$dest"
fi
cd "$dest"
if [ "$(git rev-parse HEAD)" != "$commit" ]; then
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "error: $dest has local modifications and is not at $commit" >&2
        exit 1
    fi
    git fetch origin
    git checkout --detach "$commit"
fi
git submodule update --init --recursive

# Verify every recursive submodule revision against the lock file.
status="$(git submodule status --recursive | awk '{sub(/^[-+U ]/, "", $1); print $2, $1}')"
awk '$1 == "submodule" {print $2, $3}' "$lock" | while read -r path sha; do
    actual="$(printf '%s\n' "$status" | awk -v p="$path" '$1 == p {print $2}')"
    if [ "$actual" != "$sha" ]; then
        echo "error: submodule $path is at '${actual:-missing}', lock requires $sha" >&2
        exit 1
    fi
done

# Apply recorded patches idempotently.
awk '$1 == "patch" {print $2}' "$lock" | while read -r patch; do
    file="$repo_root/third_party/$patch"
    if git apply --reverse --check "$file" 2>/dev/null; then
        echo "patch already applied: $patch"
    else
        git apply "$file"
        echo "applied patch: $patch"
    fi
done

# Local build configuration. The flags only relax -Werror for two warnings
# emitted by Homebrew's gmpxx.h and a debug fprintf under Apple clang 21.
cat > CONFIG.mine <<'EOF'
MY_CFLAGS = -Wno-deprecated-literal-operator -Wno-error=format
EOF

# semi2k-party.x pulls in libOTe/SoftSpoken, SimplestOT and every object the
# semi2k protocol needs; it also serves as MP-SPDZ's own reference binary.
make -j"$jobs" semi2k-party.x

printf 'print-%%:\n\t@echo $($*)\n' > .pps-print.mk
objects="$(make -s -f Makefile -f .pps-print.mk print-PROCESSOR) \
$(make -s -f Makefile -f .pps-print.mk print-COMMONOBJS) \
GC/square64.o GC/Instruction.o GC/SemiPrep.o GC/Semi.o \
OT/BaseOT.o OT/BitDiagonal.o OT/MascotParams.o OT/OTExtension.o \
OT/OTExtensionWithMatrix.o OT/OTTripleSetup.o"
# Record the exact flags MP-SPDZ was built with; CMake compiles the single
# translation unit that includes MP-SPDZ headers with the same settings.
make -s -f Makefile -f .pps-print.mk print-CFLAGS > pps-cflags.txt
make -s -f Makefile -f .pps-print.mk print-LDLIBS > pps-ldlibs.txt
make -s -f Makefile -f .pps-print.mk print-LIBSIMPLEOT > pps-libsimpleot.txt
rm -f .pps-print.mk
# shellcheck disable=SC2086
make -j"$jobs" $objects
rm -f libpps_mpspdz.a
# shellcheck disable=SC2086
ar -csr libpps_mpspdz.a $(printf '%s\n' $objects | sort -u)

echo "MP-SPDZ $commit ready in $dest"
