#!/usr/bin/env bash
# Reproducible-build check: build the pure workspace twice, from two different
# directories, and require bit-identical release binaries.
#
#   scripts/ci-repro.sh [OUT_DIR]        (default OUT_DIR: dist/repro)
#
# Both builds use the same toolchain (rust-toolchain.toml), the COMMITTED
# Cargo.lock with --locked (the script fails if there is none: a lock generated
# here and shared by both builds would prove nothing about rebuilding a
# release), SOURCE_DATE_EPOCH = the HEAD commit time, and
# --remap-path-prefix so neither the checkout path nor CARGO_HOME leaks into
# the binaries. The two source copies deliberately live at paths of different
# length, so a missed absolute path shows up as a hash mismatch.
#
# Compared artefacts: every executable `target/release/robodr-*` (generic, so
# it covers robodr-commission and any later binary). If the workspace has no
# such binary yet the script says so and exits 0, unless
# REPRO_REQUIRE_BINARIES=1 (CI sets it: the workspace ships robodr-* binaries).
#
# Environment:
#   REPRO_SRC=dir          tree to copy (default: repo root)
#   CARGO_FLAGS="..."      extra cargo flags, e.g. "--offline"
#   REPRO_WORK=dir         scratch dir (default: mktemp -d)
#   SOURCE_DATE_EPOCH      override the commit timestamp
#   CARGO_BUILD_TARGET     cross build (e.g. aarch64-unknown-linux-gnu): the
#                          binaries are then read from target/<triple>/release
#                          (cargo's layout); unset = native target/release. For a
#                          *-linux-musl triple, CC_<triple> defaults to clang
#                          (ring's C/assembly; as scripts/build-static.sh)
#   REPRO_ALLOW_NO_LOCK=1  local experiments only: without a committed lock,
#                          let EACH copy resolve on its own (no --locked); the
#                          result does not prove a release is rebuildable
# Pulsar-bound members are excluded (scripts/ci-pure-excludes.py).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
src="${REPRO_SRC:-$root}"
src="$(cd "$src" && pwd)"
out="${1:-dist/repro}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
read -r -a cargo_flags <<<"${CARGO_FLAGS:-}"
work="${REPRO_WORK:-$(mktemp -d)}"
mkdir -p "$work"
work="$(cd "$work" && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$src" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
echo "repro: SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" >&2

# Copy the tree twice (submodules included, build outputs and VCS excluded).
dirs=("$work/a/robodr" "$work/bb-longer-path/robodr")
for d in "${dirs[@]}"; do
    rm -rf "$d"
    mkdir -p "$d"
    (cd "$src" && tar --exclude=./target --exclude=./.git --exclude=./dist -cf - .) | tar -xf - -C "$d"
done

# Both builds must come from the committed resolution.
locked=()
if git -C "$src" ls-files --error-unmatch Cargo.lock >/dev/null 2>&1 ||
    { [[ ! -d "$src/.git" && ! -f "$src/.git" ]] && [[ -f "$src/Cargo.lock" ]]; }; then
    locked=(--locked)
    lock_sum="$(sha256sum "$src/Cargo.lock" | cut -d' ' -f1)"
    echo "repro: building from committed Cargo.lock $lock_sum" >&2
elif [[ "${REPRO_ALLOW_NO_LOCK:-0}" == 1 ]]; then
    echo "repro: WARNING: no committed Cargo.lock; each copy resolves independently (not a release proof)" >&2
    for d in "${dirs[@]}"; do rm -f "$d/Cargo.lock"; done
    lock_sum=""
else
    echo "repro: FAIL: Cargo.lock is not committed in $src (docs/BUILD.md, Cargo.lock policy)" >&2
    exit 1
fi

excludes="$(cd "${dirs[0]}" && cargo metadata --no-deps --format-version 1 "${locked[@]}" "${cargo_flags[@]}" |
    python3 "$here/ci-pure-excludes.py" -)"
read -r -a exclude_args <<<"$excludes"

# musl cross builds: ring (rustls' crypto provider, robodr-uplink) has C and
# assembly; compile it with clang, as scripts/build-static.sh does.
if [[ "${CARGO_BUILD_TARGET:-}" == *-linux-musl ]]; then
    cc_var="CC_$(printf '%s' "$CARGO_BUILD_TARGET" | tr '-' '_')"
    if [[ -z "${!cc_var:-}" ]] && command -v clang >/dev/null; then
        export "$cc_var=clang"
    fi
fi

# cargo puts --target / CARGO_BUILD_TARGET output under target/<triple>/.
rel="release"
[[ -n "${CARGO_BUILD_TARGET:-}" ]] && rel="$CARGO_BUILD_TARGET/release"

build() {
    local d="$1"
    (
        cd "$d"
        export CARGO_TARGET_DIR="$d/target"
        export CARGO_INCREMENTAL=0
        export RUSTFLAGS="--remap-path-prefix=$d=/build/robodr --remap-path-prefix=$cargo_home=/cargo ${RUSTFLAGS_EXTRA:-}"
        cargo build --release --workspace "${exclude_args[@]}" "${locked[@]}" "${cargo_flags[@]}"
    )
}

list_bins() {
    find "$1/target/$rel" -maxdepth 1 -type f -name 'robodr-*' -perm -u+x ! -name '*.d' \
        -printf '%f\n' 2>/dev/null | LC_ALL=C sort
}

for d in "${dirs[@]}"; do
    echo "repro: building in $d" >&2
    build "$d"
done

# --locked must not have rewritten the lock in either copy.
if [[ -n "$lock_sum" ]]; then
    for d in "${dirs[@]}"; do
        if [[ "$(sha256sum "$d/Cargo.lock" | cut -d' ' -f1)" != "$lock_sum" ]]; then
            echo "repro: FAIL: Cargo.lock changed during the build in $d" >&2
            exit 1
        fi
    done
fi

mapfile -t bins_a < <(list_bins "${dirs[0]}")
mapfile -t bins_b < <(list_bins "${dirs[1]}")
if [[ "${bins_a[*]}" != "${bins_b[*]}" ]]; then
    echo "repro: FAIL: different binary sets: [${bins_a[*]}] vs [${bins_b[*]}]" >&2
    exit 1
fi
if [[ ${#bins_a[@]} -eq 0 ]]; then
    echo "repro: no target/release/robodr-* binaries in this workspace yet; nothing to compare" >&2
    : >"$out/SHA256SUMS"
    [[ "${REPRO_REQUIRE_BINARIES:-0}" == 1 ]] && exit 1
    exit 0
fi

rc=0
: >"$out/SHA256SUMS"
for b in "${bins_a[@]}"; do
    ha="$(sha256sum "${dirs[0]}/target/$rel/$b" | cut -d' ' -f1)"
    hb="$(sha256sum "${dirs[1]}/target/$rel/$b" | cut -d' ' -f1)"
    if [[ "$ha" == "$hb" ]]; then
        echo "repro: OK   $b $ha" >&2
        printf '%s  %s\n' "$ha" "$b" >>"$out/SHA256SUMS"
    else
        echo "repro: FAIL $b $ha != $hb" >&2
        rc=1
    fi
done
[[ $rc -eq 0 ]] && echo "repro: ${#bins_a[@]} binary(ies) reproducible; hashes in $out/SHA256SUMS" >&2
exit "$rc"
