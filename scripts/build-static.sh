#!/usr/bin/env bash
# Static (musl) release build of the pure binaries, for robots whose OS is
# older than the glibc the regular package needs: Unitree EDU computers on
# JetPack 5 (Ubuntu 20.04, glibc 2.31, systemd 245) and any other host below
# glibc 2.35 (docs/BUILD.md "Static (musl) build", docs/UNITREE.md 3.2).
#
#   scripts/build-static.sh <x86_64-unknown-linux-musl|aarch64-unknown-linux-musl> [--out DIR]
#   scripts/build-static.sh <triple> --check-dir DIR
#
# Builds exactly what scripts/ci-repro.sh builds (the pure workspace,
# Pulsar-bound members excluded with scripts/ci-pure-excludes.py), for the
# musl target, with the release flags: --locked, SOURCE_DATE_EPOCH = HEAD
# commit time, --remap-path-prefix for the checkout and CARGO_HOME. Then it
# CHECKS every robodr-* binary and refuses to finish unless each one is
#   * an ELF for the target's machine (62 x86-64, 183 AArch64),
#   * position-independent: e_type ET_DYN (static-pie; see below),
#   * static: no PT_INTERP program header and no DT_NEEDED entry, so it
#     runs on any Linux kernel the Rust musl target supports, whatever the
#     host's libc,
# and copies them with a SHA256SUMS file to DIR (default
# dist/static/<triple>), ready for packaging/build-deb.sh --variant focal.
#
# Linker: rust-lld, shipped with the Rust toolchain, for both triples (no C
# cross linker, no musl-gcc; the musl CRT objects and libc come from the
# target's rust-std, "self-contained" linking); for aarch64 through the
# scripts/static-pie-ld wrapper. Set CARGO_TARGET_<TRIPLE>_LINKER yourself
# to override.
#
# C compiler: one dependency has C and assembly, `ring` (the crypto provider
# of rustls, used by robodr-uplink's TLS); everything else is pure Rust.
# `ring` is compiled with the PINNED clang (scripts/c-toolchain.sh: clang-18,
# 18.1.3; it cross-compiles for both triples and needs no libc headers
# beyond what clang finds). CC_<triple> defaults to it; a CC_<triple> you
# set must be the same version. A missing or different clang FAILS the
# build (exit 1) — no fallback to `cc` — unless ROBODR_ALLOW_UNPINNED_CC=1
# (local experiments; the result is not a release build). The toolchain
# versions are written to DIR/TOOLCHAIN.txt.
#
# Executable layout: static-pie on both triples (ET_DYN, no interpreter: the
# image is randomised by ASLR like stack, heap and mmap). x86_64 is
# static-pie in Rust's target; aarch64-unknown-linux-musl is not, so its
# linker defaults to scripts/static-pie-ld (rust-lld with rustc's own
# static-pie link: rcrt1.o, -pie --no-dynamic-linker -z text; tested by
# scripts/test-static-pie-ld.sh). Every binary must be ET_DYN, whatever
# linker the caller set; a non-PIE binary FAILS the build (exit 1) unless
# ROBODR_ALLOW_NON_PIE=1 (local experiments with another linker; then a
# WARNING, and the result is not a release build). ROBODR_REQUIRE_STATIC_PIE=1
# (release.yml) overrides ROBODR_ALLOW_NON_PIE.
#
# Check only (no build): --check-dir DIR checks the robodr-* binaries in DIR
# exactly as after a build and copies nothing.
#
# robodr-pulsard is NOT built: it links libsqlite3/OpenSSL and embeds
# clang-built eBPF objects, and it needs a BTF kernel that JetPack 5 does
# not have.
#
# Environment:
#   CARGO_FLAGS="..."   extra cargo flags, e.g. "--offline"
#   CARGO_TARGET_DIR    as usual (default: target/)
#   SOURCE_DATE_EPOCH   override the commit timestamp
#
# Exit: 0 built and checked, 1 build or check failed, 2 usage error.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

triple=""
out=""
check_dir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
    --check-dir) [[ $# -ge 2 ]] || { echo "build-static: --check-dir needs a value" >&2; exit 2; }; check_dir="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || { echo "build-static: --out needs a value" >&2; exit 2; }; out="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    -*) echo "build-static: unknown option $1" >&2; exit 2 ;;
    *) [[ -z "$triple" ]] || { echo "build-static: one target only" >&2; exit 2; }; triple="$1"; shift ;;
    esac
done
case "$triple" in
x86_64-unknown-linux-musl) want_machine=62 ;;
aarch64-unknown-linux-musl) want_machine=183 ;;
*) echo "build-static: target must be x86_64-unknown-linux-musl or aarch64-unknown-linux-musl" >&2; exit 2 ;;
esac
[[ -n "$out" ]] || out="$root/dist/static/$triple"
command -v readelf >/dev/null || { echo "build-static: readelf (binutils) not found" >&2; exit 2; }
linker_var="CARGO_TARGET_$(printf '%s' "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
# Is a non-PIE binary tolerated (see "Executable layout")?
pie_optional=0
if [[ "${ROBODR_ALLOW_NON_PIE:-0}" == 1 && "${ROBODR_REQUIRE_STATIC_PIE:-0}" != 1 ]]; then
    pie_optional=1
fi

# check_bins DIR NAME...: the release checks of every binary; 0 all pass.
check_bins() {
    local dir="$1" rc=0 b f machine etype
    shift
    for b in "$@"; do
        f="$dir/$b"
        machine="$(od -An -tu2 -j18 -N2 "$f" | tr -d '[:space:]')"
        if [[ "$(head -c4 "$f" | od -An -tx1 | tr -d '[:space:]')" != 7f454c46 || "$machine" != "$want_machine" ]]; then
            echo "build-static: FAIL $b: not an ELF for $triple (e_machine $machine)" >&2
            rc=1
            continue
        fi
        etype="$(od -An -tu2 -j16 -N2 "$f" | tr -d '[:space:]')"
        if [[ "$etype" != 3 ]]; then
            if [[ $pie_optional == 1 ]]; then
                echo "build-static: WARNING $b: not position-independent (e_type $etype; ROBODR_ALLOW_NON_PIE=1, not a release build)" >&2
            else
                echo "build-static: FAIL $b: not position-independent (e_type $etype, want 3 ET_DYN: static-pie)" >&2
                rc=1
            fi
        fi
        if readelf -lW "$f" | grep -q 'INTERP'; then
            echo "build-static: FAIL $b: has a program interpreter (dynamically linked)" >&2
            rc=1
        fi
        if readelf -dW "$f" 2>/dev/null | grep -q '(NEEDED)'; then
            echo "build-static: FAIL $b: needs shared libraries: $(readelf -dW "$f" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')" >&2
            rc=1
        fi
        if readelf -dW "$f" 2>/dev/null | grep -q 'TEXTREL'; then
            echo "build-static: FAIL $b: text relocations" >&2
            rc=1
        fi
    done
    return "$rc"
}
list_bins() {
    find "$1" -maxdepth 1 -type f -name 'robodr-*' -perm -u+x ! -name '*.d' -printf '%f\n' | LC_ALL=C sort
}
if [[ -n "$check_dir" ]]; then
    mapfile -t bins < <(list_bins "$check_dir")
    [[ ${#bins[@]} -gt 0 ]] || { echo "build-static: FAIL: no robodr-* binaries in $check_dir" >&2; exit 1; }
    check_bins "$check_dir" "${bins[@]}" || exit 1
    echo "build-static: ${#bins[@]} binaries in $check_dir pass the static checks" >&2
    exit 0
fi

cd "$root"
read -r -a cargo_flags <<<"${CARGO_FLAGS:-}"
if [[ ! -f Cargo.lock ]]; then
    echo "build-static: Cargo.lock missing; release builds are --locked (docs/BUILD.md)" >&2
    exit 1
fi
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
# Same flags as release.yml / ci-repro.sh. With --target, RUSTFLAGS applies to
# the target artefacts only (build scripts and proc macros stay host-native).
export RUSTFLAGS="--remap-path-prefix=$root=/build/robodr --remap-path-prefix=$cargo_home=/cargo"
if [[ -z "${!linker_var:-}" ]]; then
    if [[ "$triple" == aarch64-unknown-linux-musl ]]; then
        export "$linker_var=$here/static-pie-ld"
    else
        export "$linker_var=rust-lld"
    fi
fi
# shellcheck source=scripts/c-toolchain.sh disable=SC1091
. "$here/c-toolchain.sh"
robodr_pin_cc "$triple" build-static || exit 1
cc_var="CC_$(printf '%s' "$triple" | tr '-' '_')"
echo "build-static: $triple, linker ${!linker_var}, C compiler ${!cc_var}, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" >&2

# The target's standard library must be installed: through rustup, or in
# the sysroot of a toolchain installed without it
# (scripts/ci-install-pinned-toolchain.sh, release.yml's rebuild).
if ! rustup target list --installed 2>/dev/null | grep -qx "$triple" &&
    [[ ! -d "$(rustc --print sysroot 2>/dev/null)/lib/rustlib/$triple/lib" ]]; then
    echo "build-static: target $triple not installed: rustup target add $triple" >&2
    exit 1
fi

excludes="$(cargo metadata --no-deps --format-version 1 --locked "${cargo_flags[@]}" |
    python3 "$here/ci-pure-excludes.py" -)"
read -r -a exclude_args <<<"$excludes"
cargo build --release --locked --target "$triple" --workspace "${exclude_args[@]}" "${cargo_flags[@]}"

bin_dir="${CARGO_TARGET_DIR:-$root/target}/$triple/release"
mapfile -t bins < <(list_bins "$bin_dir")
if [[ ${#bins[@]} -eq 0 ]]; then
    echo "build-static: FAIL: no robodr-* binaries in $bin_dir" >&2
    exit 1
fi
check_bins "$bin_dir" "${bins[@]}" || exit 1

mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/robodr-* "$out/SHA256SUMS"
for b in "${bins[@]}"; do
    install -m 0755 "$bin_dir/$b" "$out/$b"
done
(cd "$out" && sha256sum "${bins[@]}" >SHA256SUMS)
robodr_toolchain_report >"$out/TOOLCHAIN.txt"
echo "build-static: ${#bins[@]} static binaries checked, copied to $out" >&2
cat "$out/SHA256SUMS"
