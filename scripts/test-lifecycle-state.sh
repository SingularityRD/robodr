#!/usr/bin/env bash
# Tests of scripts/lifecycle-state.sh (the state checks of
# scripts/systemd-lifecycle.sh): a sealed black-box segment changed past
# its first 4 KiB, truncated or removed is reported; the newest segment
# growing, or a new segment appearing, is not.
#
#   scripts/test-lifecycle-state.sh
#
# Exit: 0 pass, 1 fail.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lifecycle-state.sh
. "$here/lifecycle-state.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1" >&2; fail=1; }

bb="$work/bb"
setup() {
    rm -rf "$bb" "$work/key"
    mkdir -p "$bb"
    head -c 32 /dev/urandom >"$work/key"
    head -c 20000 /dev/urandom >"$bb/seg-0000000000000001.rbb"
    head -c 20000 /dev/urandom >"$bb/seg-0000000000000002.rbb"
    head -c 6000 /dev/urandom >"$bb/seg-0000000000000003.rbb"
    state_snapshot "$bb" "$work/key" >"$work/before"
}
flip_at() { # file offset: invert one byte
    local b
    b="$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' ')"
    printf '%b' "$(printf '\\0%03o' $(((b ^ 0xff) & 0xff)))" |
        dd of="$1" bs=1 seek="$2" conv=notrunc status=none
}
expect() { # name want(changed|unchanged) [pattern]
    local got
    got="$(state_changed "$work/before")"
    if [[ $2 == unchanged ]]; then
        if [[ -z $got ]]; then ok "$1"; else bad "$1: reported$got"; fi
    else
        if [[ -n $got && $got == *"$3"* ]]; then
            ok "$1"
        else
            bad "$1: reported '${got}', want $3"
        fi
    fi
}

setup
expect "untouched state" unchanged

setup
head -c 9000 /dev/urandom >>"$bb/seg-0000000000000003.rbb"
head -c 100 /dev/urandom >"$bb/seg-0000000000000004.rbb"
expect "newest segment grows, a new one starts" unchanged

setup
flip_at "$bb/seg-0000000000000001.rbb" 10000
expect "sealed segment changed past 4 KiB" changed "seg-0000000000000001.rbb (changed)"

setup
truncate -s 8192 "$bb/seg-0000000000000002.rbb"
expect "sealed segment truncated past 4 KiB" changed "seg-0000000000000002.rbb (changed)"

setup
flip_at "$bb/seg-0000000000000003.rbb" 100
expect "newest segment's head changed" changed "seg-0000000000000003.rbb (first 4 KiB changed)"

setup
rm "$bb/seg-0000000000000001.rbb"
expect "sealed segment removed" changed "seg-0000000000000001.rbb (missing)"

setup
flip_at "$work/key" 0
expect "key changed" changed "key (changed)"

exit "$fail"
