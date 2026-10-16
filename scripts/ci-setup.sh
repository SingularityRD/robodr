#!/usr/bin/env bash
# Common CI job setup. Run after checkout and `rustup toolchain install`.
#
#  * If ROBODR_CRATES_MIRROR is set (e.g. from the repository variable of the
#    same name on a self-hosted, air-gapped runner), write a CARGO_HOME config
#    that replaces crates.io with that sparse index, so the job never reaches
#    the public registry.
#  * Require a committed Cargo.lock (docs/BUILD.md "Cargo.lock policy"). If it
#    is missing the job FAILS, unless ROBODR_ALLOW_MISSING_LOCK=1 (set only by
#    the `lockfile` job, which generates the bootstrap lock and then fails).
#  * Export, via $GITHUB_ENV when present (else print):
#      CARGO_LOCKED   "--locked" (empty only under ROBODR_ALLOW_MISSING_LOCK=1)
#      PURE_EXCLUDES  "--exclude <pkg> ..." for Pulsar-bound members
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

if [[ -n "${ROBODR_CRATES_MIRROR:-}" ]]; then
    case "$ROBODR_CRATES_MIRROR" in
    sparse+https://*) ;;
    *)
        echo "ci-setup: ROBODR_CRATES_MIRROR must be a sparse+https:// index URL" >&2
        exit 1
        ;;
    esac
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    mkdir -p "$cargo_home"
    cat >>"$cargo_home/config.toml" <<EOF

[source.crates-io]
replace-with = "internal"

[source.internal]
registry = "$ROBODR_CRATES_MIRROR"
EOF
    echo "ci-setup: crates.io replaced by $ROBODR_CRATES_MIRROR" >&2
fi

locked=""
if [[ -f Cargo.lock ]]; then
    locked="--locked"
elif [[ "${ROBODR_ALLOW_MISSING_LOCK:-0}" == 1 ]]; then
    echo "ci-setup: no Cargo.lock (allowed for this job only: ROBODR_ALLOW_MISSING_LOCK=1)" >&2
else
    echo "ci-setup: Cargo.lock is not committed; refusing to build with an unpinned resolution." >&2
    echo "ci-setup: bootstrap it from the 'Cargo.lock-generated' artifact of the lockfile job (docs/BUILD.md)." >&2
    [[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::error file=Cargo.lock::Cargo.lock is not committed (docs/BUILD.md, Cargo.lock policy)"
    exit 1
fi
# --no-deps metadata needs no registry access; with --locked it also refuses
# to rewrite a stale lock.
# shellcheck disable=SC2086 # $locked is empty or one flag
excludes="$(cargo metadata --no-deps --format-version 1 $locked | python3 "$here/ci-pure-excludes.py" -)"

emit() {
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        printf '%s=%s\n' "$1" "$2" >>"$GITHUB_ENV"
    fi
    printf '%s=%s\n' "$1" "$2"
}
emit CARGO_LOCKED "$locked"
emit PURE_EXCLUDES "$excludes"
