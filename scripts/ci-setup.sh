#!/usr/bin/env bash
# Common CI job setup. Run after checkout and `rustup toolchain install`.
#
#  * If ROBODR_CRATES_MIRROR is set (e.g. from the repository variable of the
#    same name on a self-hosted, air-gapped runner), write a CARGO_HOME config
#    that replaces crates.io with that sparse index, so the job never reaches
#    the public registry.
#  * Export, via $GITHUB_ENV when present (else print):
#      CARGO_LOCKED   "--locked" when Cargo.lock is committed, else empty
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
[[ -f Cargo.lock ]] && locked="--locked"
excludes="$(cargo metadata --no-deps --format-version 1 | python3 "$here/ci-pure-excludes.py" -)"

emit() {
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        printf '%s=%s\n' "$1" "$2" >>"$GITHUB_ENV"
    fi
    printf '%s=%s\n' "$1" "$2"
}
emit CARGO_LOCKED "$locked"
emit PURE_EXCLUDES "$excludes"
