#!/usr/bin/env bash
# Install rustup in a CI container job (the GitHub runner image has it; the
# Ubuntu 22.04 and Rocky Linux 9 build containers do not), then the
# toolchain of rust-toolchain.toml.
#
#   scripts/ci-install-rustup.sh
#
# rustup-init is pinned by version and SHA-256 per host architecture
# (static.rust-lang.org/rustup/archive/<version>/<triple>/rustup-init.sha256,
# checked 2026-10-30); a mismatch fails before anything runs. The toolchain
# itself comes from rust-toolchain.toml (rustup verifies its downloads).
# Adds ~/.cargo/bin to $GITHUB_PATH when run under Actions.
#
# Exit: 0 installed, 1 failed.
set -euo pipefail

RUSTUP_VERSION=1.29.2
case "$(uname -m)" in
x86_64)
    triple=x86_64-unknown-linux-gnu
    sha=5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4
    ;;
aarch64)
    triple=aarch64-unknown-linux-gnu
    sha=a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697
    ;;
*) echo "ci-install-rustup: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/rustup-init" \
    "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$triple/rustup-init"
echo "$sha  $tmp/rustup-init" | sha256sum --strict -c - >/dev/null || {
    echo "ci-install-rustup: FAIL: rustup-init $RUSTUP_VERSION ($triple) does not match the pinned SHA-256" >&2
    exit 1
}
chmod 0755 "$tmp/rustup-init"
"$tmp/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$cargo_bin" >>"$GITHUB_PATH"
fi
# The pinned toolchain (rust-toolchain.toml at the repository root).
(cd "$here/.." && "$cargo_bin/rustup" toolchain install)
"$cargo_bin/rustc" --version
