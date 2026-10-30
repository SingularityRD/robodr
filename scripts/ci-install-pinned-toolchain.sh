#!/usr/bin/env bash
# Install the Rust toolchain of rust-toolchain.toml from hash-pinned
# artifacts, without rustup (release.yml, the independent rebuild jobs).
#
#   scripts/ci-install-pinned-toolchain.sh PREFIX [TARGET...]
#
# The channel manifest (static.rust-lang.org/dist/channel-rust-<v>.toml) is
# pinned here by SHA-256 per toolchain version; every component tarball
# (rustc, cargo, rust-std for the host and for each TARGET) is then checked
# against the SHA-256 that this pinned manifest lists before it is unpacked
# and installed into PREFIX with its own install.sh. Nothing is taken on
# trust from the download server, and nothing goes through rustup, so the
# rebuild does not share the release build's toolchain installation path.
# A toolchain without a pinned manifest hash fails (add it here after
# checking the manifest out of band: its .sha256 next to it on
# static.rust-lang.org, and the GPG signature channel-rust-<v>.toml.asc).
#
# Under GitHub Actions PREFIX/bin goes to $GITHUB_PATH and RUSTC, CARGO and
# RUSTDOC to $GITHUB_ENV, so later steps use exactly this toolchain.
#
# ROBODR_TOOLCHAIN_DRY_RUN=1: check the pinned manifest and print each
# component's URL and SHA-256, download and install nothing else.
#
# Exit: 0 installed, 1 a hash did not match or a download failed, 2 usage.
set -euo pipefail

declare -A MANIFEST_SHA256=(
    # channel-rust-1.98.1.toml (dist date 2026-09-03), checked 2026-10-30.
    ["1.98.1"]=a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e
)

[[ $# -ge 1 ]] || { echo "usage: $0 PREFIX [TARGET...]" >&2; exit 2; }
prefix="$1"
shift
targets=("$@")
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
channel="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$here/../rust-toolchain.toml")"
want="${MANIFEST_SHA256[$channel]:-}"
if [[ -z "$want" ]]; then
    echo "ci-install-pinned-toolchain: no pinned manifest SHA-256 for Rust '$channel' (add it to MANIFEST_SHA256)" >&2
    exit 1
fi
case "$(uname -m)" in
x86_64) host=x86_64-unknown-linux-gnu ;;
aarch64) host=aarch64-unknown-linux-gnu ;;
*) echo "ci-install-pinned-toolchain: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fetch() { # url out
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
}
check() { # sha file what
    if ! echo "$1  $2" | sha256sum --strict -c - >/dev/null; then
        echo "ci-install-pinned-toolchain: FAIL: $3 does not match its pinned SHA-256 $1" >&2
        exit 1
    fi
}

manifest="$tmp/channel-rust-$channel.toml"
fetch "https://static.rust-lang.org/dist/channel-rust-$channel.toml" "$manifest"
check "$want" "$manifest" "channel-rust-$channel.toml"

# url and hash (gzip tarball) of [pkg.<component>.target.<triple>].
component() { # component triple -> "url hash"
    awk -v sect="[pkg.$1.target.$2]" '
        $0 == sect { on = 1; next }
        on && /^\[/ { exit }
        on && $1 == "available" && $3 != "true" { print "unavailable"; exit }
        on && $1 == "url" { gsub(/"/, "", $3); u = $3 }
        on && $1 == "hash" { gsub(/"/, "", $3); h = $3 }
        END { if (u != "" && h != "") print u, h }
    ' "$manifest"
}

install_component() { # component triple
    local spec url sha name
    spec="$(component "$1" "$2")"
    if [[ -z "$spec" || "$spec" == unavailable ]]; then
        echo "ci-install-pinned-toolchain: $1 for $2 is not in the Rust $channel manifest" >&2
        exit 1
    fi
    read -r url sha <<<"$spec"
    case "$url" in https://static.rust-lang.org/dist/*) ;; *) echo "ci-install-pinned-toolchain: unexpected URL $url" >&2; exit 1 ;; esac
    if [[ "${ROBODR_TOOLCHAIN_DRY_RUN:-0}" == 1 ]]; then
        echo "ci-install-pinned-toolchain: would install $url ($sha)"
        return 0
    fi
    name="$(basename "$url" .tar.gz)"
    fetch "$url" "$tmp/$name.tar.gz"
    check "$sha" "$tmp/$name.tar.gz" "$name.tar.gz"
    tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
    "$tmp/$name/install.sh" --prefix="$prefix" --disable-ldconfig >/dev/null
    rm -rf "${tmp:?}/$name" "$tmp/$name.tar.gz"
    echo "ci-install-pinned-toolchain: $name ($sha)"
}

mkdir -p "$prefix"
install_component rustc "$host"
install_component cargo "$host"
install_component rust-std "$host"
for t in "${targets[@]}"; do
    [[ "$t" == "$host" ]] || install_component rust-std "$t"
done
[[ "${ROBODR_TOOLCHAIN_DRY_RUN:-0}" != 1 ]] || exit 0
"$prefix/bin/rustc" -vV
"$prefix/bin/cargo" -V
if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$prefix/bin" >>"$GITHUB_PATH"
    {
        echo "RUSTC=$prefix/bin/rustc"
        echo "RUSTDOC=$prefix/bin/rustdoc"
        echo "CARGO=$prefix/bin/cargo"
    } >>"$GITHUB_ENV"
fi
