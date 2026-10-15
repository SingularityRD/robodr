#!/usr/bin/env bash
# Produce a CycloneDX JSON SBOM for the RoboDR workspace.
#
#   scripts/sbom.sh [OUT_DIR]            (default OUT_DIR: dist/sbom)
#
# Primary: cargo-cyclonedx (one <crate>.cdx.json per workspace crate), when
# installed. Fallback (air-gapped hosts, no cargo-cyclonedx): `cargo metadata`
# piped through scripts/metadata_to_cyclonedx.py (Python 3 std-lib) into one
# robodr.cdx.json for the whole workspace. Either way every produced file is
# checked with `metadata_to_cyclonedx.py --check` (structure, and names,
# versions and SHA-256s against Cargo.lock when one exists), and SHA256SUMS is
# written next to them.
#
# Environment:
#   SBOM_TOOL=auto|cyclonedx|metadata   force a generator (default auto)
#   CARGO="..."                         cargo command (default: cargo), e.g. a
#                                       wrapper such as tools/offline-cargo.sh
#   CARGO_METADATA_ARGS="..."           extra args for cargo metadata, e.g.
#                                       "--offline --locked"
#   CYCLONEDX_ARGS="..."                extra args for cargo cyclonedx
#   SBOM_METADATA_FILE=path             fallback only: convert this existing
#                                       `cargo metadata --format-version 1`
#                                       dump instead of running cargo
#   SOURCE_DATE_EPOCH                   if set, used as the SBOM timestamp
#                                       (fallback generator); otherwise the
#                                       fallback SBOM carries no timestamp.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${1:-dist/sbom}"
tool="${SBOM_TOOL:-auto}"
read -r -a cargo_cmd <<<"${CARGO:-cargo}"
read -r -a meta_args <<<"${CARGO_METADATA_ARGS:-}"
read -r -a cdx_args <<<"${CYCLONEDX_ARGS:-}"
conv="$here/metadata_to_cyclonedx.py"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.cdx.json "$out/SHA256SUMS"

have_cyclonedx() {
    "${cargo_cmd[@]}" cyclonedx --version >/dev/null 2>&1
}

lock_args=()
[[ -f "$root/Cargo.lock" ]] && lock_args=(--lockfile "$root/Cargo.lock")

if [[ "$tool" == auto ]]; then
    if have_cyclonedx; then tool=cyclonedx; else tool=metadata; fi
fi

case "$tool" in
cyclonedx)
    echo "sbom: using cargo-cyclonedx ($("${cargo_cmd[@]}" cyclonedx --version 2>/dev/null || echo '?'))" >&2
    (cd "$root" && "${cargo_cmd[@]}" cyclonedx --format json "${cdx_args[@]}")
    # cargo-cyclonedx writes <name>.cdx.json next to each crate's Cargo.toml.
    found=0
    while IFS= read -r -d '' f; do
        rel="${f#"$root"/}"
        dest="$out/$(echo "$rel" | tr '/' '_')"
        mv "$f" "$dest"
        found=$((found + 1))
    done < <(find "$root" -path "$root/target" -prune -o -path "$root/vendor" -prune \
        -o -path "$out" -prune -o -name '*.cdx.json' -type f -print0)
    if [[ "$found" -eq 0 ]]; then
        echo "sbom: cargo-cyclonedx produced no *.cdx.json files" >&2
        exit 1
    fi
    ;;
metadata)
    echo "sbom: cargo-cyclonedx not used; falling back to cargo metadata + $conv" >&2
    if [[ -n "${SBOM_METADATA_FILE:-}" ]]; then
        meta="$SBOM_METADATA_FILE"
    else
        meta="$(mktemp)"
        trap 'rm -f "$meta"' EXIT
        (cd "$root" && "${cargo_cmd[@]}" metadata --format-version 1 "${meta_args[@]}") >"$meta"
    fi
    version="$(tr -d '[:space:]' <"$root/VERSION" 2>/dev/null || true)"
    ver_args=()
    [[ -n "$version" ]] && ver_args=(--version "$version")
    python3 "$conv" "$meta" "${lock_args[@]}" --name robodr "${ver_args[@]}" -o "$out/robodr.cdx.json"
    ;;
*)
    echo "sbom: unknown SBOM_TOOL=$tool (auto|cyclonedx|metadata)" >&2
    exit 2
    ;;
esac

rc=0
for f in "$out"/*.cdx.json; do
    # Structural check, plus cross-check against Cargo.lock when present.
    python3 "$conv" --check "$f" "${lock_args[@]}" || rc=1
done
(cd "$out" && sha256sum -- *.cdx.json >SHA256SUMS)
echo "sbom: wrote $(find "$out" -name '*.cdx.json' | wc -l) SBOM file(s) to $out" >&2
exit "$rc"
