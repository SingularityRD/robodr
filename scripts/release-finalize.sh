#!/usr/bin/env bash
# Everything release.yml does to the build jobs' assets before signing,
# shared by `publish` (real key) and `publish-dry-run` (throwaway key):
#
#   scripts/release-finalize.sh REL_DIR REBUILD_DIR VERSION
#
#  1. Independent rebuild == release (scripts/compare-rebuild.py), recorded
#     in REL_DIR/REPRODUCIBILITY-<version>.txt; nothing is signed on any
#     difference.
#  2. The toolchain inputs every build and rebuild job recorded
#     (TOOLCHAIN-INPUTS-*.txt, scripts/release-toolchain-inputs.sh) are
#     appended to that record; the separate files are not published.
#  3. SBOM gate: the six SBOM archives (robodr, robodr .rpm, robodr-focal;
#     amd64, arm64) must exist and every CycloneDX file in them must pass
#     `metadata_to_cyclonedx.py --check --require-complete` (Rust std, musl,
#     formulation present; a robodr-pulsard SBOM lists its embedded eBPF
#     objects); the robodr and robodr .rpm archives (which ship
#     robodr-pulsard) must contain a robodr-pulsard SBOM, the robodr-focal
#     ones (which do not) must not; and, with ROBODR_CYCLONEDX_CLI set, the
#     official schema validation (`cyclonedx validate --input-version v1_5
#     --fail-on-errors`). Without the CLI the gate fails unless
#     ROBODR_ALLOW_NO_CYCLONEDX_CLI=1 (local dry runs only).
#  4. robodr-<version>.openvex.json (scripts/vex.py, SOURCE_DATE_EPOCH = the
#     commit time).
#  5. robodr-<version>.intoto.jsonl, SLSA v1 provenance of every asset
#     (scripts/slsa-provenance.py; needs the GITHUB_* environment).
#  6. Per-architecture SHA256SUMS-* checked, SHA256SUMS of every asset.
# Run from the repository checkout (the tagged commit).
# Exit: 0 ready to sign, non-zero refused.
set -euo pipefail
rel="${1:?REL_DIR}"
rebuild="${2:?REBUILD_DIR}"
version="${3:?VERSION}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rel="$(cd "$rel" && pwd)"
repro="$rel/REPRODUCIBILITY-$version.txt"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

# 1.
python3 "$here/compare-rebuild.py" --release "$rel" --rebuild "$rebuild" --version "$version" --out "$repro"

# 2.
{
    echo
    echo "Toolchain inputs (scripts/release-toolchain-inputs.sh; build jobs, then independent rebuilds):"
    found=0
    for f in "$rel"/TOOLCHAIN-INPUTS-*.txt "$rebuild"/TOOLCHAIN-INPUTS-*.txt; do
        [[ -f "$f" ]] || continue
        found=1
        echo
        echo "== $(basename "$f")"
        cat "$f"
    done
    [[ $found == 1 ]] || echo "(none recorded)"
} >>"$repro"
grep -q '^== TOOLCHAIN-INPUTS-' "$repro" || { echo "release-finalize: FAIL: no toolchain inputs recorded" >&2; exit 1; }
rm -f "$rel"/TOOLCHAIN-INPUTS-*.txt
cat "$repro"

# 3.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rc=0
n=0
for t in "robodr-$version-amd64" "robodr-$version-arm64" "robodr-$version-rpm-amd64" "robodr-$version-rpm-arm64" \
    "robodr-focal-$version-amd64" "robodr-focal-$version-arm64"; do
    tgz="$rel/$t-sbom.tar.gz"
    if [[ ! -f "$tgz" ]]; then
        echo "release-finalize: FAIL: SBOM archive $t-sbom.tar.gz missing" >&2
        rc=1
        continue
    fi
    mkdir -p "$work/$t"
    tar -xzf "$tgz" -C "$work/$t" --no-same-owner --no-same-permissions
    has_pulsard=0
    if roots="$(python3 "$here/metadata_to_cyclonedx.py" --list-roots "$work/$t")"; then
        if grep -qx robodr-pulsard <<<"$roots"; then has_pulsard=1; fi
    else
        echo "release-finalize: FAIL: $t: cannot read its SBOMs" >&2
        rc=1
    fi
    if [[ "$t" == robodr-focal-* ]]; then
        if [[ $has_pulsard == 1 ]]; then
            echo "release-finalize: FAIL: $t: a robodr-pulsard SBOM, but robodr-focal does not ship robodr-pulsard" >&2
            rc=1
        fi
    elif [[ $has_pulsard == 0 ]]; then
        echo "release-finalize: FAIL: $t: no robodr-pulsard SBOM (its eBPF objects would be unrecorded)" >&2
        rc=1
    fi
    while IFS= read -r -d '' f; do
        n=$((n + 1))
        python3 "$here/metadata_to_cyclonedx.py" --check "$f" --require-complete >/dev/null || {
            echo "release-finalize: FAIL: $t: $(basename "$f") is not a complete release SBOM" >&2
            rc=1
        }
        if [[ -n "${ROBODR_CYCLONEDX_CLI:-}" ]]; then
            "$ROBODR_CYCLONEDX_CLI" validate --input-file "$f" --input-format json --input-version v1_5 --fail-on-errors >/dev/null || {
                echo "release-finalize: FAIL: $t: $(basename "$f") fails CycloneDX 1.5 schema validation" >&2
                rc=1
            }
        fi
    done < <(find "$work/$t" -name '*.cdx.json' -type f -print0)
done
if [[ -z "${ROBODR_CYCLONEDX_CLI:-}" ]]; then
    if [[ "${ROBODR_ALLOW_NO_CYCLONEDX_CLI:-0}" == 1 ]]; then
        echo "release-finalize: WARNING: no cyclonedx-cli: schema validation skipped (ROBODR_ALLOW_NO_CYCLONEDX_CLI=1)" >&2
    else
        echo "release-finalize: FAIL: ROBODR_CYCLONEDX_CLI not set (schema validation is part of the gate)" >&2
        rc=1
    fi
fi
[[ $n -gt 0 ]] || rc=1
[[ $rc == 0 ]] || exit 1
echo "release-finalize: $n SBOM file(s) in 6 archives complete and valid" >&2

# 4.
python3 "$here/vex.py" openvex --version "$version" --out "$rel/robodr-$version.openvex.json"

# 5.
python3 "$here/slsa-provenance.py" generate --assets "$rel" --version "$version" \
    --out "$rel/robodr-$version.intoto.jsonl"

# 6.
cd "$rel"
for a in amd64 arm64 rpm-amd64 rpm-arm64 focal-amd64 focal-arm64; do
    test -s "SHA256SUMS-$a"
    sha256sum --strict -c "SHA256SUMS-$a"
done
rm -f SHA256SUMS ./*.minisig
find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%P\n' | LC_ALL=C sort |
    xargs -r -d '\n' sha256sum >"$work/SHA256SUMS"
mv "$work/SHA256SUMS" SHA256SUMS
cat SHA256SUMS
