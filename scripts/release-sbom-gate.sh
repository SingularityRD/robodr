#!/usr/bin/env bash
# The SBOM gate of scripts/release-finalize.sh (step 3), run before anything
# is signed:
#
#   scripts/release-sbom-gate.sh REL_DIR VERSION
#
# The six SBOM archives (robodr, robodr .rpm, robodr-focal; amd64, arm64)
# must exist in REL_DIR and every CycloneDX file in them must pass
# `metadata_to_cyclonedx.py --check --require-complete` (Rust std, musl,
# formulation present; a robodr-pulsard SBOM lists its embedded eBPF
# objects); the robodr and robodr .rpm archives (which ship robodr-pulsard)
# must contain a robodr-pulsard SBOM, the robodr-focal ones (which do not)
# must not; and, with ROBODR_CYCLONEDX_CLI set, the official schema
# validation (`cyclonedx validate --input-version v1_5 --fail-on-errors`).
# Without the CLI the gate fails unless ROBODR_ALLOW_NO_CYCLONEDX_CLI=1
# (local dry runs and scripts/test-release-sbom-gate.sh only).
# Tested by scripts/test-release-sbom-gate.sh.
# Exit: 0 passed, 1 refused, 2 usage.
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: $0 REL_DIR VERSION" >&2; exit 2; }
rel="$(cd "$1" && pwd)"
version="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rc=0
n=0
for t in "robodr-$version-amd64" "robodr-$version-arm64" "robodr-$version-rpm-amd64" "robodr-$version-rpm-arm64" \
    "robodr-focal-$version-amd64" "robodr-focal-$version-arm64"; do
    tgz="$rel/$t-sbom.tar.gz"
    if [[ ! -f "$tgz" ]]; then
        echo "release-sbom-gate: FAIL: SBOM archive $t-sbom.tar.gz missing" >&2
        rc=1
        continue
    fi
    mkdir -p "$work/$t"
    tar -xzf "$tgz" -C "$work/$t" --no-same-owner --no-same-permissions
    has_pulsard=0
    if roots="$(python3 "$here/metadata_to_cyclonedx.py" --list-roots "$work/$t")"; then
        if grep -qx robodr-pulsard <<<"$roots"; then has_pulsard=1; fi
    else
        echo "release-sbom-gate: FAIL: $t: cannot read its SBOMs" >&2
        rc=1
    fi
    if [[ "$t" == robodr-focal-* ]]; then
        if [[ $has_pulsard == 1 ]]; then
            echo "release-sbom-gate: FAIL: $t: a robodr-pulsard SBOM, but robodr-focal does not ship robodr-pulsard" >&2
            rc=1
        fi
    elif [[ $has_pulsard == 0 ]]; then
        echo "release-sbom-gate: FAIL: $t: no robodr-pulsard SBOM (its eBPF objects would be unrecorded)" >&2
        rc=1
    fi
    while IFS= read -r -d '' f; do
        n=$((n + 1))
        python3 "$here/metadata_to_cyclonedx.py" --check "$f" --require-complete >/dev/null || {
            echo "release-sbom-gate: FAIL: $t: $(basename "$f") is not a complete release SBOM" >&2
            rc=1
        }
        if [[ -n "${ROBODR_CYCLONEDX_CLI:-}" ]]; then
            "$ROBODR_CYCLONEDX_CLI" validate --input-file "$f" --input-format json --input-version v1_5 --fail-on-errors >/dev/null || {
                echo "release-sbom-gate: FAIL: $t: $(basename "$f") fails CycloneDX 1.5 schema validation" >&2
                rc=1
            }
        fi
    done < <(find "$work/$t" -name '*.cdx.json' -type f -print0)
done
if [[ -z "${ROBODR_CYCLONEDX_CLI:-}" ]]; then
    if [[ "${ROBODR_ALLOW_NO_CYCLONEDX_CLI:-0}" == 1 ]]; then
        echo "release-sbom-gate: WARNING: no cyclonedx-cli: schema validation skipped (ROBODR_ALLOW_NO_CYCLONEDX_CLI=1)" >&2
    else
        echo "release-sbom-gate: FAIL: ROBODR_CYCLONEDX_CLI not set (schema validation is part of the gate)" >&2
        rc=1
    fi
fi
[[ $n -gt 0 ]] || rc=1
[[ $rc == 0 ]] || exit 1
echo "release-sbom-gate: $n SBOM file(s) in 6 archives complete and valid" >&2
