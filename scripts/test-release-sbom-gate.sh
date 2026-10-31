#!/usr/bin/env bash
# Tests of scripts/release-sbom-gate.sh (the SBOM gate of release-finalize.sh).
#
#   scripts/test-release-sbom-gate.sh
#
# Builds the six SBOM archives a release carries from complete fixture SBOMs
# (scripts/metadata_to_cyclonedx.py convert + augment, as
# release-sbom-augment.sh does) and checks that the gate passes them and
# refuses: a robodr-focal archive with a robodr-pulsard SBOM, a robodr or
# .rpm archive without one, a robodr-pulsard SBOM without its eBPF objects,
# a missing archive, an SBOM that was not augmented, and a run without
# cyclonedx-cli unless ROBODR_ALLOW_NO_CYCLONEDX_CLI=1.
#
# Exit: 0 pass, 1 fail.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="$here/release-sbom-gate.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
v=9.9.9
fail=0
ok() { echo "PASS $1"; }
bad() {
    echo "FAIL $1" >&2
    fail=1
}

# fixture DIR [ROOT[:plain|:noebpf] ...]: write one SBOM per root into DIR.
fixture() {
    python3 - "$here" "$@" <<'EOF'
import importlib.util, json, os, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("m2c", os.path.join(sys.argv[1], "metadata_to_cyclonedx.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
rustc = m.parse_rustc_vv(
    "rustc 1.98.1 (48a229cea 2026-09-01)\nbinary: rustc\n"
    "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\ncommit-date: 2026-09-01\n"
    "host: x86_64-unknown-linux-gnu\nrelease: 1.98.1\nLLVM version: 22.1.8\n")
out = sys.argv[2]
os.makedirs(out, exist_ok=True)
for spec_ in sys.argv[3:]:
    root, _, mode = spec_.partition(":")
    bom = m.convert(m._fixture(), root_name=root)
    if mode != "plain":
        ebpf = [("p/out/probes.bpf.o", b"BPF1")] if root == "robodr-pulsard" and mode != "noebpf" else None
        bom = m.augment(bom, rustc, "x86_64-unknown-linux-gnu", ebpf=ebpf,
                        ebpf_version="0.11.0" if ebpf else None, tools=[("cargo", "1.98.1")])
    with open(os.path.join(out, f"crates_{root}_{root}.cdx.json"), "w") as f:
        json.dump(bom, f)
EOF
}

# release DIR FOCAL_ROOTS STD_ROOTS: the six archives under DIR.
release() {
    local dir="$1" focal="$2" std="$3" t roots
    rm -rf "$dir" "$work/src"
    mkdir -p "$dir"
    for t in "robodr-$v-amd64" "robodr-$v-arm64" "robodr-$v-rpm-amd64" "robodr-$v-rpm-arm64" \
        "robodr-focal-$v-amd64" "robodr-focal-$v-arm64"; do
        case "$t" in robodr-focal-*) roots="$focal" ;; *) roots="$std" ;; esac
        # shellcheck disable=SC2086 # word splitting intended: one root per word
        fixture "$work/src/$t/sbom" $roots
        tar -C "$work/src/$t" -czf "$dir/$t-sbom.tar.gz" sbom
    done
}

run() { # expect(pass|fail) name dir [env...]
    local want="$1" name="$2" dir="$3" got
    shift 3
    if env "$@" "$gate" "$dir" "$v" >"$work/out" 2>&1; then got=pass; else got=fail; fi
    if [[ "$got" == "$want" ]]; then ok "$name"; else
        bad "$name (want $want, got $got)"
        sed 's/^/    /' "$work/out" >&2
    fi
}

std="robodr-agentd robodr-pulsard robodr-ocsf"
focal="robodr-agentd robodr-ocsf"
nocli=(-u ROBODR_CYCLONEDX_CLI ROBODR_ALLOW_NO_CYCLONEDX_CLI=1)

release "$work/good" "$focal" "$std"
run pass "six complete archives pass" "$work/good" "${nocli[@]}"
run fail "no cyclonedx-cli and no opt-out" "$work/good" -u ROBODR_CYCLONEDX_CLI -u ROBODR_ALLOW_NO_CYCLONEDX_CLI
printf '#!/bin/sh\nexit 0\n' >"$work/cli-ok" && chmod +x "$work/cli-ok"
printf '#!/bin/sh\nexit 1\n' >"$work/cli-bad" && chmod +x "$work/cli-bad"
run pass "cyclonedx-cli validates" "$work/good" ROBODR_CYCLONEDX_CLI="$work/cli-ok"
run fail "cyclonedx-cli rejects" "$work/good" ROBODR_CYCLONEDX_CLI="$work/cli-bad"

release "$work/focal-pulsard" "$std" "$std"
run fail "robodr-focal archive with a robodr-pulsard SBOM" "$work/focal-pulsard" "${nocli[@]}"
if grep -q "robodr-focal does not ship robodr-pulsard" "$work/out"; then ok "  ... named"; else bad "  ... not named"; cat "$work/out" >&2; fi

release "$work/std-no-pulsard" "$focal" "$focal"
run fail "robodr / .rpm archives without a robodr-pulsard SBOM" "$work/std-no-pulsard" "${nocli[@]}"
if grep -q "no robodr-pulsard SBOM" "$work/out"; then ok "  ... named"; else bad "  ... not named"; cat "$work/out" >&2; fi

release "$work/noebpf" "$focal" "robodr-agentd robodr-pulsard:noebpf"
run fail "robodr-pulsard SBOM without eBPF objects" "$work/noebpf" "${nocli[@]}"

release "$work/plain" "robodr-agentd:plain" "$std"
run fail "an SBOM that was not augmented" "$work/plain" "${nocli[@]}"

release "$work/missing" "$focal" "$std"
rm "$work/missing/robodr-focal-$v-arm64-sbom.tar.gz"
run fail "a missing archive" "$work/missing" "${nocli[@]}"

[[ $fail == 0 ]] && echo "test-release-sbom-gate: all passed"
exit "$fail"
