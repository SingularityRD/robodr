#!/usr/bin/env bash
# Complete the release SBOMs that scripts/sbom.sh wrote (release.yml build,
# build-rpm, build-static): scripts/metadata_to_cyclonedx.py --augment on
# every *.cdx.json in SBOM_DIR, then SBOM_DIR/SHA256SUMS again.
#
#   scripts/release-sbom-augment.sh SBOM_DIR [EBPF_BUILD_DIR [PULSARD]]
#
#  * target: CARGO_BUILD_TARGET, else TARGET (the musl jobs), else rustc's host;
#  * musl targets: musl and libunwind from the toolchain's rust-std
#    self-contained directory, with the archives' SHA-256;
#  * EBPF_BUILD_DIR (e.g. target/release/build, after the release build): the
#    *.bpf.o objects Pulsar's build scripts compiled there that the built
#    PULSARD (default EBPF_BUILD_DIR/../robodr-pulsard) embeds byte for byte
#    go into robodr-pulsard's SBOM(s), version = vendor/pulsar's; stale or
#    duplicate build output is left out, and an eBPF object in PULSARD that
#    no *.bpf.o accounts for is refused. There must be at least one such
#    SBOM and one embedded object;
#  * without EBPF_BUILD_DIR, a robodr-pulsard SBOM in SBOM_DIR is refused
#    (it would lack the eBPF objects): remove it first when the build does
#    not ship robodr-pulsard;
#  * formulation: rustc, cargo, cargo-cyclonedx, the pinned C compiler
#    (scripts/c-toolchain.sh) and, with EBPF_BUILD_DIR, the eBPF clang.
# Exit: 0 every SBOM augmented and complete, non-zero otherwise.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
dir="${1:?SBOM_DIR}"
ebpf="${2:-}"
pulsard_bin="${3:-${ebpf:+$(dirname "$ebpf")/robodr-pulsard}}"
conv="$here/metadata_to_cyclonedx.py"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rustc -vV >"$work/rustc-vV"
target="${CARGO_BUILD_TARGET:-${TARGET:-$(sed -n 's/^host: //p' "$work/rustc-vV")}}"
# shellcheck source=scripts/c-toolchain.sh disable=SC1091
. "$here/c-toolchain.sh"
tools=(--tool "cargo=$(cargo -V | cut -d' ' -f2-)"
    --tool "c-compiler=$ROBODR_CLANG $ROBODR_CLANG_VERSION (scripts/c-toolchain.sh, $(robodr_build_userland))")
if v="$(cargo cyclonedx --version 2>/dev/null)"; then tools+=(--tool "cargo-cyclonedx=${v##* }"); fi
args=(--rustc-vv "$work/rustc-vV" --target "$target")
if [[ "$target" == *-musl ]]; then
    args+=(--self-contained-dir "$(rustc --print sysroot)/lib/rustlib/$target/lib/self-contained")
fi

mapfile -t all < <(find "$dir" -maxdepth 1 -name '*.cdx.json' -type f | LC_ALL=C sort)
[[ ${#all[@]} -gt 0 ]] || { echo "release-sbom-augment: no *.cdx.json in $dir" >&2; exit 1; }
pulsard=() rest=()
for f in "${all[@]}"; do
    case "$(basename "$f")" in *robodr-pulsard*) pulsard+=("$f") ;; *) rest+=("$f") ;; esac
done

if [[ -n "$ebpf" ]]; then
    [[ ${#pulsard[@]} -gt 0 ]] || { echo "release-sbom-augment: no robodr-pulsard SBOM in $dir for the eBPF objects" >&2; exit 1; }
    [[ -f "$pulsard_bin" ]] || { echo "release-sbom-augment: no built robodr-pulsard at $pulsard_bin" >&2; exit 1; }
    # Pulsar's [package] version is `version.workspace = true`.
    pulsar_version="$(python3 -c '
import sys, tomllib
t = tomllib.load(open(sys.argv[1], "rb"))
v = t.get("package", {}).get("version")
if not isinstance(v, str):
    v = t["workspace"]["package"]["version"]
print(v)' "$root/vendor/pulsar/Cargo.toml")"
    [[ "$pulsar_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || { echo "release-sbom-augment: bad Pulsar version '$pulsar_version'" >&2; exit 1; }
    ebpf_cc="$({ clang-20 --version 2>/dev/null || clang --version 2>/dev/null; } | head -n1)"
    python3 "$conv" --augment "${pulsard[@]}" "${args[@]}" "${tools[@]}" --tool "ebpf-clang=${ebpf_cc:-unknown}" \
        --ebpf-dir "$ebpf" --ebpf-embedded-in "$pulsard_bin" --ebpf-version "$pulsar_version"
    [[ ${#rest[@]} -eq 0 ]] || python3 "$conv" --augment "${rest[@]}" "${args[@]}" "${tools[@]}"
else
    [[ ${#pulsard[@]} -eq 0 ]] || {
        echo "release-sbom-augment: ${pulsard[*]}: a robodr-pulsard SBOM needs EBPF_BUILD_DIR (remove it if robodr-pulsard is not shipped)" >&2
        exit 1
    }
    python3 "$conv" --augment "${all[@]}" "${args[@]}" "${tools[@]}"
fi
for f in "${all[@]}"; do
    python3 "$conv" --check "$f" --require-complete >/dev/null
done
(cd "$dir" && sha256sum -- *.cdx.json >"$work/SHA256SUMS" && mv "$work/SHA256SUMS" SHA256SUMS)
echo "release-sbom-augment: ${#all[@]} SBOM(s) for $target augmented and complete" >&2
