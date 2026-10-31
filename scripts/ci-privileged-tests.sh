#!/usr/bin/env bash
# The tests that need root, a software TPM, network namespaces, nftables or
# CAP_NET_RAW, run for real: none of them may skip itself (T24 of
# docs/SALES-READINESS.md). Used by the `privileged` job of
# .github/workflows/ci-extended.yml; runs the same on a developer machine
# with sudo (or as root).
#
#   scripts/ci-privileged-tests.sh [--list] [--only <package>] [LOG_DIR]
#
# Each test binary is built as the invoking user (so no root-owned files land
# in target/), then run as root with --nocapture and the variables that turn
# a missing environment from a printed skip into a failure:
#
#   ROBODR_SWTPM=1              swtpm + tpm2-tools (seal, depot, deliverd,
#                               blackbox, agentd TPM tests)
#   ROBODR_SEAL_DM=1            loop devices + dm-crypt (seal runtime volume)
#   ROBODR_TANG=1               tangd + clevis + cryptsetup (seal Tang fallback)
#   ROBODR_REQUIRE_NETNS=1      executor nftables tests in network namespaces
#   ROBODR_REQUIRE_DPKG_TEST=1  deliverd install kinds against the real dpkg
#
# Every log is then checked by scripts/ci-no-skips.py: a "skipped" line, a
# binary that ran no test, or a failed test fails the script. The logs are
# kept in LOG_DIR (default: target/privileged-logs) for the CI artefact.
#
# Environment: CARGO_LOCKED (from scripts/ci-setup.sh);
# ROBODR_PRIV_WITHOUT="dm tang" leaves out ROBODR_SEAL_DM (no loop devices
# or dm-crypt, e.g. a container) and/or ROBODR_TANG (no tangd / clevis):
# exactly those tests' skip lines are then allowed, every other skip still
# fails. CI sets neither.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

# package | test target | extra arguments to the test binary
#
# Deliberately not listed: robodr-depot `soak_binaries` (#[ignore], needs
# ROBODR_SWTPM=1 and the release robodr-deliverd binary). It is a long soak
# of N lease-gated rollouts through the real binaries, run by hand as its
# module docs say, not a per-push check.
SPECS=(
    "robodr-seal|swtpm_harness|"
    "robodr-seal|adversarial|"
    "robodr-seal|cli|"
    "robodr-seal|exit_criteria|"
    "robodr-seal|lease_14b|"
    "robodr-seal|review_13c|"
    "robodr-depot|adversarial_14a|"
    "robodr-depot|exit_14a|"
    "robodr-depot|exit_14b|"
    "robodr-blackbox|tpm_anchor|"
    "robodr-agentd|tpm_head_anchor|"
    "robodr-deliverd|sealed|"
    "robodr-deliverd|kinds|"
    "robodr-deliverd|review_13b|"
    "robodr-deliverd|review2_13b|"
    "robodr-deliverd|review3_13b|"
    "robodr-executor|netns|--test-threads=1"
    "robodr-firewall-gw|netns_e2e|--ignored --test-threads=1"
    "robodr-capture|live_afpacket|"
    "robodr-ros2-pipeline|live_capture|"
)

list=0
only=""
logdir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
    --list) list=1 ;;
    --only)
        only="${2:?--only needs a package}"
        shift
        ;;
    -h | --help)
        sed -n '2,27p' "$0"
        exit 0
        ;;
    -*)
        echo "ci-privileged-tests: unknown option $1" >&2
        exit 2
        ;;
    *) logdir="$1" ;;
    esac
    shift
done
logdir="${logdir:-$root/target/privileged-logs}"

if [[ "$list" == 1 ]]; then
    printf '%s\n' "${SPECS[@]}"
    exit 0
fi

if [[ "$(id -u)" == 0 ]]; then
    as_root=()
else
    as_root=(sudo)
fi

mkdir -p "$logdir"
read -r -a locked <<<"${CARGO_LOCKED:-}"

# The executable of one integration test target (built here, as this user).
build_test() {
    local pkg="$1" t="$2"
    cargo test -p "$pkg" --test "$t" "${locked[@]}" --no-run --message-format=json |
        python3 -c '
import json, sys
want = sys.argv[1]
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
            and m["target"]["name"] == want and "test" in m["target"]["kind"]:
        print(m["executable"])
' "$t"
}

tmp="${ROBODR_PRIV_TMPDIR:-$(mktemp -d /var/tmp/robodr-priv.XXXXXX)}"
without=" ${ROBODR_PRIV_WITHOUT:-} "
allowed=()
env_vars=(
    ROBODR_SWTPM=1
    ROBODR_REQUIRE_NETNS=1
    ROBODR_REQUIRE_DPKG_TEST=1
    RUST_BACKTRACE=1
    # Short (unix socket paths are limited to 108 bytes) and disk-backed,
    # so the "TPM work directory must be tmpfs" test has a disk directory
    # to refuse.
    TMPDIR="$tmp"
)
if [[ "$without" == *" dm "* ]]; then
    allowed+=(--allow '^runtime_volume_dm: skipped: set ROBODR_SEAL_DM=1')
else
    env_vars+=(ROBODR_SEAL_DM=1)
fi
if [[ "$without" == *" tang "* ]]; then
    allowed+=(--allow '^fallback_tang: skipped: set ROBODR_TANG=1')
else
    env_vars+=(ROBODR_TANG=1)
fi
mkdir -p "$tmp"
chmod 1777 "$tmp"

failed=()
ran=0
for spec in "${SPECS[@]}"; do
    IFS='|' read -r pkg t extra <<<"$spec"
    if [[ -n "$only" && "$pkg" != "$only" ]]; then
        continue
    fi
    echo "::group::$pkg --test $t $extra"
    exe="$(build_test "$pkg" "$t" | tail -n 1)"
    if [[ -z "$exe" || ! -x "$exe" ]]; then
        echo "::error::ci-privileged-tests: no test executable for $pkg --test $t"
        failed+=("$pkg/$t (build)")
        echo "::endgroup::"
        continue
    fi
    log="$logdir/$pkg-$t.log"
    read -r -a extra_args <<<"$extra"
    # The binary runs from the package directory, as `cargo test` would.
    set +e
    (cd "crates/$pkg" && "${as_root[@]}" env "${env_vars[@]}" "$exe" --nocapture "${extra_args[@]}") 2>&1 | tee "$log"
    status="${PIPESTATUS[0]}"
    set -e
    ran=$((ran + 1))
    check=(python3 "$here/ci-no-skips.py" "${allowed[@]}")
    if [[ " ${extra_args[*]} " == *" --ignored "* ]]; then
        check+=(--ignored-run)
    fi
    if [[ "$status" != 0 ]] || ! "${check[@]}" "$log"; then
        failed+=("$pkg/$t")
    fi
    echo "::endgroup::"
done

# Root-owned leftovers in target/ would break the next (cached) build.
"${as_root[@]}" chown -R "$(id -u):$(id -g)" "$logdir" 2>/dev/null || true
if [[ -z "${ROBODR_PRIV_TMPDIR:-}" ]]; then
    "${as_root[@]}" rm -rf "$tmp"
fi

if [[ "$ran" == 0 ]]; then
    echo "::error::ci-privileged-tests: no test target selected"
    exit 1
fi
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "::error::ci-privileged-tests: ${#failed[@]} target(s) failed or skipped: ${failed[*]}"
    exit 1
fi
echo "ci-privileged-tests: $ran target(s) ran, none skipped"
