#!/bin/sh
# Integration test of the black box's TPM 2.0 NV counter head anchor against
# a software TPM: the recorder runs through marks on a real NV counter, the
# log tail and every state file (head.json, checkpoint.json, the sidecar) are
# rolled back, and the reopen must report TruncationDetected; then
# robodr-agentd runs with `head_anchor.kind = tpm_nv_counter`.
#
# Needs swtpm and tpm2-tools 5.x (Debian: apt install swtpm tpm2-tools).
# Each test starts its own swtpm on a free-looking TCP port (override the
# base with ROBODR_SWTPM_PORT) with its state in a temp directory.
#
# Usage: scripts/swtpm-anchor-it.sh [extra cargo test args]
set -eu

for t in swtpm tpm2_nvdefine tpm2_nvincrement tpm2_nvread tpm2_nvreadpublic; do
    command -v "$t" >/dev/null 2>&1 || {
        echo "swtpm-anchor-it: $t not found (apt install swtpm tpm2-tools)" >&2
        exit 2
    }
done
if [ -z "${ROBODR_TPM2_TOOLS_DIR:-}" ]; then
    ROBODR_TPM2_TOOLS_DIR=$(dirname "$(command -v tpm2_nvincrement)")
    export ROBODR_TPM2_TOOLS_DIR
fi

cd "$(dirname "$0")/.."
export ROBODR_SWTPM=1
cargo test -p robodr-blackbox --test tpm_anchor "$@" -- --nocapture --test-threads=1
cargo test -p robodr-agentd --test tpm_head_anchor "$@" -- --nocapture --test-threads=1
echo "swtpm-anchor-it: OK"
