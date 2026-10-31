#!/usr/bin/env bash
# minisign every release asset in DIR and verify the signatures with the
# public key, as release.yml `publish` (real key, from the `release`
# environment) and `publish-dry-run` (throwaway key) do.
#
#   MINISIGN_SECRET_KEY=<key file contents> [MINISIGN_PASSWORD=...] \
#       scripts/release-sign.sh DIR VERSION PUBKEY
#
# PUBKEY is the public key string (RW...). Every file but *.minisig gets
# DIR/<file>.minisig with the trusted comment "robodr <version> <file>"
# (install-bundle.sh and build-pkg-repo.sh check it). The secret key is
# written to a 0600 file under RUNNER_TEMP (or TMPDIR) and shredded on exit.
# Exit: 0 signed and verified, 1 failed.
set -euo pipefail
dir="${1:?DIR}"
version="${2:?VERSION}"
pubkey="${3:?PUBKEY}"
test -n "${MINISIGN_SECRET_KEY:-}" || { echo "::error::MINISIGN_SECRET_KEY is not set"; exit 1; }
test -n "$pubkey" || { echo "::error::public key is empty"; exit 1; }
cd "$dir"
umask 077
key="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/minisign.XXXXXX")"
trap 'shred -u "$key" 2>/dev/null || rm -f "$key"' EXIT
printf '%s\n' "$MINISIGN_SECRET_KEY" >"$key"
mapfile -t files < <(find . -maxdepth 1 -type f ! -name '*.minisig' -printf '%P\n' | LC_ALL=C sort)
[ "${#files[@]}" -gt 0 ] || { echo "::error::no assets in $dir"; exit 1; }
for f in "${files[@]}"; do
    if [ -n "${MINISIGN_PASSWORD:-}" ]; then
        printf '%s\n' "$MINISIGN_PASSWORD" | minisign -S -s "$key" -m "$f" -t "robodr $version $f"
    else
        minisign -S -s "$key" -m "$f" -t "robodr $version $f" </dev/null
    fi
done
for f in "${files[@]}"; do
    minisign -V -q -P "$pubkey" -m "$f"
    grep -qx "trusted comment: robodr $version $f" "$f.minisig"
done
echo "release-sign: $(find . -maxdepth 1 -name '*.minisig' | wc -l) signatures written and verified" >&2
