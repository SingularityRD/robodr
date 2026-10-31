#!/bin/bash
# Checks entrypoint_cyclone.sh's wheel pinning without Docker or network:
# python3 is a stub that records its arguments, /wheels is a temp dir
# (ROBODR_PEER_WHEELS_DIR).
#   tools/e2e/ros2-peer/test_entrypoint_cyclone.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/wheels"
printf '#!/bin/sh\necho "$*" >>"%s/python3.log"\n' "$t" >"$t/bin/python3"
chmod +x "$t/bin/python3"
name=cyclonedds-0.10.5-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
fail=0
# run EXPECTED_EXIT EXPECTED_TEXT LABEL
run() {
  : >"$t/python3.log"
  out="$(PATH="$t/bin:$PATH" ROBODR_PEER_WHEELS_DIR="$t/wheels" \
    bash "$here/entrypoint_cyclone.sh" 2>&1)"
  rc=$?
  seen="$out $(cat "$t/python3.log")"
  if [ "$rc" != "$1" ] || ! grep -q -- "$2" <<<"$seen"; then
    echo "FAIL ($3): exit $rc, wanted $1 and '$2'; output and python3 calls: $seen"
    fail=1
  else
    echo "ok   ($3)"
  fi
}
# No local wheel: pip with the pinned hash, then the peer.
run 0 "require-hashes" "no local wheel: PyPI with the pinned hash"
# A cyclonedds wheel under another name is refused, not silently ignored.
echo junk >"$t/wheels/cyclonedds-0.10.5-cp310-cp310-linux_x86_64.whl"
run 1 "not the pinned wheel" "a wheel under another name is refused"
if grep -q . "$t/python3.log"; then
  echo "FAIL: python3 ran although the wheel was refused"
  fail=1
fi
rm "$t/wheels/"*.whl
# The pinned name with another hash is refused.
echo junk >"$t/wheels/$name"
run 1 "sha256 differs" "the pinned name with another hash is refused"
exit "$fail"
