#!/bin/bash
# Container entry point of the Cyclone DDS peer (peer_cyclone.py): the
# cyclonedds wheel from /wheels (or PyPI), participant index 0 so the
# executor reaches it on the RTPS well-known ports (7410 / 7411 in domain
# 0; Cyclone's default index "none" picks ephemeral ports: configure
# `peer_meta_port` / `peer_user_port` then).
# The wheel is pinned by its file name and sha256 (PyPI's
# cyclonedds-0.10.5-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl,
# the Python 3.10 of the Humble image): a local wheel under that name with
# another hash is refused, and so is a cyclonedds wheel in /wheels under
# any other name (it would otherwise be ignored without a word); with no
# local wheel, pip installs from PyPI only with that hash.
# ROBODR_PEER_WHEELS_DIR replaces /wheels (test_entrypoint_cyclone.sh).
set -e
wheels="${ROBODR_PEER_WHEELS_DIR:-/wheels}"
whl_name=cyclonedds-0.10.5-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
whl_sha256=861d2ffd9513126d6a62ad9f842e85122518a7db1fb0a11d6e4fa86e3cacf61c
whl="$wheels/$whl_name"
for other in "$wheels"/cyclonedds*.whl; do
  if [ -e "$other" ] && [ "$other" != "$whl" ]; then
    echo "$other: not the pinned wheel (only $whl_name is used, checked by its sha256)" >&2
    exit 1
  fi
done
if [ -e "$whl" ]; then
  echo "$whl_sha256  $whl" | sha256sum -c --quiet - || {
    echo "$whl: sha256 differs from the pinned one" >&2
    exit 1
  }
  python3 -m zipfile -e "$whl" /opt/cyclonedds-py
else
  req="$(mktemp)"
  echo "cyclonedds==0.10.5 --hash=sha256:$whl_sha256" >"$req"
  python3 -m pip install --no-deps --only-binary :all: --require-hashes \
    --target /opt/cyclonedds-py -r "$req"
fi
export PYTHONPATH=/opt/cyclonedds-py
export CYCLONEDDS_URI='<CycloneDDS><Domain><Discovery><ParticipantIndex>0</ParticipantIndex></Discovery></Domain></CycloneDDS>'
exec python3 -u /peer/peer_cyclone.py
