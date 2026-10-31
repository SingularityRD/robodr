#!/bin/bash
# Container entry point of the Cyclone DDS peer (peer_cyclone.py): the
# cyclonedds wheel from /wheels (or PyPI), participant index 0 so the
# executor reaches it on the RTPS well-known ports (7410 / 7411 in domain
# 0; Cyclone's default index "none" picks ephemeral ports: configure
# `peer_meta_port` / `peer_user_port` then).
set -e
if ls /wheels/cyclonedds-*.whl >/dev/null 2>&1; then
  python3 -m zipfile -e /wheels/cyclonedds-*.whl /opt/cyclonedds-py
else
  python3 -m pip install --no-deps --target /opt/cyclonedds-py "cyclonedds==0.10.5"
fi
export PYTHONPATH=/opt/cyclonedds-py
export CYCLONEDDS_URI='<CycloneDDS><Domain><Discovery><ParticipantIndex>0</ParticipantIndex></Discovery></Domain></CycloneDDS>'
exec python3 -u /peer/peer_cyclone.py
