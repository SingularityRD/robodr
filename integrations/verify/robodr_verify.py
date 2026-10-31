#!/usr/bin/env python3
"""Verify RoboDR per-finding signatures in a SIEM pipeline.

Reads NDJSON on stdin (or files), one record per line:

    {"value": "<the Kafka record value, as a string, byte for byte>",
     "headers": [["robodr-finding-sig", "<header value>"], ...]}

``headers`` may also be an object ``{"name": "value"}`` (Logstash's
``[@metadata][kafka][headers]``); a list is preferred because it keeps
duplicates, which must be rejected.

For each record (docs/contracts/robodr.findings.md section 2, "Verification"):

1. exactly one ``robodr-finding-sig`` header (name case-insensitive), parsed
   strictly: exactly ``alg``, ``key_id``, ``sig`` in that order, ``alg`` =
   ``ed25519``, printable-ASCII key id of 1-128 bytes, 128 lower-case hex;
2. the value parses as JSON and names a robot (``entity_context.robot.id``)
   that matches ``external_id`` and ``ocsf.device.uid``;
3. the key is looked up for **the robot the finding names** in the
   keyring; another robot's key never vouches for it;
4. Ed25519 over ``"robodr-ocsf/finding-sig/v1" NUL || u32be(len alg) || alg
   || u32be(len key_id) || key_id || u64be(len value) || value``.

Verified findings are written to stdout as the finding object plus
``"robodr_verification": {"status": "verified", "key_id": ...}``. With
``--policy optional`` a record without the header passes as ``unsigned``
(migration only). Anything else goes to ``--reject FILE`` (default stderr)
with the reason, and is not forwarded.

This checks origin, not content: run the schema validation
(``integrations/schemas/validate_findings.py``) as well, and drop exact
replays on ``ocsf.metadata.uid``.

    robodr_verify.py --keyring keys.json [--policy strict|optional] [--reject FILE] [FILE...]

Keyring: ``{"<robot id>": {"<key id>": "<64 hex Ed25519 public key>"}}``.
Requires the ``cryptography`` package.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys

SIG_HEADER = "robodr-finding-sig"
DOMAIN = b"robodr-ocsf/finding-sig/v1\x00"
MAX_VALUE = 64 * 1024
MAX_HEADER = 512
KEY_ID = re.compile(r"^[!-~]{1,128}$")
SIG = re.compile(r"^[0-9a-f]{128}$")


class Reject(Exception):
    pass


def signed_message(alg: str, key_id: str, value: bytes) -> bytes:
    a, k = alg.encode(), key_id.encode()
    return (
        DOMAIN
        + struct.pack(">I", len(a)) + a
        + struct.pack(">I", len(k)) + k
        + struct.pack(">Q", len(value)) + value
    )


def header_value(headers) -> str | None:
    pairs = headers.items() if isinstance(headers, dict) else headers or []
    found = None
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise Reject("malformed headers")
        name, val = pair
        if isinstance(name, str) and name.lower() == SIG_HEADER:
            if found is not None:
                raise Reject("duplicate robodr-finding-sig header")
            if not isinstance(val, str):
                raise Reject("header value is not a string")
            found = val
    return found


def parse_header(h: str):
    if len(h.encode()) > MAX_HEADER:
        raise Reject("signature header too long")
    try:
        pairs = json.loads(h, object_pairs_hook=lambda p: p)
    except ValueError:
        raise Reject("signature header is not JSON") from None
    if not isinstance(pairs, list) or [k for k, _ in pairs] != ["alg", "key_id", "sig"]:
        raise Reject("signature header must be exactly alg, key_id, sig in that order")
    d = dict(pairs)
    if d["alg"] != "ed25519":
        raise Reject(f"unsupported signature algorithm {d['alg']!r}")
    if not isinstance(d["key_id"], str) or not KEY_ID.match(d["key_id"]):
        raise Reject("bad key id")
    if not isinstance(d["sig"], str) or not SIG.match(d["sig"]):
        raise Reject("signature is not 128 lower-case hex digits")
    return d["alg"], d["key_id"], bytes.fromhex(d["sig"])


def robot_of(finding) -> str:
    try:
        robot = finding["entity_context"]["robot"]["id"]
    except (KeyError, TypeError):
        raise Reject("finding names no robot") from None
    if not isinstance(robot, str) or not robot:
        raise Reject("finding names no robot")
    if not str(finding.get("external_id", "")).startswith(robot + ":"):
        raise Reject("external_id does not name the finding's robot")
    try:
        if finding["ocsf"]["device"]["uid"] != robot:
            raise Reject("ocsf.device.uid does not name the finding's robot")
    except (KeyError, TypeError):
        raise Reject("ocsf.device.uid missing") from None
    return robot


def verify(record, keyring, policy: str):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(record, dict) or not isinstance(record.get("value"), str):
        raise Reject("record has no string value")
    raw = record["value"].encode("utf-8")
    if len(raw) > MAX_VALUE:
        raise Reject("value larger than 64 KiB")
    h = header_value(record.get("headers"))
    try:
        finding = json.loads(raw)
    except ValueError:
        raise Reject("value is not JSON") from None
    if not isinstance(finding, dict):
        raise Reject("value is not a JSON object")
    robot = robot_of(finding)
    if h is None:
        if policy == "optional":
            return finding, {"status": "unsigned"}
        raise Reject("missing robodr-finding-sig header (strict policy)")
    alg, key_id, sig = parse_header(h)
    pub = keyring.get(robot, {}).get(key_id)
    if pub is None:
        raise Reject(f"no key {key_id!r} registered for robot {robot!r}")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            sig, signed_message(alg, key_id, raw)
        )
    except (InvalidSignature, ValueError):
        raise Reject("signature does not verify") from None
    return finding, {"status": "verified", "key_id": key_id}


def load_keyring(path):
    with open(path, encoding="utf-8") as fh:
        k = json.load(fh)
    ok = isinstance(k, dict) and all(
        isinstance(v, dict)
        and all(isinstance(p, str) and re.fullmatch(r"[0-9a-f]{64}", p) for p in v.values())
        for v in k.values()
    )
    if not ok:
        raise SystemExit("keyring must be {robot id: {key id: 64 hex public key}}")
    return k


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--keyring", required=True)
    ap.add_argument("--policy", choices=["strict", "optional"], default="strict")
    ap.add_argument("--reject", help="file for rejected records (default stderr)")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args(argv)
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("python3 package 'cryptography' is required", file=sys.stderr)
        return 2
    keyring = load_keyring(a.keyring)
    rej = open(a.reject, "a", encoding="utf-8") if a.reject else sys.stderr
    sources = [open(f, encoding="utf-8") for f in a.files] or [sys.stdin]
    ok = bad = 0
    for src in sources:
        for n, line in enumerate(src, 1):
            if not line.strip():
                continue
            try:
                try:
                    record = json.loads(line)
                except ValueError:
                    raise Reject("line is not JSON") from None
                finding, status = verify(record, keyring, a.policy)
            except Reject as e:
                bad += 1
                rej.write(json.dumps({"line": n, "reason": str(e)}) + "\n")
                continue
            finding["robodr_verification"] = status
            sys.stdout.write(json.dumps(finding, separators=(",", ":")) + "\n")
            ok += 1
    print(f"robodr_verify: {ok} forwarded, {bad} rejected", file=sys.stderr)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
