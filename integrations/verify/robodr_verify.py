#!/usr/bin/env python3
"""Verify RoboDR per-finding signatures in a SIEM pipeline.

Reads NDJSON on stdin (or files), one record per line:

    {"value": "<the Kafka record value, as a string, byte for byte>",
     "headers": [["robodr-finding-sig", "<header value>"], ...]}

``headers`` may also be an object ``{"name": "value"}``; a list is
preferred because it keeps duplicates, which must be rejected. Logstash's
Kafka input keeps one value per header name (``[@metadata][kafka][headers]``
is a hash), so on the Logstash path a duplicated header has already been
collapsed to one before this script sees it and the duplicate rejection of
step 1 cannot fire there; the remaining header must still verify.

For each record (docs/contracts/robodr.findings.md section 2, "Verification"):

1. exactly one ``robodr-finding-sig`` header (name case-insensitive), parsed
   strictly: exactly ``alg``, ``key_id``, ``sig`` in that order, ``alg`` =
   ``ed25519``, printable-ASCII key id of 1-128 bytes, 128 lower-case hex;
2. NOT the contract's step 2: the value is only parsed as JSON and its
   identity checked: it names a robot (``entity_context.robot.id``),
   ``external_id`` is exactly ``<robot id>:<finding_id>``,
   ``ocsf.finding_info.uid`` is ``finding_id`` and ``ocsf.device.uid`` is the
   robot. The strict validator (``robodr_ocsf::parse_and_validate``) is not
   run; ``integrations/schemas/validate_findings.py`` is a separate,
   schema-level check (it does not check every cross-field rule the Rust
   validator does);
3. the key is looked up for **the robot the finding names** in the
   keyring; another robot's key never vouches for it. The keyring is keyed
   by robot, so every key is bound to the one robot it is listed under
   (the contract's device binding);
4. Ed25519 over ``"robodr-ocsf/finding-sig/v1" NUL || u32be(len alg) || alg
   || u32be(len key_id) || key_id || u64be(len value) || value``, with the
   ``verify_strict`` checks the Rust verifier applies on top of the
   ``cryptography`` package's verification: the public key and the
   signature's R must be canonical encodings of points that are not of
   small order, and S must be below the group order. Keyring keys that fail
   this are refused when the keyring is loaded.

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

# Ed25519 (RFC 8032) field and group constants for the strict checks.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


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


def _decompress(b: bytes):
    """Affine (x, y) of a canonical point encoding, else None."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= _P:
        return None  # non-canonical y
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None  # not on the curve
    if x == 0 and sign:
        return None  # non-canonical: -0
    if x & 1 != sign:
        x = _P - x
    return x, y


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return x3, y3


def strong_point(b: bytes) -> bool:
    """A canonical encoding of a curve point whose order is not 1, 2, 4 or 8."""
    pt = _decompress(b)
    if pt is None:
        return False
    for _ in range(3):
        pt = _add(pt, pt)
    return pt != (0, 1)


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
    fid = finding.get("finding_id")
    if not isinstance(fid, str) or not fid:
        raise Reject("finding has no finding_id")
    if finding.get("external_id") != f"{robot}:{fid}":
        raise Reject("external_id is not <robot id>:<finding_id>")
    try:
        if finding["ocsf"]["device"]["uid"] != robot:
            raise Reject("ocsf.device.uid does not name the finding's robot")
        if finding["ocsf"]["finding_info"]["uid"] != fid:
            raise Reject("ocsf.finding_info.uid is not finding_id")
    except (KeyError, TypeError):
        raise Reject("ocsf.device.uid or ocsf.finding_info.uid missing") from None
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
    # verify_strict: weak or non-canonical keys and R, and S >= L, never verify.
    if not strong_point(bytes.fromhex(pub)) or not strong_point(sig[:32]):
        raise Reject("signature does not verify (weak or non-canonical point)")
    if int.from_bytes(sig[32:], "little") >= _L:
        raise Reject("signature does not verify (non-canonical S)")
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
    weak = [f"{r}/{i}" for r, v in k.items() for i, p in v.items() if not strong_point(bytes.fromhex(p))]
    if weak:
        raise SystemExit(f"keyring: weak or non-canonical Ed25519 public key(s): {', '.join(weak)}")
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
