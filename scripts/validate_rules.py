#!/usr/bin/env python3
"""Offline validator for RoboDR's Pulsar rules (std-only, Python >= 3.11).

Pulsar's rules engine cannot be built here (crates.io is unreachable), so this
script re-implements, from the vendored source, exactly the parts of the engine
that decide whether a rule file loads and compiles:

  1. File discovery   : every ``**/*.toml`` below the rules dir is loaded.
                        (rules-engine/src/engine.rs:14 RULE_EXTENSION, :113 glob)
  2. Document schema  : ``[[rules]]`` with the six required string keys
                        name/type/condition/category/severity/description and
                        the Category / Severity enums.
                        (rules-engine/src/engine.rs:17-31, :218-245)
  3. Event type       : ``type`` must be a ``PayloadDiscriminant`` (strum
                        EnumString, case-sensitive).
                        (pulsar-core/src/event.rs:177-280)
  4. DSL grammar      : the LALRPOP grammar, including its traps: AND and OR
                        have EQUAL precedence and are LEFT-associative; NOT
                        applies to one simple condition; IN expands to an OR of
                        ``==``.  (rules-engine/src/dsl.lalrpop)
  5. Type checking    : every ``header.X`` / ``payload.X`` path must exist in
                        the embedded schema below, and the operator must be one
                        the field's Validatron type accepts, and the literal
                        must parse as that type.
                        (validatron/src/builtins.rs, pulsar-core/src/event.rs
                        Argv:551-580 FileFlags:450-513, pdk/module.rs:170)

It also contains a small evaluator so ``scripts/rules_fixtures.json`` can
assert that each robot rule fires (or not) on hand-written sample events, using
the engine's matching semantics (Argv CONTAINS = exact element; FileFlags
CONTAINS = access-mode equality or bit test; IpAddr ordering V4 < V6; a path
through a ``None`` Option evaluates to false).

If the Pulsar source tree is present (default ``vendor/pulsar`` or
``--pulsar-src``) the script additionally:
  * re-extracts the Payload / Header / Host / ContainerInfo fields, the
    Category / Severity enums and the UserRule keys and fails if they drifted
    from the embedded schema;
  * checks the grammar itself (dsl.lalrpop): the exact operator token set, the
    keywords, every plain terminal, and fingerprints of the productions this
    parser hard-codes (AND/OR equal precedence, NOT on one simple condition,
    IN, literal regexes, trim_matches without unescaping, identifiers, '?');
  * checks the operator families each field type accepts against the
    Validatron impls (builtins.rs String/IpAddr/bool/numeric, event.rs Argv /
    FileFlags, pdk/module.rs ModuleName) and the FileFlags name tables;
  * runs a mutation test proving those drift checks fire on in-memory edits
    (renamed/added operator, changed precedence, IpAddr gaining STARTS_WITH,
    ...), and
  * validates Pulsar's OWN shipped rules (``<pulsar>/rules``), which upstream's
    ``shipped_rules_are_valid`` test proves compile in the real engine. They
    must all pass here too; that calibrates this checker against the engine.

Usage:
  scripts/validate_rules.py [--rules-dir rules] [--pulsar-src vendor/pulsar]
                            [--fixtures scripts/rules_fixtures.json] [--strict]
  scripts/validate_rules.py --self-test

Exit status 0 = everything loads, type-checks and fixtures match.
What this cannot prove: that the kernel probes emit the events/paths assumed
(e.g. dpkg maintainer-script exec filenames). See rules/README.md.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Embedded schema, extracted by hand from Pulsar rev 4796504 (0.11.0-alpha.1).
# ---------------------------------------------------------------------------

# rules-engine/src/engine.rs:23-30 (UserRule) -- all required, all strings.
REQUIRED_KEYS = ("name", "type", "condition", "category", "severity", "description")

# rules-engine/src/engine.rs:218-235 (Category, serde snake_case)
CATEGORIES = {
    "command_and_control", "credential_access", "defense_evasion", "discovery",
    "execution", "exfiltration", "generic", "impact", "initial_access",
    "lateral_movement", "persistence", "privilege_escalation", "reconnaissance",
    "resource_development",
}

# rules-engine/src/engine.rs:237-245 (Severity, serde lowercase)
SEVERITIES = {"low", "medium", "high", "critical"}

# Primitive type names used below. Operator support per type:
#   String     : validatron/src/builtins.rs:37-55   rel, STARTS/ENDS_WITH, CONTAINS(substring)
#   ModuleName : pulsar-core/src/pdk/module.rs:170-190 rel, STARTS/ENDS_WITH
#   Argv       : pulsar-core/src/event.rs:561-580  CONTAINS only (exact element)
#   FileFlags  : pulsar-core/src/event.rs:479-513  CONTAINS only, named flags
#   IpAddr     : validatron/src/builtins.rs:90-108  rel only, value must parse
#   ints       : validatron/src/builtins.rs:9-35    rel only
#   bool       : validatron/src/builtins.rs:57-82   == and != only
REL_OPS = {"==", "!=", ">", "<", ">=", "<="}
STR_OPS = {"STARTS_WITH", "ENDS_WITH"}
TYPE_OPS = {
    "String": REL_OPS | STR_OPS | {"CONTAINS"},
    "ModuleName": REL_OPS | STR_OPS,
    "Argv": {"CONTAINS"},
    "FileFlags": {"CONTAINS"},
    "IpAddr": REL_OPS,
    "bool": {"==", "!="},
}
INT_RANGES = {
    "i32": (-(2**31), 2**31 - 1),
    "u32": (0, 2**32 - 1),
    "u16": (0, 2**16 - 1),
    "usize": (0, 2**64 - 1),
}
for _t in INT_RANGES:
    TYPE_OPS[_t] = REL_OPS

# pulsar-core/src/event.rs:462-476 (FileFlags::ACC_MODE_FLAGS / OTHER_FLAGS)
ACC_MODE_FLAGS = ("O_RDONLY", "O_WRONLY", "O_RDWR")
OTHER_FLAGS = ("O_CREAT", "O_EXCL", "O_NOCTTY", "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_DIRECTORY")

# Struct types: name -> {field: type}. "Option<X>" marks Option.
STRUCTS = {
    # pulsar-core/src/event.rs:80-95 (threat, timestamp, fork_time are #[validatron(skip)])
    "Header": {
        "image": "String", "pid": "i32", "parent_pid": "i32", "uid": "u32",
        "gid": "u32", "container": "Option<ContainerInfo>", "source": "ModuleName",
    },
    # bpf-common/src/containers/mod.rs:160-167 (layers skipped)
    "ContainerInfo": {"id": "String", "name": "String", "image": "String", "image_digest": "String"},
    # pulsar-core/src/event.rs:395-399
    "Host": {"ip": "IpAddr", "port": "u16"},
}

# pulsar-core/src/event.rs:181-280 (Payload). Fields marked #[validatron(skip)]
# are omitted (DnsQuery/DnsResponse questions/answers, Custom fields); Empty is
# a valid discriminant with no fields.
PAYLOADS = {
    "FileCreated": {"filename": "String"},
    "FileDeleted": {"filename": "String"},
    "DirCreated": {"dirname": "String"},
    "DirDeleted": {"dirname": "String"},
    "FileOpened": {"filename": "String", "flags": "FileFlags"},
    "FileLink": {"source": "String", "destination": "String", "hard_link": "bool"},
    "FileRename": {"source": "String", "destination": "String"},
    "ElfOpened": {"filename": "String", "flags": "FileFlags"},
    "Fork": {"ppid": "i32", "uid": "u32", "gid": "u32"},
    "Exec": {"filename": "String", "argc": "usize", "argv": "Argv"},
    "Exit": {"exit_code": "u32"},
    "ChangeParent": {"ppid": "i32"},
    "CredentialsChange": {"uid": "u32", "gid": "u32"},
    "Bind": {"address": "Host", "is_tcp": "bool"},
    "Listen": {"address": "Host"},
    "Connect": {"destination": "Host", "is_tcp": "bool"},
    "Accept": {"source": "Host", "destination": "Host"},
    "Close": {"source": "Host", "destination": "Host"},
    "Receive": {"source": "Host", "destination": "Host", "len": "usize", "is_tcp": "bool"},
    "DnsQuery": {},
    "DnsResponse": {},
    "Send": {"source": "Host", "destination": "Host", "len": "usize", "is_tcp": "bool"},
    "Custom": {},
    "Empty": {},
}

# Rust type spellings used in event.rs, for the drift check.
RUST_TYPE = {"String": "String", "i32": "i32", "u32": "u32", "u16": "u16", "usize": "usize",
             "bool": "bool", "Argv": "Argv", "FileFlags": "FileFlags", "Host": "Host",
             "IpAddr": "IpAddr", "ModuleName": "ModuleName",
             "Option<ContainerInfo>": "Option<ContainerInfo>"}


class RuleError(Exception):
    pass


# ---------------------------------------------------------------------------
# Lexer + parser for rules-engine/src/dsl.lalrpop
# ---------------------------------------------------------------------------

# LALRPOP's lexer: longest match wins; on a tie a literal beats a regex. Every
# keyword is also a valid identifier, so "AND" is a keyword but "ANDx" an ident.
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>[\t\n\x0b\x0c\r\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<ident>[a-zA-Z]+\w*)
  | (?P<num>[0-9]+)
  | (?P<punct>\(\)|==|!=|>=|<=|[()\[\],.?<>])
    """,
    re.VERBOSE,
)
# ws: the Rust regex crate's Unicode \s (White_Space property), which LALRPOP's
# lexer skips. Python's \s is str.isspace() and ALSO matches \x1c-\x1f, which
# Rust would reject as an unexpected character -- so the set is spelled out.
KEYWORDS = {"AND", "OR", "NOT", "IN", "STARTS_WITH", "ENDS_WITH", "CONTAINS"}
OPERATORS = REL_OPS | STR_OPS | {"CONTAINS"}


@dataclass
class Tok:
    kind: str  # 'kw', 'ident', 'string', 'num', 'punct', 'eof'
    text: str
    pos: int


def tokenize(src: str) -> list[Tok]:
    toks, i = [], 0
    while i < len(src):
        m = _TOKEN_RE.match(src, i)
        if not m:
            raise RuleError(f"unexpected character {src[i]!r} at offset {i}")
        kind = m.lastgroup
        text = m.group()
        if kind == "ident" and text in KEYWORDS:
            kind = "kw"
        if kind != "ws":
            toks.append(Tok(kind, text, i))
        i = m.end()
    toks.append(Tok("eof", "", len(src)))
    return toks


@dataclass
class Path_:
    # each element: ('field', name) | ('some',) | ('method', name)
    parts: list


@dataclass
class Binary:
    left: Path_
    op: str
    right: object  # str literal value or Path_


@dataclass
class Unary:
    path: Path_


@dataclass
class Not:
    inner: object


@dataclass
class BoolOp:
    op: str  # AND / OR
    left: object
    right: object


@dataclass
class Group:
    inner: object  # parenthesised condition (kept for lint purposes)


class Parser:
    def __init__(self, src: str):
        self.toks = tokenize(src)
        self.i = 0
        self.warnings: list[str] = []

    def peek(self) -> Tok:
        return self.toks[self.i]

    def next(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def expect(self, text: str) -> Tok:
        t = self.next()
        if t.text != text or t.kind in ("string",):
            raise RuleError(f"expected {text!r} at offset {t.pos}, got {t.text!r}")
        return t

    def parse(self):
        cond = self.condition()
        if self.peek().kind != "eof":
            t = self.peek()
            raise RuleError(f"unexpected token {t.text!r} at offset {t.pos}")
        return cond

    # Condition: Condition ("AND"|"OR") SignedCondition | SignedCondition
    def condition(self):
        left = self.signed()
        ops_seen = set()
        while self.peek().kind == "kw" and self.peek().text in ("AND", "OR"):
            op = self.next().text
            ops_seen.add(op)
            right = self.signed()
            left = BoolOp(op, left, right)
        if len(ops_seen) == 2:
            self.warnings.append(
                "AND and OR mixed at one nesting level: Pulsar gives them EQUAL precedence, "
                "left-associative ('a OR b AND c' == '(a OR b) AND c'); add parentheses"
            )
        return left

    def signed(self):
        if self.peek().kind == "kw" and self.peek().text == "NOT":
            self.next()
            return Not(self.simple())
        return self.simple()

    def simple(self):
        t = self.peek()
        if t.kind == "punct" and t.text == "(":
            self.next()
            inner = self.condition()
            self.expect(")")
            return Group(inner)
        path = self.field_path()
        t = self.peek()
        if t.kind == "kw" and t.text == "IN":
            self.next()
            values = self.value_list()
            if not values:
                raise RuleError("Empty list is not allowed (IN [])")
            # dsl.lalrpop: IN expands to (f == v1) OR (f == v2) ...
            cond = Binary(path, "==", values[0])
            for v in values[1:]:
                cond = BoolOp("OR", cond, Binary(path, "==", v))
            return Group(cond)
        if (t.kind == "kw" and t.text in OPERATORS) or (t.kind == "punct" and t.text in OPERATORS):
            op = self.next().text
            v = self.peek()
            if v.kind in ("string", "num"):
                return Binary(path, op, self.value())
            if v.kind == "ident":
                return Binary(path, op, self.field_path())
            raise RuleError(f"expected value or field after {op} at offset {v.pos}")
        return Unary(path)

    def value(self) -> str:
        t = self.next()
        if t.kind == "string":
            # dsl.lalrpop: <>.trim_matches('"') -- escapes are NOT processed.
            if "\\" in t.text:
                self.warnings.append(
                    f"backslash in {t.text}: Pulsar does not unescape string literals"
                )
            return t.text.strip('"')
        if t.kind == "num":
            return t.text
        raise RuleError(f"expected a quoted string or digits at offset {t.pos}, got {t.text!r}")

    def value_list(self) -> list[str]:
        self.expect("[")
        values = []
        while not (self.peek().kind == "punct" and self.peek().text == "]"):
            values.append(self.value())
            if self.peek().kind == "punct" and self.peek().text == ",":
                self.next()
            elif not (self.peek().kind == "punct" and self.peek().text == "]"):
                raise RuleError(f"expected ',' or ']' at offset {self.peek().pos}")
        self.expect("]")
        return values

    def field_path(self) -> Path_:
        parts = []
        while True:
            t = self.next()
            if t.kind not in ("ident", "kw"):
                raise RuleError(f"expected identifier at offset {t.pos}, got {t.text!r}")
            if t.kind == "kw":
                raise RuleError(f"keyword {t.text!r} used where a field was expected (offset {t.pos})")
            if self.peek().kind == "punct" and self.peek().text == "()":
                self.next()
                parts.append(("method", t.text))
            else:
                parts.append(("field", t.text))
            if self.peek().kind == "punct" and self.peek().text == "?":
                self.next()
                parts.append(("some",))
                if not (self.peek().kind == "punct" and self.peek().text == "."):
                    raise RuleError("'?' must be followed by '.'")
            if self.peek().kind == "punct" and self.peek().text == ".":
                self.next()
                continue
            break
        # dsl.lalrpop FieldPath checks
        for idx, p in enumerate(parts):
            if p[0] == "method":
                if idx == 0:
                    raise RuleError("Function calls are not supported, only methods are allowed")
                if idx != len(parts) - 1:
                    raise RuleError("Methods are allowed only as final type")
        return Path_(parts)


# ---------------------------------------------------------------------------
# Type checker
# ---------------------------------------------------------------------------

def resolve_type(path: Path_, event_type: str) -> str:
    """Return the Validatron type of ``path`` on Event for payload variant ``event_type``."""
    parts = path.parts
    names = [p[1] if p[0] != "some" else "?" for p in parts]
    dotted = ".".join(names)
    if parts[0] != ("field", "header") and parts[0] != ("field", "payload"):
        raise RuleError(f"'{dotted}': paths must start with header or payload")
    if parts[0] == ("field", "payload"):
        if len(parts) < 2 or parts[1][0] != "field":
            raise RuleError(f"'{dotted}': payload needs a field")
        fields = PAYLOADS[event_type]
        if parts[1][1] not in fields:
            raise RuleError(
                f"'{dotted}': {event_type} has no field '{parts[1][1]}' "
                f"(fields: {', '.join(sorted(fields)) or 'none'})"
            )
        cur = fields[parts[1][1]]
        rest = parts[2:]
    else:
        cur = "Header"
        rest = parts[1:]
    for p in rest:
        if p[0] == "some":
            if not cur.startswith("Option<"):
                raise RuleError(f"'{dotted}': '?' used on non-Option type {cur}")
            cur = cur[len("Option<"):-1]
        elif p[0] == "method":
            if cur.startswith("Option<") and p[1] == "is_some":
                cur = "bool"
            else:
                raise RuleError(f"'{dotted}': no method {p[1]}() on {cur}")
        else:
            if cur.startswith("Option<"):
                raise RuleError(f"'{dotted}': '{p[1]}' on Option type {cur}; use '?.' or is_some()")
            if cur not in STRUCTS:
                raise RuleError(f"'{dotted}': {cur} is a primitive, it has no field '{p[1]}'")
            if p[1] not in STRUCTS[cur]:
                raise RuleError(
                    f"'{dotted}': {cur} has no field '{p[1]}' (fields: {', '.join(STRUCTS[cur])})"
                )
            cur = STRUCTS[cur][p[1]]
    return cur


# Literal parsers that mirror the Rust ``FromStr`` impls validatron calls
# (validatron/src/builtins.rs). Python's own int()/ipaddress are MORE lenient
# (int() takes "1_000", " 7 ", full-width digits; ipaddress takes "fe80::1%eth0")
# and anything the Rust side rejects makes RuleEngine::new fail, which disables
# EVERY rule, Pulsar's included. So these are strict, ASCII-only, and are
# differentially tested against the Rust std parsers (see --self-test and
# rules/README.md "Validator vs. Rust parsing").

# core::num from_str_radix(10): optional single '+' (or '-' for signed types),
# then >= 1 ASCII digit. No whitespace, no '_', no Unicode digits. Leading zeros
# are fine. fullmatch(), never '$' (which also matches before a trailing "\n").
_RUST_UINT_RE = re.compile(r"\+?[0-9]+")
_RUST_SINT_RE = re.compile(r"[+-]?[0-9]+")
_SIGNED = {"i32"}


def rust_parse_int(ty: str, value: str) -> int | None:
    rx = _RUST_SINT_RE if ty in _SIGNED else _RUST_UINT_RE
    if not rx.fullmatch(value):
        return None
    n = int(value, 10)  # safe now: ASCII digits with optional sign only
    lo, hi = INT_RANGES[ty]
    return n if lo <= n <= hi else None


# core::net::parser (std::net::IpAddr::from_str).
_V4_OCTET = re.compile(r"0|[1-9][0-9]{0,2}")
_V6_GROUP = re.compile(r"[0-9a-fA-F]{1,4}")


def _rust_v4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(_V4_OCTET.fullmatch(p) and int(p) <= 255 for p in parts)


def _rust_v6_groups(s: str, allow_v4_tail: bool) -> int | None:
    """Number of 16-bit groups in a ':'-separated run, or None if malformed."""
    if s == "":
        return 0
    parts = s.split(":")
    n = 0
    for i, p in enumerate(parts):
        if i == len(parts) - 1 and allow_v4_tail and "." in p:
            if not _rust_v4(p):
                return None
            n += 2
        elif _V6_GROUP.fullmatch(p):
            n += 1
        else:
            return None
    return n


def rust_parse_ip(value: str) -> bool:
    if not value.isascii():
        return False
    if _rust_v4(value):
        return True
    if value.count("::") > 1 or ":::" in value:
        return False
    if "::" in value:
        head, tail = value.split("::")
        h = _rust_v6_groups(head, allow_v4_tail=False)
        t = _rust_v6_groups(tail, allow_v4_tail=True)
        # "::" stands for at least one zero group.
        return h is not None and t is not None and h + t <= 7
    return _rust_v6_groups(value, allow_v4_tail=True) == 8


def check_literal(ty: str, value: str, dotted: str) -> None:
    if ty in INT_RANGES:
        if rust_parse_int(ty, value) is None:
            if (_RUST_SINT_RE if ty in _SIGNED else _RUST_UINT_RE).fullmatch(value):
                raise RuleError(f"'{dotted}' is {ty}; {value} is out of range")
            raise RuleError(f"'{dotted}' is {ty}; {value!r} does not parse "
                            "(Rust from_str: ASCII digits, optional sign, nothing else)")
    elif ty == "bool":
        # bool::from_str: exactly "true" / "false".
        if value not in ("true", "false"):
            raise RuleError(f"'{dotted}' is bool; use \"true\" / \"false\", got {value!r}")
    elif ty == "IpAddr":
        if not rust_parse_ip(value):
            raise RuleError(f"'{dotted}' is IpAddr; {value!r} is not an IP address "
                            "(Rust std::net: ASCII only, no zone id '%', no leading zeros in IPv4)")
    elif ty == "FileFlags":
        # event.rs FileFlags parser: exact name match.
        if value not in ACC_MODE_FLAGS + OTHER_FLAGS:
            raise RuleError(f"'{dotted}' is FileFlags; unknown flag {value!r}")
    # String / ModuleName / Argv: infallible from_str (String::from_str,
    # ModuleName(Cow::Owned), Argv(vec![s])) -- any literal loads.


def typecheck(cond, event_type: str, warnings: list[str]) -> None:
    if isinstance(cond, (BoolOp,)):
        typecheck(cond.left, event_type, warnings)
        typecheck(cond.right, event_type, warnings)
    elif isinstance(cond, (Not, Group)):
        typecheck(cond.inner, event_type, warnings)
    elif isinstance(cond, Unary):
        ty = resolve_type(cond.path, event_type)
        if ty != "bool":
            raise RuleError(f"unary condition on non-bool field ({ty})")
    elif isinstance(cond, Binary):
        dotted = ".".join(p[1] if p[0] != "some" else "?" for p in cond.left.parts)
        ty = resolve_type(cond.left, event_type)
        if ty not in TYPE_OPS:
            raise RuleError(f"'{dotted}' is a {ty} struct, not a primitive; pick a sub-field")
        if cond.op not in TYPE_OPS[ty]:
            raise RuleError(
                f"operator {cond.op} not allowed on '{dotted}' ({ty}); allowed: "
                f"{', '.join(sorted(TYPE_OPS[ty]))}"
            )
        if isinstance(cond.right, Path_):
            rty = resolve_type(cond.right, event_type)
            if rty != ty:
                raise RuleError(f"'{dotted}' ({ty}) compared to field of type {rty}")
        else:
            check_literal(ty, cond.right, dotted)
            if ty == "Argv" and " " in cond.right:
                warnings.append(
                    f"argv CONTAINS {cond.right!r}: matches one whole argv element, "
                    "never a substring of the command line"
                )
        if event_type == "Exec" and cond.left.parts[:2] == [("field", "header"), ("field", "image")]:
            warnings.append(
                "header.image on an Exec event is the NEW image (== payload.filename), "
                "not the parent; Pulsar exposes only header.parent_pid"
            )
    else:  # pragma: no cover
        raise RuleError(f"internal: unknown node {cond!r}")


# ---------------------------------------------------------------------------
# Evaluator (for fixtures)
# ---------------------------------------------------------------------------

_MISSING = object()


def extract(path: Path_, event: dict):
    cur = event
    for p in path.parts:
        if cur is None:
            return _MISSING
        if p[0] == "field":
            if not isinstance(cur, dict) or p[1] not in cur:
                raise RuleError(f"fixture event lacks field {p[1]}")
            cur = cur[p[1]]
        elif p[0] == "some":
            if cur is None:
                return _MISSING
        elif p[0] == "method":
            return cur is not None  # is_some()
    return _MISSING if cur is None else cur


def ip_key(s: str):
    a = ipaddress.ip_address(s)
    return (a.version, int(a))  # Rust IpAddr: every V4 < every V6


def apply(op: str, ty: str, a, b) -> bool:
    if ty == "Argv":
        return b in a
    if ty == "FileFlags":
        acc = next((f for f in a if f in ACC_MODE_FLAGS), "O_RDONLY")
        return acc == b if b in ACC_MODE_FLAGS else b in a
    if ty == "IpAddr":
        a, b = ip_key(a), ip_key(b)
    elif ty in INT_RANGES:
        a, b = int(a), int(b)
    elif ty == "bool":
        a = bool(a) if isinstance(a, bool) else a == "true"
        b = bool(b) if isinstance(b, bool) else b == "true"
    if op == "STARTS_WITH":
        return a.startswith(b)
    if op == "ENDS_WITH":
        return a.endswith(b)
    if op == "CONTAINS":
        return b in a
    return {"==": a == b, "!=": a != b, ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]


def evaluate(cond, event: dict, event_type: str) -> bool:
    if isinstance(cond, BoolOp):
        l = evaluate(cond.left, event, event_type)
        r = evaluate(cond.right, event, event_type)
        return (l and r) if cond.op == "AND" else (l or r)
    if isinstance(cond, Not):
        return not evaluate(cond.inner, event, event_type)
    if isinstance(cond, Group):
        return evaluate(cond.inner, event, event_type)
    if isinstance(cond, Unary):
        v = extract(cond.path, event)
        return v is not _MISSING and bool(v)
    ty = resolve_type(cond.left, event_type)
    a = extract(cond.left, event)
    if a is _MISSING:
        return False
    if isinstance(cond.right, Path_):
        b = extract(cond.right, event)
        if b is _MISSING:
            return False
    else:
        b = cond.right
    return apply(cond.op, ty, a, b)


# ---------------------------------------------------------------------------
# File-level validation
# ---------------------------------------------------------------------------

@dataclass
class LoadedRule:
    file: str
    name: str
    type: str
    ast: object


@dataclass
class Report:
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    rules: list = field(default_factory=list)


def validate_text(text: str, label: str, report: Report) -> None:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        report.errors.append(f"{label}: TOML parse error: {e}")
        return
    if set(doc) != {"rules"}:
        extra = set(doc) - {"rules"}
        if "rules" not in doc:
            report.errors.append(f"{label}: missing top-level 'rules' array ([[rules]])")
            return
        report.warnings.append(f"{label}: top-level keys {sorted(extra)} are ignored by Pulsar")
    rules = doc["rules"]
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        report.errors.append(f"{label}: 'rules' must be an array of tables")
        return
    for idx, r in enumerate(rules):
        rl = f"{label}: rule #{idx + 1} ({r.get('name', '?')!r})"
        n_err = len(report.errors)
        for k in REQUIRED_KEYS:
            if k not in r:
                report.errors.append(f"{rl}: missing required key '{k}'")
            elif not isinstance(r[k], str):
                report.errors.append(f"{rl}: key '{k}' must be a string")
        for k in set(r) - set(REQUIRED_KEYS):
            report.warnings.append(f"{rl}: key '{k}' is ignored by Pulsar (not in UserRule)")

        def ok(k):
            return isinstance(r.get(k), str)

        if ok("category") and r["category"] not in CATEGORIES:
            report.errors.append(
                f"{rl}: category {r['category']!r} is not a Pulsar Category "
                f"(valid: {', '.join(sorted(CATEGORIES))})"
            )
        if ok("severity") and r["severity"] not in SEVERITIES:
            report.errors.append(f"{rl}: severity {r['severity']!r} not in {sorted(SEVERITIES)}")
        if not (ok("type") and ok("condition")):
            continue
        if r["type"] not in PAYLOADS:
            report.errors.append(f"{rl}: type {r['type']!r} is not a Pulsar PayloadDiscriminant")
            continue
        try:
            parser = Parser(r["condition"])
            ast = parser.parse()
            w = list(parser.warnings)
            typecheck(ast, r["type"], w)
        except RuleError as e:
            report.errors.append(f"{rl}: condition: {e}")
            continue
        for msg in dict.fromkeys(w):
            report.warnings.append(f"{rl}: {msg}")
        if len(report.errors) == n_err:
            report.rules.append(LoadedRule(label, r["name"], r["type"], ast))


def validate_dir(rules_dir: Path, report: Report) -> None:
    files = sorted(rules_dir.rglob("*.toml"))  # engine.rs:113 "{dir}/**/*.toml"
    if not files:
        report.errors.append(f"{rules_dir}: no *.toml rule files found")
    for f in files:
        validate_text(f.read_text(encoding="utf-8"), str(f), report)
    seen: dict[str, str] = {}
    for r in report.rules:
        if r.name in seen:
            report.warnings.append(f"duplicate rule name {r.name!r} in {seen[r.name]} and {r.file}")
        seen[r.name] = r.file


def run_fixtures(fixtures_path: Path, rules: list[LoadedRule], report: Report) -> int:
    by_name = {r.name: r for r in rules}
    fixtures = json.loads(fixtures_path.read_text(encoding="utf-8"))
    covered = set()
    for i, fx in enumerate(fixtures):
        label = f"{fixtures_path.name}[{i}] ({fx.get('note', '')})"
        rule = by_name.get(fx["rule"])
        if rule is None:
            report.errors.append(f"{label}: unknown rule {fx['rule']!r}")
            continue
        covered.add(rule.name)
        ev = fx["event"]
        header = {"image": "", "pid": 1000, "parent_pid": 1, "uid": 0, "gid": 0,
                  "container": None, "source": "test"}
        header.update(ev.get("header", {}))
        event = {"header": header, "payload": ev["payload"]}
        try:
            got = evaluate(rule.ast, event, rule.type)
        except RuleError as e:
            report.errors.append(f"{label}: {e}")
            continue
        if got != fx["expect"]:
            report.errors.append(f"{label}: rule {rule.name!r} returned {got}, expected {fx['expect']}")
    for r in rules:
        if r.name not in covered:
            report.warnings.append(f"rule {r.name!r} has no fixture")
    return len(fixtures)


# ---------------------------------------------------------------------------
# Drift check against the vendored Pulsar source
# ---------------------------------------------------------------------------

def _struct_fields(body: str) -> dict:
    out, skip = {}, False
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("#[validatron(skip)]"):
            skip = True
            continue
        m = re.match(r"(?:pub(?:\(crate\))?\s+)?(\w+)\s*:\s*([^,]+),?$", line)
        if m:
            if not skip:
                out[m.group(1)] = m.group(2).strip()
            skip = False
    return out


def drift_check(pulsar: Path, report: Report) -> None:
    ev = (pulsar / "crates/pulsar-core/src/event.rs").read_text(encoding="utf-8")
    m = re.search(r"pub enum Payload \{(.*?)\n\}", ev, re.S)
    if not m:
        report.errors.append("drift: could not find `pub enum Payload` in event.rs")
        return
    body = m.group(1)
    variants = {}
    for vm in re.finditer(r"(?:#\[validatron\(skip\)\]\s*)?(\w+)\s*(\{(.*?)\})?,", body, re.S):
        name = vm.group(1)
        variants[name] = _struct_fields(vm.group(3) or "")
    if set(variants) != set(PAYLOADS):
        report.errors.append(
            f"drift: Payload variants differ: source-only {sorted(set(variants) - set(PAYLOADS))}, "
            f"embedded-only {sorted(set(PAYLOADS) - set(variants))}"
        )
    for name, fields in variants.items():
        want = {k: RUST_TYPE[v] for k, v in PAYLOADS.get(name, {}).items()}
        if name in PAYLOADS and fields != want:
            report.errors.append(f"drift: Payload::{name} fields {fields} != embedded {want}")
    hm = re.search(r"pub struct Header \{(.*?)\n\}", ev, re.S)
    hf = _struct_fields(hm.group(1)) if hm else {}
    if hf != STRUCTS["Header"]:
        report.errors.append(f"drift: Header fields {hf} != embedded {STRUCTS['Header']}")
    hostm = re.search(r"pub struct Host \{(.*?)\n\}", ev, re.S)
    if not hostm or _struct_fields(hostm.group(1)) != STRUCTS["Host"]:
        report.errors.append("drift: Host struct changed")
    eng = (pulsar / "crates/modules/rules-engine/src/engine.rs").read_text(encoding="utf-8")
    cm = re.search(r"pub enum Category \{(.*?)\}", eng, re.S)
    cats = {re.sub(r"(?<!^)([A-Z])", r"_\1", c).lower() for c in re.findall(r"(\w+),", cm.group(1))}
    if cats != CATEGORIES:
        report.errors.append(f"drift: Category enum is {sorted(cats)}")
    um = re.search(r"pub struct UserRule \{(.*?)\}", eng, re.S)
    keys = {k.replace("r#", "") for k in re.findall(r"([\w#]+)\s*:", um.group(1))}
    if keys != set(REQUIRED_KEYS):
        report.errors.append(f"drift: UserRule keys are {sorted(keys)}")
    if 'RULE_EXTENSION: &str = "toml"' not in eng:
        report.errors.append("drift: RULE_EXTENSION is no longer \"toml\"")
    sm = re.search(r"pub enum Severity \{(.*?)\}", eng, re.S)
    sev = {s.lower() for s in re.findall(r"(\w+),", sm.group(1))} if sm else set()
    if sev != SEVERITIES:
        report.errors.append(f"drift: Severity enum is {sorted(sev)}")

    # The DSL grammar itself: operator tokens, keywords, precedence shape,
    # literal and identifier regexes, and the no-unescape value handling.
    lal = (pulsar / "crates/modules/rules-engine/src/dsl.lalrpop").read_text(encoding="utf-8")
    report.errors.extend(f"drift: dsl.lalrpop: {e}" for e in grammar_drift(lal))

    # FileFlags names (the only literals FileFlags accepts) and the operator
    # families each field type accepts.
    report.errors.extend(f"drift: {e}" for e in flags_drift(ev))
    bi = (pulsar / "crates/validatron/src/builtins.rs").read_text(encoding="utf-8")
    mod = (pulsar / "crates/pulsar-core/src/pdk/module.rs").read_text(encoding="utf-8")
    report.errors.extend(f"drift: {e}" for e in operator_drift(bi, ev, mod))
    cont = pulsar / "crates/bpf-common/src/containers/mod.rs"
    if cont.exists():
        cm2 = re.search(r"pub struct ContainerInfo \{(.*?)\n\}", cont.read_text(encoding="utf-8"), re.S)
        cf = _struct_fields(cm2.group(1)) if cm2 else {}
        if cf != STRUCTS["ContainerInfo"]:
            report.errors.append(f"drift: ContainerInfo fields {cf} != embedded {STRUCTS['ContainerInfo']}")
    else:
        report.errors.append("drift: bpf-common/src/containers/mod.rs not found")


# Grammar fragments this checker's parser hard-codes (whitespace-normalised).
_GRAMMAR_FINGERPRINT = (
    # AND and OR in ONE production, both left-recursive over SignedCondition:
    # equal precedence, left-associative.
    '<l:Condition> "AND" <r:SignedCondition> => Condition::And',
    '<l:Condition> "OR" <r:SignedCondition> => Condition::Or',
    # NOT applies to a SimpleCondition only.
    '"NOT" <b:SimpleCondition> => Condition::Not',
    '<f: FieldPath> "IN" <list: ValueList>',
    '"(" <Condition> ")"',
    # Literal value forms; escapes are not processed.
    r'''r#""([^"\\]|\\.)*""# => <>.trim_matches('"').to_string()''',
    'r"[0-9]+" => <>.to_string()',
    # Identifiers and method calls.
    r'r"[a-zA-Z]+\w*" => Identifier::Field',
    r'<r"[a-zA-Z]+\w*">"()" => Identifier::MethodCall',
    '"?" => OptCheck',
)


def _strip_actions(lal: str) -> str:
    """Drop Rust action code (`=> expr` / `=>? { .. }`) and `extern { .. }`."""
    out, i, n = [], 0, len(lal)
    while i < n:
        if lal.startswith("extern", i) or lal.startswith("=>", i):
            j = i + (6 if lal.startswith("extern", i) else 2)
            if lal.startswith("?", j):
                j += 1
            while j < n and lal[j] in " \t":
                j += 1
            if j < n and lal[j] == "{":
                depth = 0
                while j < n:
                    depth += {"{": 1, "}": -1}.get(lal[j], 0)
                    j += 1
                    if depth == 0:
                        break
            else:
                while j < n and lal[j] != "\n":
                    j += 1
            i = j
            continue
        out.append(lal[i])
        i += 1
    return "".join(out)


def grammar_drift(lal: str) -> list[str]:
    errs = []
    norm = re.sub(r"\s+", " ", lal)
    for frag in _GRAMMAR_FINGERPRINT:
        if re.sub(r"\s+", " ", frag) not in norm:
            errs.append(f"grammar fragment changed or missing: {frag}")
    ops = set(re.findall(r'"([^"]+)"\s*=>\s*Operator::', lal))
    if ops != OPERATORS:
        errs.append(f"operator tokens are {sorted(ops)}, checker knows {sorted(OPERATORS)}")
    # Production lines only (before "=>"): every quoted terminal must be one
    # the tokenizer knows, so a new keyword or punctuation fails loudly.
    terms = set()
    # Raw-string regex terminals (r#"..."#, r"...") are checked by the
    # fingerprint above; drop them before scanning for plain terminals.
    plain = re.sub(r'r"[^"]*"', "", re.sub(r'r#".*?"#', "", _strip_actions(lal)))
    for line in plain.splitlines():
        if line.lstrip().startswith(("//", "use ", "grammar", "type ")):
            continue
        terms |= set(re.findall(r'(?<![#r\w])"([^"\s]+)"(?![#\w])', line))
    known = KEYWORDS | OPERATORS | {"(", ")", "[", "]", ",", ".", "?", "()"}
    if terms - known:
        errs.append(f"unknown grammar terminals {sorted(terms - known)}")
    for kw in ("AND", "OR", "NOT", "IN"):
        if f'"{kw}"' not in lal:
            errs.append(f"keyword {kw} no longer in the grammar")
    return errs


def flags_drift(ev: str) -> list[str]:
    got = {}
    for name in ("ACC_MODE_FLAGS", "OTHER_FLAGS"):
        m = re.search(name + r"\s*:\s*\[[^\]]*\]\s*=\s*\[(.*?)\];", ev, re.S)
        got[name] = tuple(re.findall(r'\("(\w+)"', m.group(1))) if m else None
    errs = []
    if got["ACC_MODE_FLAGS"] != ACC_MODE_FLAGS:
        errs.append(f"FileFlags::ACC_MODE_FLAGS is {got['ACC_MODE_FLAGS']}")
    if got["OTHER_FLAGS"] != OTHER_FLAGS:
        errs.append(f"FileFlags::OTHER_FLAGS is {got['OTHER_FLAGS']}")
    return errs


_FAMILY = {"Relational": REL_OPS, "String": STR_OPS, "Multi": {"CONTAINS"}}


def _impl_block(src: str, header_re: str) -> str | None:
    """Text of the first `impl ... {` block matching header_re (brace-balanced)."""
    m = re.search(header_re, src)
    if not m:
        return None
    i = src.index("{", m.end() - 1)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return None


def _families(block: str) -> set[str]:
    """Operator families with an `Ok(...)` arm in an operator factory block."""
    fams = set()
    for fam in _FAMILY:
        # `Operator::Fam(op) => Ok(..)` or `=> match op { ... Ok(` -- i.e. the
        # family is matched explicitly; families only reached through `_ =>`
        # fall into the Err arm.
        if re.search(r"Operator::" + fam + r"\(", block):
            fams.add(fam)
    return fams


def operator_drift(builtins: str, ev: str, module: str) -> list[str]:
    """Check TYPE_OPS against the Validatron impls that define it."""
    errs = []
    blocks = {
        "String": _impl_block(builtins, r"impl Validatron for String\s*\{"),
        "IpAddr": _impl_block(builtins, r"impl Validatron for IpAddr\s*\{"),
        "bool": _impl_block(builtins, r"impl Validatron for bool\s*\{"),
        "ints": _impl_block(builtins, r"macro_rules! impl_numeric\s*\{"),
        "Argv": _impl_block(ev, r"impl Validatron for Argv\s*\{"),
        "FileFlags": _impl_block(ev, r"impl Validatron for FileFlags\s*\{"),
        "ModuleName": _impl_block(module, r"impl Validatron for ModuleName\s*\{"),
    }
    for ty, block in blocks.items():
        if block is None:
            errs.append(f"Validatron impl for {ty} not found")
            continue
        want = TYPE_OPS["u32" if ty == "ints" else ty]
        fams = _families(block)
        ops = set().union(*(_FAMILY[f] for f in fams)) if fams else set()
        if ty == "bool":
            # Relational family, but only Equals / NotEquals get an Ok arm.
            arms = set(re.findall(r"RelationalOperator::(\w+)\s*=>\s*Ok", block))
            ops = {"==" if a == "Equals" else "!=" if a == "NotEquals" else a for a in arms}
        if ops != want:
            errs.append(f"{ty} accepts {sorted(ops)} in the source, checker assumes {sorted(want)}")
    if not re.search(r"impl_numeric!\[i8, i16, i32, i64", builtins):
        errs.append("impl_numeric! no longer covers i32")
    return errs


# ---------------------------------------------------------------------------
# Self-test: the checker must reject what the real engine rejects.
# ---------------------------------------------------------------------------

# The rules/robot.toml that shipped before this validation (verbatim conditions).
_ORIGINAL_ROBOT_TOML = r'''
[[rules]]
name = "Robot controller spawns a shell"
type = "Exec"
category = "robotics"
condition = 'payload.filename IN ["/bin/sh", "/bin/bash", "/bin/dash"] AND header.image STARTS_WITH "/opt/ros"'

[[rules]]
name = "Outbound connection from robot controller to non-local network"
type = "Connect"
category = "robotics"
condition = 'header.image STARTS_WITH "/opt/ros" AND NOT (payload.destination.ip STARTS_WITH "10." OR payload.destination.ip STARTS_WITH "192.168.")'
'''


def _errs(text: str) -> list[str]:
    rep = Report()
    validate_text(text, "t", rep)
    return rep.errors


def _rule(cond: str, ty: str = "Exec", cat: str = "execution") -> str:
    return (f'[[rules]]\nname = "x"\ntype = "{ty}"\ncategory = "{cat}"\nseverity = "low"\n'
            f'description = "d"\ncondition = \'{cond}\'\n')


# (type, literal, does Rust std from_str accept it) -- generated with rustc 1.97.
_RUST_ORACLE = [
    ('u32', '1_000', False), ('i32', ' \uff10 ', False), ('i32', '\uff10', False),
    ('u32', ' 7', False), ('u32', '7 ', False), ('u32', '7\n', False), ('u32', '+7', True),
    ('u32', '-0', False), ('i32', '-0', True), ('i32', '+-1', False), ('u32', '+', False),
    ('i32', '-', False), ('u32', '', False), ('u32', '007', True), ('u32', '4294967295', True),
    ('u32', '4294967296', False), ('i32', '-2147483648', True), ('i32', '-2147483649', False),
    ('u16', '65536', False), ('usize', '18446744073709551615', True), ('u32', '\u0663', False),
    ('u32', '1e3', False), ('u32', '0x10', False),
    ('IpAddr', 'fe80::1%eth0', False), ('IpAddr', 'fe80::1%1', False),
    ('IpAddr', '10.0.0.1', True), ('IpAddr', '010.0.0.1', False), ('IpAddr', '10.0.0', False),
    ('IpAddr', '256.0.0.1', False), ('IpAddr', '::', True), ('IpAddr', '::ffff:1.2.3.4', True),
    ('IpAddr', '::ffff:01.2.3.4', False), ('IpAddr', '1:2:3:4:5:6:7::', True),
    ('IpAddr', '1:2:3:4:5:6:7:8::', False), ('IpAddr', '1:2:3:4:5:6:1.2.3.4', True),
    ('IpAddr', '1.2.3.4::', False), ('IpAddr', 'FE80::0001', True),
    ('IpAddr', 'fe80::00001', False), ('IpAddr', '\uff11.2.3.4', False),
    ('IpAddr', ' 1.2.3.4', False), ('IpAddr', '1.2.3.4\n', False), ('IpAddr', '[::1]', False),
    ('bool', 'True', False), ('bool', 'true', True), ('bool', ' false', False),
]


def self_test() -> int:
    cases = [
        # (toml, expect_ok, substring expected in the first error)
        (_ORIGINAL_ROBOT_TOML, False, "missing required key 'severity'"),
        (_rule('payload.filename == "/bin/sh"', cat="robotics"), False, "not a Pulsar Category"),
        (_rule('payload.destination.ip STARTS_WITH "10."', ty="Connect"), False, "not allowed on"),
        (_rule('payload.destination.ip >= "10.0.0.0"', ty="Connect"), True, ""),
        (_rule('payload.destination.ip == "10.0.0"', ty="Connect"), False, "not an IP"),
        (_rule('payload.argv STARTS_WITH "-i"'), False, "not allowed on"),
        (_rule('payload.argv IN ["-i"]'), False, "not allowed on"),
        (_rule('payload.argv CONTAINS "-i"'), True, ""),
        (_rule('payload.flags CONTAINS "O_WRITE"', ty="FileOpened"), False, "unknown flag"),
        (_rule('payload.flags CONTAINS "O_WRONLY"', ty="FileOpened"), True, ""),
        (_rule('payload.filename == "x"', ty="Connect"), False, "has no field"),
        (_rule('payload.destination == "1.2.3.4"', ty="Connect"), False, "struct"),
        (_rule('header.container.image == "x"'), False, "Option"),
        (_rule('header.container?.image == "x"'), True, ""),
        (_rule('header.container.is_some()'), True, ""),
        (_rule('header.image'), False, "non-bool"),
        (_rule('header.uid == "root"'), False, "does not parse"),
        (_rule('header.uid == 0'), True, ""),
        (_rule('payload.hard_link == true', ty="FileLink"), False, "paths must start"),
        (_rule('payload.hard_link == "true"', ty="FileLink"), True, ""),
        (_rule('payload.filename IN []'), False, "Empty list"),
        (_rule('payload.filename == "a" and header.uid == 0'), False, "unexpected token"),
        (_rule('header.image == payload.filename'), True, ""),
        (_rule('header.uid == payload.filename'), False, "compared to field"),
        (_rule('payload.filename == "a"', ty="Network"), False, "PayloadDiscriminant"),
        # Review PoC (rules-fool/fool.toml): Python int()/ipaddress accepted these,
        # Rust from_str rejects them -> the whole rules-engine would fail to load.
        (_rule('header.uid == "1_000"'), False, "does not parse"),
        (_rule('header.pid == " \uff10 "'), False, "does not parse"),
        (_rule('payload.destination.ip == "fe80::1%eth0"', ty="Connect"), False, "not an IP"),
        (_rule('header.uid == "-0"'), False, "does not parse"),
        (_rule('header.pid == "-0"'), True, ""),
        (_rule('header.uid == "4294967296"'), False, "out of range"),
        (_rule('payload.destination.port == "+80"', ty="Connect"), True, ""),
        (_rule('payload.destination.ip == "010.0.0.1"', ty="Connect"), False, "not an IP"),
        (_rule('payload.is_tcp == "True"', ty="Connect"), False, "bool"),
        # TOML basic-string escape smuggles U+001C into the condition.
        (_rule('header.uid == 0').replace("condition = 'header.uid == 0'",
                                          'condition = "header.uid ==\\u001c0"'),
         False, "unexpected character"),
        (_rule('header.uid ==\u30000'), True, ""),
        ("rules = []\n", True, ""),
        ("[rule]\nname='x'\n", False, "missing top-level"),
    ]
    fails = 0
    for i, (text, ok, needle) in enumerate(cases):
        errs = _errs(text)
        if ok and errs:
            print(f"self-test {i}: expected OK, got {errs}")
            fails += 1
        elif not ok and (not errs or needle not in errs[0]):
            print(f"self-test {i}: expected error containing {needle!r}, got {errs}")
            fails += 1
    # Precedence: 'a OR b AND c' must evaluate as '(a OR b) AND c'.
    ast = Parser('payload.filename == "a" OR payload.filename == "b" AND header.uid == 5').parse()
    ev = {"header": {"uid": 0}, "payload": {"filename": "a"}}
    if evaluate(ast, ev, "Exec") is not False:
        print("self-test precedence: expected left-assoc equal precedence")
        fails += 1
    # NOT binds to one simple condition only.
    ast = Parser('NOT payload.filename == "a" AND header.uid == 0').parse()
    if evaluate(ast, {"header": {"uid": 0}, "payload": {"filename": "b"}}, "Exec") is not True:
        print("self-test NOT binding failed")
        fails += 1
    # IpAddr ordering: all V4 < all V6.
    if not apply("<", "IpAddr", "255.255.255.255", "::"):
        print("self-test IpAddr ordering failed")
        fails += 1
    # FileFlags: O_RDONLY is an access-mode equality test, not a bit test.
    if apply("CONTAINS", "FileFlags", ["O_RDWR"], "O_RDONLY") or not apply(
        "CONTAINS", "FileFlags", ["O_CREAT"], "O_RDONLY"
    ):
        print("self-test FileFlags semantics failed")
        fails += 1
    # Differential corpus: expected values were produced by Rust 1.97 std
    # (u32/i32/u16/usize/bool/IpAddr ::from_str), the parsers validatron uses.
    # A 420k-case random differential run found no further disagreement.
    for ty, value, rust_ok in _RUST_ORACLE:
        if ty == "IpAddr":
            got = rust_parse_ip(value)
        elif ty == "bool":
            got = value in ("true", "false")
        else:
            got = rust_parse_int(ty, value) is not None
        if got != rust_ok:
            print(f"self-test oracle: {ty} {value!r}: validator {got}, Rust {rust_ok}")
            fails += 1
    total = len(cases) + 4 + len(_RUST_ORACLE)
    print(f"self-test: {total - fails}/{total} passed")
    return 1 if fails else 0


def drift_mutation_test(pulsar: Path) -> int:
    """The drift checks must notice grammar / type changes (mutated in memory)."""
    lal = (pulsar / "crates/modules/rules-engine/src/dsl.lalrpop").read_text(encoding="utf-8")
    ev = (pulsar / "crates/pulsar-core/src/event.rs").read_text(encoding="utf-8")
    bi = (pulsar / "crates/validatron/src/builtins.rs").read_text(encoding="utf-8")
    mod = (pulsar / "crates/pulsar-core/src/pdk/module.rs").read_text(encoding="utf-8")
    ip_hdr = "impl Validatron for IpAddr {"
    argv_hdr = "impl Validatron for Argv {"
    cases = [
        ("operator token renamed", grammar_drift(lal.replace('"ENDS_WITH" =>', '"ENDSWITH" =>'))),
        ("new operator added", grammar_drift(lal.replace(
            '"CONTAINS" =>', '"MATCHES" => Operator::String(StringOperator::Regex),\n    "CONTAINS" =>'))),
        ("OR given its own precedence level", grammar_drift(lal.replace(
            '<l:Condition> "OR" <r:SignedCondition>', '<l:Condition> "OR" <r:AndCondition>'))),
        ("NOT widened to a condition", grammar_drift(lal.replace(
            '"NOT" <b:SimpleCondition>', '"NOT" <b:Condition>'))),
        ("string escapes now processed", grammar_drift(lal.replace(".trim_matches('\"')", ".unescape()"))),
        ("new keyword", grammar_drift(lal.replace('"IN" <list: ValueList>', '"WITHIN" <list: ValueList>'))),
        ("FileFlags lost O_TRUNC", flags_drift(ev.replace('("O_TRUNC"', '("O_TRUNCATE"'))),
        ("IpAddr gained STARTS_WITH", operator_drift(
            bi.replace(ip_hdr, ip_hdr + " // Operator::String(op) => Ok\n"), ev, mod)),
        ("Argv gained relational ops", operator_drift(
            bi, ev.replace(argv_hdr, argv_hdr + " // Operator::Relational(op) => Ok\n"), mod)),
    ]
    fails = 0
    for label, errs in cases:
        if not errs:
            print(f"drift mutation test: '{label}' was NOT detected")
            fails += 1
    for label, errs in (("grammar", grammar_drift(lal)), ("flags", flags_drift(ev)),
                        ("operators", operator_drift(bi, ev, mod))):
        if errs:
            print(f"drift mutation test: unmutated {label} reports {errs}")
            fails += 1
    print(f"drift mutation test: {len(cases) + 3 - fails}/{len(cases) + 3} passed")
    return 1 if fails else 0


# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rules-dir", type=Path, default=root / "rules")
    ap.add_argument("--pulsar-src", type=Path, default=None,
                    help="Pulsar checkout (default: vendor/pulsar if populated)")
    ap.add_argument("--fixtures", type=Path, default=root / "scripts/rules_fixtures.json")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    rc = self_test()

    pulsar = args.pulsar_src
    if pulsar is None:
        cand = root / "vendor/pulsar"
        pulsar = cand if (cand / "crates/pulsar-core/src/event.rs").exists() else None
    if pulsar is not None and not (pulsar / "crates/pulsar-core/src/event.rs").exists():
        print(f"ERROR: --pulsar-src {pulsar} has no crates/pulsar-core/src/event.rs "
              "(submodule not checked out?)")
        return 1
    if pulsar is not None:
        rep = Report()
        rc |= drift_mutation_test(pulsar)
        drift_check(pulsar, rep)
        validate_dir(pulsar / "rules", rep)
        for e in rep.errors:
            print(f"ERROR (pulsar {pulsar}): {e}")
        print(f"calibration: {len(rep.rules)} upstream Pulsar rules type-check "
              f"({len(rep.errors)} errors), schema drift check "
              f"{'FAILED' if rep.errors else 'ok'}")
        rc |= 1 if rep.errors else 0
    else:
        print("note: no Pulsar source found; skipped drift check and upstream calibration "
              "(pass --pulsar-src /path/to/pulsar)")

    rep = Report()
    validate_dir(args.rules_dir, rep)
    nfx = run_fixtures(args.fixtures, rep.rules, rep) if args.fixtures.exists() else 0
    for w in rep.warnings:
        print(f"WARN: {w}")
    for e in rep.errors:
        print(f"ERROR: {e}")
    files = len({r.file for r in rep.rules})
    print(f"{args.rules_dir}: {len(rep.rules)} rules in {files} files, {nfx} fixtures, "
          f"{len(rep.errors)} errors, {len(rep.warnings)} warnings")
    if rep.errors or (args.strict and rep.warnings):
        rc |= 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
