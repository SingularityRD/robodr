#!/usr/bin/env python3
"""Keep docs/customer/detection-catalog.md in step with the rule catalog.

The trusted rule catalog lives in crates/robodr-ocsf/src/builder.rs:
`catalog_*` functions, one match arm per rule id (`"robot.x.y" => RuleInfo
{ .. }` or `"robot.x.y" => e(..)`), plus one entry per row of HOST_RULES
(crates/robodr-ocsf/src/host_rules.rs) where a catalog function calls
`host_rule_title`. The contract version of each catalog function ("Since")
is read from `rule_info_for_contract`, the function validators use: a call
gated by `with_X` takes the version of the `CATALOG_<major>_<minor>_MINOR`
constant in `with_X`, an ungated call 1.0, and a catalog function called by
another inherits its caller's version. A catalog function that
`rule_info_for_contract` does not reach fails the check. This script renders
the table between the GENERATED markers of the customer detection catalog.

    scripts/check-detection-catalog.py           # exit 1 when the doc drifted
    scripts/check-detection-catalog.py --write   # regenerate the table
    scripts/check-detection-catalog.py --self-test

Standard library only. It is a text check of the Rust source, not a Rust
build: an arm the pattern does not recognise makes the check fail (every
`"robot.*" =>` arm must be parsed), so a new arm style cannot slip through
unlisted.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "crates/robodr-ocsf/src/builder.rs"
HOST_RULES = ROOT / "crates/robodr-ocsf/src/host_rules.rs"
DOC = ROOT / "docs/customer/detection-catalog.md"
BEGIN = "<!-- BEGIN GENERATED: scripts/check-detection-catalog.py --write -->"
END = "<!-- END GENERATED -->"

STR = r'"((?:[^"\\]|\\.)*)"'
# An arm that spells all four fields: `RuleInfo { title: .., desc: ..,
# data_source: .., techniques: &[..] }`, or the 4-argument helper
# `e(title, desc, data_source, &[..])`.
ARM = re.compile(
    r'"(robot\.[a-z0-9_.]+)"\s*=>\s*(?:e\(|RuleInfo\s*\{)\s*'
    r"(?:title:\s*)?" + STR + r",\s*"
    r"(?:desc:\s*)?" + STR + r",\s*"
    r"(?:data_source:\s*)?([A-Za-z_0-9]+|" + STR + r"),\s*"
    r"(?:techniques:\s*)?&\[([^\]]*)\]"
)
# A local helper with no technique that fixes the remaining fields:
# `const fn e(title: .., desc: ..[, data_source: ..]) -> RuleInfo {
# RuleInfo { title, desc, data_source[: X], techniques: &[] } }`.
HELPER = re.compile(r"const fn e\(([^)]*)\)\s*->\s*RuleInfo\s*\{\s*RuleInfo\s*\{([^}]*)\}\s*\}")
ARG = r"(?:" + STR + r"|[A-Za-z_][A-Za-z_0-9]*)"
# `"robot.x" => e(arg, arg[, arg])`, each argument a literal or a constant.
ARM_HELPER = re.compile(
    r'"(robot\.[a-z0-9_.]+)"\s*=>\s*e\(\s*((?:' + ARG + r"\s*,\s*)*" + ARG + r")\s*,?\s*\)"
)
ARG_ITEM = re.compile(STR + r"|([A-Za-z_][A-Za-z_0-9]*)")
# `if let Some(title) = crate::host_rules::host_rule_title(rule) { return
# Some(e(title, "desc", DS)); }`: every row of HOST_RULES is an entry.
HOST_HOOK = re.compile(
    r"host_rules::host_rule_title\(rule\)\s*\{\s*return\s+Some\(\s*e\(\s*title\s*,\s*"
    + STR
    + r"\s*,\s*([A-Za-z_][A-Za-z_0-9]*)\s*,?\s*\)\s*\);"
)
HOST_ROW = re.compile(r"\(\s*" + STR + r"\s*,\s*" + STR + r"\s*,?\s*\)")
ANY_ARM = re.compile(r'"(robot\.[a-z0-9_.]+)"\s*=>')
CONST = re.compile(r"const ([A-Z_0-9]+): &str = " + STR + ";")
U64_CONST = re.compile(r"const ([A-Z_0-9]+): u64 = (\d+);")
TECH_CONST = re.compile(r"const (T\d{4}): \(&str, &str\) = \(" + STR + r", " + STR + r"\);")
TECH_INLINE = re.compile(r"\(" + STR + r",\s*" + STR + r"\)")
# A top-level function (column 0) with any visibility and qualifiers
# (`pub`, `pub(crate)`, `const`, ...): the boundaries of each body.
TOP_FN = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern(?:\s+\"[^\"]*\")?)\s+)*"
    r"fn\s+([A-Za-z_][A-Za-z_0-9]*)\s*[(<]",
    re.MULTILINE,
)
# Every `fn catalog_*` declaration at any indentation: each must also be a
# TOP_FN boundary, or its arms would be read as the previous function's.
ANY_CATALOG_FN = re.compile(r"\bfn\s+(catalog_[A-Za-z0-9_]*)\s*[(<]")
CALL = re.compile(r"\b(catalog_[A-Za-z0-9_]+)\s*\(")
GATED_CALL = re.compile(r"\b(with_[A-Za-z0-9_]+)\s*\.then\(\s*\|\|\s*(catalog_[A-Za-z0-9_]+)\s*\(")
WITH_LET = re.compile(r"\blet\s+(with_[A-Za-z0-9_]+)\s*=([^;]*);")
MINOR_REF = re.compile(r"\bCATALOG_(\d+)_(\d+)_MINOR\b")
BASE_VERSION = "1.0"


def fail(problems: list[str]) -> None:
    raise SystemExit("check-detection-catalog: " + "\n  ".join(["parse failed:"] + problems))


def functions(src: str) -> dict[str, str]:
    """Top-level function name -> its text up to the next top-level fn."""
    starts = [(m.start(), m.group(1)) for m in TOP_FN.finditer(src)]
    starts.append((len(src), ""))
    out: dict[str, str] = {}
    for (s, name), (e, _) in zip(starts, starts[1:]):
        out[name] = src[s:e]
    return out


def since_map(src: str, fns: dict[str, str]) -> dict[str, str]:
    """Contract version that added each catalog function's entries, read
    from `rule_info_for_contract`: a call gated by `with_X` gets the version
    named by the one `CATALOG_<major>_<minor>_MINOR` constant in `with_X`'s
    definition, an ungated call the base version 1.0, and a catalog
    function another one calls inherits its caller's version."""
    body = fns.get("rule_info_for_contract")
    if body is None:
        fail(["rule_info_for_contract not found"])
        return {}
    minors = {m.group(1): int(m.group(2)) for m in U64_CONST.finditer(src)}
    problems: list[str] = []
    gate: dict[str, str] = {}
    for m in WITH_LET.finditer(body):
        refs = set(MINOR_REF.findall(m.group(2)))
        if len(refs) != 1:
            problems.append(
                f"{m.group(1)}: expected one CATALOG_<major>_<minor>_MINOR, got {sorted(refs)}"
            )
            continue
        major, minor = refs.pop()
        const = f"CATALOG_{major}_{minor}_MINOR"
        if minors.get(const) != int(minor):
            problems.append(f"{const} is {minors.get(const)}, its name says {minor}")
        gate[m.group(1)] = f"{int(major)}.{int(minor)}"
    since: dict[str, str] = {}
    gated_at = set()
    for m in GATED_CALL.finditer(body):
        gated_at.add(m.start(2))
        if m.group(1) not in gate:
            problems.append(f"{m.group(2)} gated by {m.group(1)}, which has no version")
            continue
        since[m.group(2)] = gate[m.group(1)]
    for m in CALL.finditer(body):
        if m.start(1) not in gated_at:
            since[m.group(1)] = BASE_VERSION
    changed = True
    while changed:
        changed = False
        for name, ver in list(since.items()):
            text = fns.get(name, "")
            for m in CALL.finditer(text, text.find("(") + 1):
                callee = m.group(1)
                if callee == name:
                    continue
                if callee not in since:
                    since[callee] = ver
                    changed = True
                elif since[callee] != ver and f"{callee} reached as" not in " ".join(problems):
                    problems.append(f"{callee} reached as {since[callee]} and as {ver}")
    if problems:
        fail(problems)
    return since


def host_rows(host_src: str) -> list[tuple[str, str]]:
    """(Pulsar rule name, rule id) of every HOST_RULES row."""
    b = host_src.find("pub const HOST_RULES")
    if b == -1:
        fail(["HOST_RULES not found in the host-rules source"])
    e = host_src.find("];", b)
    return [(m.group(1), m.group(2)) for m in HOST_ROW.finditer(host_src[b:e])]


def parse(src: str, host_src: str = "") -> list[dict[str, str]]:
    """Every catalog entry, in source order."""
    # Strip the test module: its literals are not catalog entries.
    cut = src.find("\n#[cfg(test)]")
    if cut != -1:
        src = src[:cut]
    techs = {m.group(1): (m.group(2), m.group(3)) for m in TECH_CONST.finditer(src)}
    global_consts = {m.group(1): m.group(2) for m in CONST.finditer(src)}
    fns = functions(src)
    problems: list[str] = []
    declared = [m.group(1) for m in ANY_CATALOG_FN.finditer(src)]
    for name in declared:
        if name not in fns:
            problems.append(f"fn {name} is not a top-level function the parser can delimit")
    if len(declared) != len(set(declared)):
        problems.append("a catalog function is declared twice")
    for name, body in fns.items():
        if not name.startswith("catalog_"):
            for m in ANY_ARM.finditer(body):
                problems.append(f"{m.group(1)}: arm outside a catalog function (in {name})")
    if problems:
        fail(problems)
    since = since_map(src, fns)
    out: list[dict[str, str]] = []

    def add(rid: str, title: str, ds: str, attack: str, name: str) -> None:
        out.append(
            {
                "id": rid,
                "title": title.replace('\\"', '"'),
                "data_source": ds,
                "attack": attack,
                "since": since[name],
            }
        )

    for name, body in fns.items():
        if not name.startswith("catalog_"):
            continue
        if name not in since:
            problems.append(f"{name} is not reached from rule_info_for_contract")
            continue
        consts = dict(global_consts)
        consts.update({m.group(1): m.group(2) for m in CONST.finditer(body)})
        parsed = set()
        for m in ARM.finditer(body):
            rid, title, _desc, ds_raw, ds_lit, tech_raw = m.groups()
            ds = ds_lit if ds_lit is not None else consts.get(ds_raw, "")
            if not ds:
                problems.append(f"{rid}: data source {ds_raw} not resolved")
            names = [t for t in re.findall(r"T\d{4}", tech_raw) if t in techs]
            names += [m2.group(1) for m2 in TECH_INLINE.finditer(tech_raw)]
            add(rid, title, ds, ", ".join(dict.fromkeys(names)), name)
            parsed.add(m.start())
        helper = HELPER.search(body)
        params: list[str] = []
        fixed: dict[str, str] = {}
        if helper:
            params = [p.split(":")[0].strip() for p in helper.group(1).split(",") if p.strip()]
            for field in (f.strip() for f in helper.group(2).split(",")):
                if ":" in field:
                    k, v = (x.strip() for x in field.split(":", 1))
                    fixed[k] = v
            if "techniques" in params or fixed.get("techniques", "").replace(" ", "") != "&[]":
                helper = None  # a helper with techniques: only ARM applies
        for m in ARM_HELPER.finditer(body) if helper else ():
            if m.start() in parsed:
                continue
            args = [(a.group(1), a.group(2)) for a in ARG_ITEM.finditer(m.group(2))]
            if len(args) != len(params):
                continue  # reported below as not recognised
            vals = dict(zip(params, args))
            title_lit = vals.get("title", (None, None))[0]
            if title_lit is None:
                continue
            if "data_source" in vals:
                lit, ident = vals["data_source"]
                ds_name = ident or ""
                ds = lit if lit is not None else consts.get(ds_name, "")
            else:
                ds_name = fixed.get("data_source", "")
                ds = consts.get(ds_name, "")
            if not ds:
                problems.append(f"{m.group(1)}: data source {ds_name} not resolved")
            add(m.group(1), title_lit, ds, "", name)
            parsed.add(m.start())
        hook = HOST_HOOK.search(body)
        if hook:
            if not helper or params != ["title", "desc", "data_source"]:
                problems.append(
                    f"{name}: host_rule_title hook without an e(title, desc, data_source) helper"
                )
            else:
                ds = consts.get(hook.group(2), "")
                if not ds:
                    problems.append(f"{name}: host data source {hook.group(2)} not resolved")
                rows = host_rows(host_src)
                if not rows:
                    problems.append(f"{name}: calls host_rule_title but HOST_RULES has no row")
                for pulsar, rid in rows:
                    title = pulsar.removeprefix("RoboDR: ")
                    add(rid, title, ds, "", name)
        elif "host_rule_title" in body:
            problems.append(f"{name}: host_rule_title call not recognised by the parser")
        for m in ANY_ARM.finditer(body):
            if m.start() not in parsed:
                problems.append(f"{m.group(1)}: arm in {name} not recognised by the parser")
    ids = [o["id"] for o in out]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems.append(f"ids in more than one catalog entry: {dupes}")
    if problems:
        fail(problems)
    return out


def render(entries: list[dict[str, str]]) -> str:
    groups: dict[str, list[dict[str, str]]] = {}
    for e in sorted(entries, key=lambda e: e["id"]):
        ns = ".".join(e["id"].split(".")[:2])
        groups.setdefault(ns, []).append(e)
    lines = [BEGIN, ""]
    lines.append(
        f"{len(entries)} catalogued rule ids, plus the `robot.correlate.*` "
        "prefix entry for site-specific correlation rules."
    )
    for ns, rows in groups.items():
        lines += ["", f"### `{ns}.*` ({len(rows)})", ""]
        lines.append("| Rule id | Title | Data source | ATT&CK for ICS | Since |")
        lines.append("|---|---|---|---|---|")
        for r in rows:
            title = r["title"].replace("|", "\\|")
            lines.append(
                f"| `{r['id']}` | {title} | `{r['data_source']}` | "
                f"{r['attack'] or '—'} | {r['since']} |"
            )
    lines += ["", END]
    return "\n".join(lines)


def regenerate(builder_text: str, doc: str, host_text: str = "") -> tuple[str, int]:
    """`doc` with its generated block re-rendered, and the id count."""
    entries = parse(builder_text, host_text)
    b, e = doc.find(BEGIN), doc.find(END)
    if b == -1 or e == -1 or e < b:
        raise SystemExit("check-detection-catalog: GENERATED markers missing")
    return doc[:b] + render(entries) + doc[e + len(END):], len(entries)


def drift(builder_text: str, doc: str, host_text: str = "") -> list[str]:
    """Why `doc` is out of date (empty: up to date)."""
    new, _ = regenerate(builder_text, doc, host_text)
    if new == doc:
        return []
    code_ids = {x["id"] for x in parse(builder_text, host_text)}
    b, e = doc.find(BEGIN), doc.find(END)
    doc_ids = set(re.findall(r"^\| `(robot\.[a-z0-9_.]+)`", doc[b:e], re.M))
    out = [f"missing from the doc: {i}" for i in sorted(code_ids - doc_ids)]
    out += [f"in the doc, not in the catalog: {i}" for i in sorted(doc_ids - code_ids)]
    return out or ["a title, data source, technique or version changed"]


SELF_TEST_BUILDER = """
const T0855: (&str, &str) = ("T0855", "Unauthorized Command Message");
const AGENT: &str = "robodr_agent";
pub const CATALOG_1_3_MINOR: u64 = 3;
pub const CATALOG_2_3_MINOR: u64 = 3;
pub const CATALOG_2_5_MINOR: u64 = 5;
pub fn rule_info_for_contract(rule: &str, contract_version: &str) -> RuleInfo {
    let with_1_3 = major > LEGACY_CONTRACT_MAJOR || minor >= CATALOG_1_3_MINOR;
    let with_2_3 =
        major > CONTRACT_MAJOR || (major == CONTRACT_MAJOR && minor >= CATALOG_2_3_MINOR);
    let with_2_5 =
        major > CONTRACT_MAJOR || (major == CONTRACT_MAJOR && minor >= CATALOG_2_5_MINOR);
    catalog_1_0(rule)
        .or_else(|| with_1_3.then(|| catalog_1_3(rule)).flatten())
        .or_else(|| with_2_3.then(|| catalog_2_3(rule)).flatten())
        .or_else(|| with_2_5.then(|| catalog_2_5(rule)).flatten())
        .unwrap_or(GENERIC)
}
fn catalog_1_0(rule: &str) -> Option<RuleInfo> {
    Some(match rule {
        "robot.ros2.a" => RuleInfo {
            title: "A | pipe",
            desc: "d",
            data_source: "ros2_dds_discovery",
            techniques: &[T0855],
        },
        r if r.starts_with("robot.correlate.") => RuleInfo {
            title: "generic", desc: "d", data_source: AGENT, techniques: &[],
        },
        _ => return None,
    })
}
fn catalog_1_3(rule: &str) -> Option<RuleInfo> {
    catalog_1_3_wave7(rule)
}
fn catalog_1_3_wave7(rule: &str) -> Option<RuleInfo> {
    const MOTION: &str = "ros2_motion_commands";
    Some(match rule {
        "robot.motion.b" => e("B", "d", MOTION, &[("T0831", "Manipulation of Control")]),
        _ => return None,
    })
}
fn catalog_2_3(rule: &str) -> Option<RuleInfo> {
    catalog_2_3_depot(rule)
}
fn catalog_2_3_depot(rule: &str) -> Option<RuleInfo> {
    const DELIVERY: &str = "robodr_delivery";
    const fn e(title: &'static str, desc: &'static str) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source: DELIVERY,
            techniques: &[],
        }
    }
    Some(match rule {
        "robot.depot.c" => e(
            "C",
            "d",
        ),
        _ => return None,
    })
}
fn catalog_2_5(rule: &str) -> Option<RuleInfo> {
    const AGENT: &str = "robodr_agent";
    const HOST: &str = "host_runtime";
    const fn e(title: &'static str, desc: &'static str, data_source: &'static str) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source,
            techniques: &[],
        }
    }
    if let Some(title) = crate::host_rules::host_rule_title(rule) {
        return Some(e(
            title,
            "host rule",
            HOST,
        ));
    }
    Some(match rule {
        "robot.agent.d" => e("D", "d", AGENT),
        _ => return None,
    })
}
#[cfg(test)]
mod tests { fn t() { let _ = "robot.ros2.not_an_entry" => 1; } }
"""

SELF_TEST_HOST = """
pub const HOST_RULES: &[(&str, &str)] = &[
    // x.toml
    (
        "RoboDR: Host thing happened",
        "robot.host.thing",
    ),
];
"""


def check(cond: object, what: object = "") -> None:
    """An assertion that `python3 -O` does not remove."""
    if not cond:
        raise AssertionError(what)


def must_fail(builder: str, needle: str, what: str, host: str = SELF_TEST_HOST) -> None:
    try:
        parse(builder, host)
    except SystemExit as e:
        check(needle in str(e), e)
    else:
        raise AssertionError(f"{what} accepted")


def self_test() -> int:
    B, H = SELF_TEST_BUILDER, SELF_TEST_HOST
    try:
        check(False)
    except AssertionError:
        pass
    else:  # pragma: no cover - only if check() itself is broken
        raise SystemExit("check() does not fail")
    doc = f"head\n{BEGIN}\n{END}\ntail\n"
    entries = parse(B, H)
    got = {e["id"]: e for e in entries}
    check(
        set(got)
        == {"robot.ros2.a", "robot.motion.b", "robot.depot.c", "robot.agent.d", "robot.host.thing"},
        got,
    )
    check(got["robot.ros2.a"]["attack"] == "T0855" and got["robot.ros2.a"]["since"] == "1.0")
    check(got["robot.motion.b"]["data_source"] == "ros2_motion_commands")
    # catalog_1_3_wave7 inherits 1.3 from catalog_1_3, its caller.
    check(got["robot.motion.b"]["attack"] == "T0831" and got["robot.motion.b"]["since"] == "1.3")
    check(got["robot.depot.c"]["data_source"] == "robodr_delivery")
    check(got["robot.depot.c"]["since"] == "2.3", got["robot.depot.c"])
    check(got["robot.agent.d"]["data_source"] == "robodr_agent")
    check(got["robot.agent.d"]["since"] == "2.5", got["robot.agent.d"])
    # A HOST_RULES row: title without "RoboDR: ", the hook's data source.
    check(got["robot.host.thing"]["title"] == "Host thing happened", got["robot.host.thing"])
    check(got["robot.host.thing"]["data_source"] == "host_runtime")
    check(got["robot.host.thing"]["since"] == "2.5")
    # The version follows rule_info_for_contract's wiring, not a list here.
    moved = B.replace("with_2_3.then(|| catalog_2_3(rule))", "with_2_5.then(|| catalog_2_3(rule))")
    check({e["id"]: e for e in parse(moved, H)}["robot.depot.c"]["since"] == "2.5")
    # A stale doc fails and names the missing ids; the regenerated one passes.
    problems = drift(B, doc, H)
    check("missing from the doc: robot.depot.c" in problems, problems)
    fresh, n = regenerate(B, doc, H)
    check(n == 5 and drift(B, fresh, H) == [], (n, drift(B, fresh, H)))
    check(fresh.startswith("head\n") and fresh.endswith("tail\n"))
    check("A \\| pipe" in fresh, "a pipe in a title must not split the table")
    # An id removed from the code is reported as extra in the doc.
    smaller = B.replace('"robot.depot.c" => e(', '"robot.depot.x" => e(')
    check("in the doc, not in the catalog: robot.depot.c" in drift(smaller, fresh, H))
    # A removed host rule is drift too.
    check("in the doc, not in the catalog: robot.host.thing" in drift(B, fresh, H.replace("thing", "other")))
    # A changed title is drift too.
    check(drift(B.replace('"B"', '"B2"'), fresh, H))
    # An arm the parser does not understand fails instead of being skipped.
    must_fail(
        B.replace(
            "_ => return None,\n    })\n}\nfn catalog_1_3(",
            '"robot.ros2.z" => other(),\n        _ => return None,\n    })\n}\nfn catalog_1_3(',
            1,
        ),
        "robot.ros2.z",
        "unrecognised arm",
    )
    # A catalog function rule_info_for_contract does not reach fails (its
    # contract minor is unknown).
    must_fail(B.replace("fn catalog_2_3_depot", "fn catalog_9_9"), "catalog_9_9", "unknown catalog function")
    # ... whatever its visibility or qualifiers: `pub`, `pub(crate)` and
    # `const fn` are function boundaries too, so the new function's arms are
    # not taken as the previous function's.
    for vis in ("pub fn", "pub(crate) fn", "const fn", "pub(crate) const fn"):
        must_fail(B.replace("fn catalog_2_3_depot", f"{vis} catalog_9_9"), "catalog_9_9", vis)
        visible = B.replace("fn catalog_2_3_depot", f"{vis} catalog_2_3_depot")
        check({e["id"]: e for e in parse(visible, H)}["robot.depot.c"]["since"] == "2.3", vis)
    # A catalog function nested where no boundary is seen fails.
    must_fail(
        B.replace("fn catalog_2_3_depot", "    fn catalog_2_3_depot"),
        "catalog_2_3_depot",
        "indented catalog function",
    )
    # A version gate without its CATALOG_*_MINOR constant fails, and so
    # does a constant whose value disagrees with its name.
    must_fail(
        B.replace("minor >= CATALOG_2_5_MINOR", "minor >= 5"),
        "with_2_5",
        "gate without a CATALOG_*_MINOR constant",
    )
    must_fail(
        B.replace("CATALOG_2_5_MINOR: u64 = 5", "CATALOG_2_5_MINOR: u64 = 6"),
        "CATALOG_2_5_MINOR",
        "mismatched minor constant",
    )
    # The same id in two catalog entries fails, a host id included.
    must_fail(B.replace('"robot.depot.c" => e(', '"robot.ros2.a" => e('), "more than one", "duplicate id")
    must_fail(B, "more than one", "duplicate host id", H.replace("robot.host.thing", "robot.agent.d"))
    # A host hook the parser does not understand fails.
    must_fail(B.replace('"host rule",', "DESC,"), "host_rule_title", "unrecognised host hook")
    print("check-detection-catalog self-test: ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="regenerate the table in place")
    ap.add_argument("--self-test", action="store_true", help="test the parser and the check")
    ap.add_argument("--builder", type=Path, default=BUILDER)
    ap.add_argument("--host-rules", type=Path, default=HOST_RULES)
    ap.add_argument("--doc", type=Path, default=DOC)
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    builder_text = a.builder.read_text(encoding="utf-8")
    host_text = a.host_rules.read_text(encoding="utf-8")
    doc = a.doc.read_text(encoding="utf-8")
    new, n = regenerate(builder_text, doc, host_text)
    if a.write:
        if new != doc:
            a.doc.write_text(new, encoding="utf-8")
        print(f"{a.doc}: {n} rule ids")
        return 0
    problems = drift(builder_text, doc, host_text)
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        print(
            f"{a.doc} is out of date with {a.builder}: run "
            "scripts/check-detection-catalog.py --write",
            file=sys.stderr,
        )
        return 1
    print(f"{a.doc}: up to date ({n} rule ids)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
