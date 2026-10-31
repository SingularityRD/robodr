#!/usr/bin/env python3
"""Keep docs/customer/detection-catalog.md in step with the rule catalog.

The trusted rule catalog lives in crates/robodr-ocsf/src/builder.rs: one
`catalog_*` function per contract minor, one match arm per rule id
(`"robot.x.y" => RuleInfo { .. }` or `"robot.x.y" => e(..)`). This script
reads those arms and renders the table between the GENERATED markers of the
customer detection catalog.

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
DOC = ROOT / "docs/customer/detection-catalog.md"
BEGIN = "<!-- BEGIN GENERATED: scripts/check-detection-catalog.py --write -->"
END = "<!-- END GENERATED -->"

# Contract version that added each catalog function's entries
# (builder.rs `rule_info_for_contract`).
SINCE = {
    "catalog_1_0": "1.0",
    "catalog_1_3": "1.3",
    "catalog_1_3_wave7": "1.3",
    "catalog_2_1": "2.1",
    "catalog_2_2": "2.2",
    "catalog_2_3": "2.3",
    "catalog_2_3_depot": "2.3",
    "catalog_2_3_seal": "2.3",
    "catalog_2_3_gateway": "2.3",
    "catalog_2_3_unitree": "2.3",
    "catalog_2_4": "2.4",
}

STR = r'"((?:[^"\\]|\\.)*)"'
ARM = re.compile(
    r'"(robot\.[a-z0-9_.]+)"\s*=>\s*(?:e\(|RuleInfo\s*\{)\s*'
    r"(?:title:\s*)?" + STR + r",\s*"
    r"(?:desc:\s*)?" + STR + r",\s*"
    r"(?:data_source:\s*)?([A-Za-z_0-9]+|" + STR + r"),\s*"
    r"(?:techniques:\s*)?&\[([^\]]*)\]"
)
# `e(title, desc)`: a block whose helper fixes the data source and no
# technique (`const fn e(title, desc) -> RuleInfo { .. data_source: X, .. }`).
ARM2 = re.compile(r'"(robot\.[a-z0-9_.]+)"\s*=>\s*e\(\s*' + STR + r",\s*" + STR + r",?\s*\)")
E2 = re.compile(
    r"const fn e\(title: &'static str, desc: &'static str\) -> RuleInfo \{\s*RuleInfo \{"
    r"\s*title,\s*desc,\s*data_source: ([A-Z_0-9]+),\s*techniques: &\[\],"
)
ANY_ARM = re.compile(r'"(robot\.[a-z0-9_.]+)"\s*=>')
CONST = re.compile(r"const ([A-Z_0-9]+): &str = " + STR + ";")
TECH_CONST = re.compile(r"const (T\d{4}): \(&str, &str\) = \(" + STR + r", " + STR + r"\);")
TECH_INLINE = re.compile(r"\(" + STR + r",\s*" + STR + r"\)")
FN = re.compile(r"\nfn (catalog_[0-9a-z_]+)\(")


def parse(src: str) -> list[dict[str, str]]:
    """Every catalog entry, in source order."""
    # Strip the test module: its literals are not catalog entries.
    cut = src.find("\n#[cfg(test)]")
    if cut != -1:
        src = src[:cut]
    techs = {m.group(1): (m.group(2), m.group(3)) for m in TECH_CONST.finditer(src)}
    global_consts = {m.group(1): m.group(2) for m in CONST.finditer(src)}
    starts = [(m.start(), m.group(1)) for m in FN.finditer(src)]
    starts.append((len(src), ""))
    out: list[dict[str, str]] = []
    problems: list[str] = []
    for (s, name), (e, _) in zip(starts, starts[1:]):
        if name not in SINCE:
            problems.append(f"unknown catalog function {name}: add it to SINCE")
            continue
        body = src[s:e]
        consts = dict(global_consts)
        consts.update({m.group(1): m.group(2) for m in CONST.finditer(body)})
        parsed = set()
        for m in ARM.finditer(body):
            rid, title, _desc, ds_raw, ds_lit, tech_raw = m.groups()
            ds = ds_lit if ds_lit is not None else consts.get(ds_raw, "")
            if not ds:
                problems.append(f"{rid}: data source {ds_raw} not resolved")
            names = []
            for t in re.findall(r"T\d{4}", tech_raw):
                if t in techs:
                    names.append(t)
            for m2 in TECH_INLINE.finditer(tech_raw):
                names.append(m2.group(1))
            out.append(
                {
                    "id": rid,
                    "title": title.replace('\\"', '"'),
                    "data_source": ds,
                    "attack": ", ".join(dict.fromkeys(names)),
                    "since": SINCE[name],
                }
            )
            parsed.add(m.start())
        helper = E2.search(body)
        for m in ARM2.finditer(body) if helper else ():
            if m.start() in parsed:
                continue
            ds = consts.get(helper.group(1), "")
            if not ds:
                problems.append(f"{m.group(1)}: data source {helper.group(1)} not resolved")
            out.append(
                {
                    "id": m.group(1),
                    "title": m.group(2).replace('\\"', '"'),
                    "data_source": ds,
                    "attack": "",
                    "since": SINCE[name],
                }
            )
            parsed.add(m.start())
        for m in ANY_ARM.finditer(body):
            if m.start() not in parsed:
                problems.append(f"{m.group(1)}: arm in {name} not recognised by the parser")
    ids = [o["id"] for o in out]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems.append(f"ids in more than one catalog function: {dupes}")
    if problems:
        raise SystemExit("check-detection-catalog: " + "\n  ".join(["parse failed:"] + problems))
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


def regenerate(builder_text: str, doc: str) -> tuple[str, int]:
    """`doc` with its generated block re-rendered, and the id count."""
    entries = parse(builder_text)
    b, e = doc.find(BEGIN), doc.find(END)
    if b == -1 or e == -1 or e < b:
        raise SystemExit("check-detection-catalog: GENERATED markers missing")
    return doc[:b] + render(entries) + doc[e + len(END):], len(entries)


def drift(builder_text: str, doc: str) -> list[str]:
    """Why `doc` is out of date (empty: up to date)."""
    new, _ = regenerate(builder_text, doc)
    if new == doc:
        return []
    code_ids = {x["id"] for x in parse(builder_text)}
    b, e = doc.find(BEGIN), doc.find(END)
    doc_ids = set(re.findall(r"^\| `(robot\.[a-z0-9_.]+)`", doc[b:e], re.M))
    out = [f"missing from the doc: {i}" for i in sorted(code_ids - doc_ids)]
    out += [f"in the doc, not in the catalog: {i}" for i in sorted(doc_ids - code_ids)]
    return out or ["a title, data source, technique or version changed"]


SELF_TEST_BUILDER = """
const T0855: (&str, &str) = ("T0855", "Unauthorized Command Message");
const AGENT: &str = "robodr_agent";
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
fn catalog_1_3_wave7(rule: &str) -> Option<RuleInfo> {
    const MOTION: &str = "ros2_motion_commands";
    Some(match rule {
        "robot.motion.b" => e("B", "d", MOTION, &[("T0831", "Manipulation of Control")]),
        _ => return None,
    })
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
#[cfg(test)]
mod tests { fn t() { let _ = "robot.ros2.not_an_entry" => 1; } }
"""


def self_test() -> int:
    doc = f"head\n{BEGIN}\n{END}\ntail\n"
    entries = parse(SELF_TEST_BUILDER)
    got = {e["id"]: e for e in entries}
    assert set(got) == {"robot.ros2.a", "robot.motion.b", "robot.depot.c"}, got
    assert got["robot.ros2.a"]["attack"] == "T0855" and got["robot.ros2.a"]["since"] == "1.0"
    assert got["robot.motion.b"]["data_source"] == "ros2_motion_commands"
    assert got["robot.motion.b"]["attack"] == "T0831" and got["robot.motion.b"]["since"] == "1.3"
    assert got["robot.depot.c"]["data_source"] == "robodr_delivery"
    assert got["robot.depot.c"]["since"] == "2.3"
    # A stale doc fails and names the missing ids; the regenerated one passes.
    problems = drift(SELF_TEST_BUILDER, doc)
    assert "missing from the doc: robot.depot.c" in problems, problems
    fresh, n = regenerate(SELF_TEST_BUILDER, doc)
    assert n == 3 and drift(SELF_TEST_BUILDER, fresh) == []
    assert fresh.startswith("head\n") and fresh.endswith("tail\n")
    assert "A \\| pipe" in fresh, "a pipe in a title must not split the table"
    # An id removed from the code is reported as extra in the doc.
    smaller = SELF_TEST_BUILDER.replace('"robot.depot.c" => e(', '"robot.depot.x" => e(')
    assert "in the doc, not in the catalog: robot.depot.c" in drift(smaller, fresh)
    # A changed title is drift too.
    assert drift(SELF_TEST_BUILDER.replace('"B"', '"B2"'), fresh)
    # An arm the parser does not understand fails instead of being skipped.
    odd = SELF_TEST_BUILDER.replace(
        "_ => return None,\n    })\n}\nfn catalog_1_3_wave7",
        '"robot.ros2.z" => other(),\n        _ => return None,\n    })\n}\nfn catalog_1_3_wave7',
        1,
    )
    try:
        parse(odd)
    except SystemExit as e:
        assert "robot.ros2.z" in str(e), e
    else:
        raise AssertionError("unrecognised arm accepted")
    # An unknown catalog function fails (its contract minor is unknown).
    try:
        parse(SELF_TEST_BUILDER.replace("fn catalog_2_3_depot", "fn catalog_9_9"))
    except SystemExit as e:
        assert "catalog_9_9" in str(e), e
    else:
        raise AssertionError("unknown catalog function accepted")
    # The same id in two catalog functions fails.
    try:
        parse(SELF_TEST_BUILDER.replace('"robot.depot.c" => e(', '"robot.ros2.a" => e('))
    except SystemExit as e:
        assert "more than one" in str(e), e
    else:
        raise AssertionError("duplicate id accepted")
    print("check-detection-catalog self-test: ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="regenerate the table in place")
    ap.add_argument("--self-test", action="store_true", help="test the parser and the check")
    ap.add_argument("--builder", type=Path, default=BUILDER)
    ap.add_argument("--doc", type=Path, default=DOC)
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    builder_text = a.builder.read_text(encoding="utf-8")
    doc = a.doc.read_text(encoding="utf-8")
    new, n = regenerate(builder_text, doc)
    if a.write:
        if new != doc:
            a.doc.write_text(new, encoding="utf-8")
        print(f"{a.doc}: {n} rule ids")
        return 0
    problems = drift(builder_text, doc)
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
