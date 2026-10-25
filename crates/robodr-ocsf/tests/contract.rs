//! Contract tests: the JSON Schema and the example in docs/contracts must
//! match what the builder produces.
//!
//! No external JSON-Schema validator is available, so this implements the
//! subset the schema file uses: `$ref` (local `#/$defs/...`), `type`,
//! `required`, `properties`, `additionalProperties: false`, `items`, `const`,
//! `enum`, `minLength`/`maxLength`, `minimum`/`maximum`, `maxItems`, and
//! `pattern` — evaluated with the small hand-written matcher in [`re`], which
//! supports exactly the regex subset the schema uses (anchors, literals,
//! `\`-escapes, character classes with ranges, groups with alternation, and
//! the quantifiers `* + ? {n} {m,n}`) and panics on anything else, so a new
//! pattern the matcher cannot evaluate fails the tests instead of being
//! silently skipped.

mod common;

use serde_json::Value;
use std::cell::Cell;
use std::path::PathBuf;

/// Minimal backtracking matcher for the schema's `pattern` subset.
mod re {
    #[derive(Debug)]
    enum Node {
        Char(char),
        Class(Vec<(char, char)>),
        Group(Vec<Vec<Piece>>),
    }

    #[derive(Debug)]
    struct Piece {
        node: Node,
        min: usize,
        max: usize,
    }

    #[derive(Debug)]
    pub struct Regex {
        seq: Vec<Piece>,
        end_anchor: bool,
    }

    struct P<'a> {
        s: &'a [char],
        i: usize,
        src: &'a str,
    }

    impl P<'_> {
        fn peek(&self) -> Option<char> {
            self.s.get(self.i).copied()
        }
        fn next(&mut self) -> char {
            let c = self
                .peek()
                .unwrap_or_else(|| panic!("pattern {:?}: unexpected end", self.src));
            self.i += 1;
            c
        }
        fn unsupported(&self, what: &str) -> ! {
            panic!("pattern {:?}: unsupported {what} at {}", self.src, self.i)
        }
        fn escaped(&mut self) -> char {
            match self.next() {
                c @ ('.' | '?' | '\\' | '-' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}'
                | '|' | '^' | '$' | '/') => c,
                c => self.unsupported(&format!("escape \\{c}")),
            }
        }
        fn alts(&mut self) -> Vec<Vec<Piece>> {
            let mut alts = vec![self.seq()];
            while self.peek() == Some('|') {
                self.i += 1;
                alts.push(self.seq());
            }
            alts
        }
        fn seq(&mut self) -> Vec<Piece> {
            let mut out = Vec::new();
            while let Some(c) = self.peek() {
                if c == '|' || c == ')' || (c == '$' && self.i + 1 == self.s.len()) {
                    break;
                }
                self.i += 1;
                let node = match c {
                    '\\' => Node::Char(self.escaped()),
                    '[' => self.class(),
                    '(' => {
                        let g = self.alts();
                        if self.next() != ')' {
                            self.unsupported("group");
                        }
                        Node::Group(g)
                    }
                    '.' | '^' | '$' | '*' | '+' | '?' | '{' | '}' | ']' => {
                        self.unsupported(&format!("metacharacter {c}"))
                    }
                    c => Node::Char(c),
                };
                let (min, max) = self.quant();
                out.push(Piece { node, min, max });
            }
            out
        }
        fn class(&mut self) -> Node {
            if self.peek() == Some('^') {
                self.unsupported("negated class");
            }
            let mut ranges = Vec::new();
            loop {
                let c = match self.next() {
                    ']' => break,
                    '\\' => self.escaped(),
                    '[' => self.unsupported("nested class"),
                    c => c,
                };
                let is_range = self.peek() == Some('-') && self.s.get(self.i + 1) != Some(&']');
                if is_range {
                    self.i += 1;
                    let hi = match self.next() {
                        '\\' => self.escaped(),
                        c => c,
                    };
                    assert!(c <= hi, "pattern {:?}: bad range", self.src);
                    ranges.push((c, hi));
                } else {
                    ranges.push((c, c));
                }
            }
            Node::Class(ranges)
        }
        fn num(&mut self) -> usize {
            let st = self.i;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
            let t: String = self.s[st..self.i].iter().collect();
            t.parse().unwrap_or_else(|_| self.unsupported("quantifier"))
        }
        fn quant(&mut self) -> (usize, usize) {
            let q = match self.peek() {
                Some('*') => (0, usize::MAX),
                Some('+') => (1, usize::MAX),
                Some('?') => (0, 1),
                Some('{') => {
                    self.i += 1;
                    let a = self.num();
                    let b = if self.peek() == Some(',') {
                        self.i += 1;
                        self.num()
                    } else {
                        a
                    };
                    if self.peek() != Some('}') {
                        self.unsupported("quantifier");
                    }
                    (a, b)
                }
                _ => return (1, 1),
            };
            self.i += 1;
            if matches!(self.peek(), Some('?' | '+')) {
                self.unsupported("lazy/possessive quantifier");
            }
            q
        }
    }

    impl Regex {
        /// Compile; panics on syntax outside the supported subset.
        pub fn new(src: &str) -> Regex {
            let chars: Vec<char> = src.chars().collect();
            let mut p = P {
                s: &chars,
                i: 0,
                src,
            };
            if p.peek() != Some('^') {
                p.unsupported("unanchored pattern");
            }
            p.i += 1;
            let alts = p.alts();
            let end_anchor = p.peek() == Some('$');
            if end_anchor {
                p.i += 1;
            }
            if p.i != chars.len() {
                p.unsupported("trailing syntax");
            }
            let seq = if alts.len() == 1 {
                alts.into_iter().next().unwrap()
            } else {
                vec![Piece {
                    node: Node::Group(alts),
                    min: 1,
                    max: 1,
                }]
            };
            Regex { seq, end_anchor }
        }

        pub fn is_match(&self, s: &str) -> bool {
            let s: Vec<char> = s.chars().collect();
            let n = s.len();
            m_seq(&self.seq, &s, 0, &mut |end| !self.end_anchor || end == n)
        }
    }

    type K<'k> = &'k mut dyn FnMut(usize) -> bool;

    fn m_seq(seq: &[Piece], s: &[char], pos: usize, k: K) -> bool {
        match seq.split_first() {
            None => k(pos),
            Some((p, rest)) => m_rep(p, 0, rest, s, pos, k),
        }
    }

    fn m_rep(p: &Piece, count: usize, rest: &[Piece], s: &[char], pos: usize, k: K) -> bool {
        if count < p.max
            && m_node(&p.node, s, pos, &mut |np| {
                np != pos && m_rep(p, count + 1, rest, s, np, k)
            })
        {
            return true;
        }
        count >= p.min && m_seq(rest, s, pos, k)
    }

    fn m_node(n: &Node, s: &[char], pos: usize, k: K) -> bool {
        match n {
            Node::Char(c) => s.get(pos) == Some(c) && k(pos + 1),
            Node::Class(r) => {
                s.get(pos)
                    .is_some_and(|c| r.iter().any(|(lo, hi)| (lo..=hi).contains(&c)))
                    && k(pos + 1)
            }
            Node::Group(alts) => {
                for a in alts {
                    if m_seq(a, s, pos, k) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

thread_local! {
    /// Number of `pattern` evaluations, to prove the checker visits them.
    static PATTERN_CHECKS: Cell<usize> = const { Cell::new(0) };
}

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts")
}

fn load(name: &str) -> String {
    std::fs::read_to_string(contracts_dir().join(name))
        .unwrap_or_else(|e| panic!("cannot read docs/contracts/{name}: {e}"))
}

fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let ptr = r.strip_prefix('#').expect("only local refs");
            resolve(
                root,
                root.pointer(ptr).unwrap_or_else(|| panic!("bad $ref {r}")),
            )
        }
        None => schema,
    }
}

fn check(root: &Value, schema: &Value, inst: &Value, path: &str, errs: &mut Vec<String>) {
    let s = resolve(root, schema);
    if let Some(c) = s.get("const") {
        if c != inst {
            errs.push(format!("{path}: expected const {c}, got {inst}"));
        }
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(inst) {
            errs.push(format!("{path}: {inst} not in enum"));
        }
    }
    if let Some(t) = s.get("type").and_then(Value::as_str) {
        let ok = match t {
            "object" => inst.is_object(),
            "array" => inst.is_array(),
            "string" => inst.is_string(),
            "integer" => inst.is_u64() || inst.is_i64(),
            "number" => inst.is_number(),
            "boolean" => inst.is_boolean(),
            _ => panic!("unsupported type {t}"),
        };
        if !ok {
            errs.push(format!("{path}: expected {t}"));
            return;
        }
    }
    if let Some(st) = inst.as_str() {
        let n = st.chars().count() as u64;
        if s.get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: longer than maxLength"));
        }
        if s.get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n < m)
        {
            errs.push(format!("{path}: shorter than minLength"));
        }
        if let Some(p) = s.get("pattern").and_then(Value::as_str) {
            PATTERN_CHECKS.with(|c| c.set(c.get() + 1));
            if !re::Regex::new(p).is_match(st) {
                errs.push(format!("{path}: {st:?} does not match pattern {p}"));
            }
        }
    }
    if let Some(x) = inst.as_f64() {
        if s.get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|m| x < m)
        {
            errs.push(format!("{path}: below minimum"));
        }
        if s.get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|m| x > m)
        {
            errs.push(format!("{path}: above maximum"));
        }
    }
    if let Some(obj) = inst.as_object() {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for k in req {
                let k = k.as_str().unwrap();
                if !obj.contains_key(k) {
                    errs.push(format!("{path}: missing required key `{k}`"));
                }
            }
        }
        let props = s.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            let sub = format!("{path}/{k}");
            match props.and_then(|p| p.get(k)) {
                Some(ps) => check(root, ps, v, &sub, errs),
                None => {
                    if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                        errs.push(format!("{sub}: key not declared in schema"));
                    }
                }
            }
        }
    }
    if let Some(arr) = inst.as_array() {
        if s.get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| arr.len() as u64 > m)
        {
            errs.push(format!("{path}: too many items"));
        }
        if let Some(items) = s.get("items") {
            for (i, v) in arr.iter().enumerate() {
                check(root, items, v, &format!("{path}/{i}"), errs);
            }
        }
    }
}

fn schema_errors(inst: &Value) -> Vec<String> {
    let schema: Value = serde_json::from_str(&load("robodr-finding.schema.json"))
        .expect("schema file is valid JSON");
    let mut errs = vec![];
    check(&schema, &schema, inst, "", &mut errs);
    errs
}

/// Collect every `required` key list in the schema, to prove the walk above
/// actually visits them (guards against the checker silently skipping).
fn count_required(v: &Value) -> usize {
    match v {
        Value::Object(m) => {
            m.get("required")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
                + m.values().map(count_required).sum::<usize>()
        }
        Value::Array(a) => a.iter().map(count_required).sum(),
        _ => 0,
    }
}

#[test]
fn produced_finding_contains_every_required_schema_key() {
    let f = common::example_finding();
    let inst: Value = serde_json::from_str(&robodr_ocsf::to_json(&f).unwrap()).unwrap();
    let errs = schema_errors(&inst);
    assert!(errs.is_empty(), "schema violations:\n{}", errs.join("\n"));
    let schema: Value = serde_json::from_str(&load("robodr-finding.schema.json")).unwrap();
    assert!(
        count_required(&schema) > 80,
        "schema lost its required lists"
    );
}

#[test]
fn minimal_and_maximal_findings_match_schema() {
    use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
    let ctx = common::ctx();
    // Minimal: no subject, no evidence, no techniques.
    let dev = Deviation::new("robot.custom.rule", Severity::Low, "x");
    let min = robodr_ocsf::FindingBuilder::from_deviation(&dev, &ctx)
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    // Maximal-ish: command with envelope, anomaly score, bus id, all ROS ids.
    let cmd = MotionCommand {
        channel: "/cmd_vel".into(),
        source_guid: Some("aa".into()),
        linear_speed: Some(2.0),
        joint_speed: Some(0.5),
        angular_speed: None,
        ..Default::default()
    };
    let dev = Deviation::new("robot.motion.linear_over_envelope", Severity::High, "x");
    let env = robodr_events::profile::Envelope {
        max_linear_speed: Some(1.0),
        max_joint_speed: Some(1.0),
        ..Default::default()
    };
    let max = robodr_ocsf::FindingBuilder::from_deviation(&dev, &ctx)
        .event(&RobotEvent::MotionCommand(cmd.clone()))
        .command(&cmd, Some(&env))
        .subject(robodr_ocsf::Subject {
            participant_guid: Some("aa".into()),
            node: Some("/teleop".into()),
            topic: Some("/cmd_vel".into()),
            type_name: Some("Twist".into()),
            src_ip: Some("10.0.0.9".into()),
        })
        .anomaly_score(0.9)
        .bus_message_id(7)
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    for f in [min, max] {
        let inst = serde_json::to_value(&f).unwrap();
        let errs = schema_errors(&inst);
        assert!(errs.is_empty(), "schema violations:\n{}", errs.join("\n"));
    }
}

#[test]
fn schema_checker_detects_missing_and_undeclared_keys() {
    let f = common::example_finding();
    let mut inst = serde_json::to_value(&f).unwrap();
    inst.as_object_mut().unwrap().remove("finding_id");
    inst["ocsf"]["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("uid");
    inst["ocsf"]["surprise"] = 1.into();
    let errs = schema_errors(&inst);
    assert!(errs.iter().any(|e| e.contains("`finding_id`")));
    assert!(errs
        .iter()
        .any(|e| e.contains("/ocsf/metadata: missing required key `uid`")));
    assert!(errs.iter().any(|e| e.contains("/ocsf/surprise")));
}

#[test]
fn contract_example_file_is_exactly_what_the_builder_produces() {
    let f = common::example_finding();
    let produced = serde_json::to_string_pretty(&f).unwrap() + "\n";
    let on_disk = load("robodr-finding.example.json");
    if produced != on_disk {
        eprintln!("---- regenerate docs/contracts/robodr-finding.example.json ----\n{produced}");
    }
    assert_eq!(produced, on_disk, "contract example is stale");
    // And the example itself passes the strict validator.
    assert_eq!(robodr_ocsf::parse_and_validate(&on_disk).unwrap(), f);
}

// ------------------------------------------------------- SR-TAINT patterns --

fn schema() -> Value {
    serde_json::from_str(&load("robodr-finding.schema.json")).unwrap()
}

fn collect_patterns(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            if let Some(p) = m.get("pattern").and_then(Value::as_str) {
                out.push(p.to_string());
            }
            m.values().for_each(|x| collect_patterns(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| collect_patterns(x, out)),
        _ => {}
    }
}

#[test]
fn matcher_semantics() {
    let r = re::Regex::new(r"^T[0-9]{4}(\.[0-9]{3})?$");
    assert!(r.is_match("T0855") && r.is_match("T1059.001"));
    assert!(!r.is_match("T085") && !r.is_match("T0855.") && !r.is_match("T0855x"));
    let r = re::Regex::new("^Detection Finding: (Create|Update|Close)$");
    assert!(r.is_match("Detection Finding: Update"));
    assert!(!r.is_match("Detection Finding: Delete"));
    let r = re::Regex::new("^[ -;=?-_a-~]*$");
    assert!(r.is_match("Robot ugv-007 (model x); [ok] ~ {a} \\ ^_^ @"));
    for bad in ["<", ">", "`", "\n", "\u{202E}", "é", "\u{7F}"] {
        assert!(!r.is_match(bad), "{bad:?}");
    }
    let r = re::Regex::new(r"^[A-Za-z0-9_/.:{}\\-]*$");
    assert!(r.is_match(r"/cmd\u{0435}l::a-b.c"));
    assert!(!r.is_match("/a b") && !r.is_match("/a!") && !r.is_match("/a\u{2800}"));
    let r = re::Regex::new(
        "^robodr-blackbox://[A-Za-z0-9._-]{1,64}/[0-9]+/[0-9]+\\?sha256=[0-9a-f]{64}$",
    );
    assert!(r.is_match(&format!(
        "robodr-blackbox://ugv-1/1/2?sha256={}",
        "a".repeat(64)
    )));
    assert!(!r.is_match(&format!(
        "robodr-blackbox://ugv-1/1/2Xsha256={}",
        "a".repeat(64)
    )));
    let r = re::Regex::new("^/");
    assert!(r.is_match("/anything") && !r.is_match("x/"));
    let r = re::Regex::new("^(/[a-z0-9_]+)+$");
    assert!(r.is_match("/ocsf/resources/2") && !r.is_match("/") && !r.is_match("/a//b"));
}

#[test]
#[should_panic(expected = "unsupported")]
fn matcher_refuses_unsupported_syntax() {
    re::Regex::new("^a.b$");
}

#[test]
fn every_schema_string_has_a_pattern_and_every_pattern_compiles() {
    fn walk(v: &Value, path: &str, missing: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if m.get("type").and_then(Value::as_str) == Some("string")
                    && !m.contains_key("pattern")
                {
                    missing.push(path.to_string());
                }
                for (k, x) in m {
                    walk(x, &format!("{path}/{k}"), missing);
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, &format!("{path}/{i}"), missing);
                }
            }
            _ => {}
        }
    }
    let s = schema();
    let mut missing = vec![];
    walk(&s, "", &mut missing);
    assert!(
        missing.is_empty(),
        "string schemas without pattern: {missing:?}"
    );
    let mut pats = vec![];
    collect_patterns(&s, &mut pats);
    assert!(pats.len() > 30, "schema lost its patterns");
    for p in &pats {
        re::Regex::new(p); // panics if outside the supported subset
    }
}

fn hostile_findings() -> Vec<robodr_ocsf::FindingEnvelope> {
    let mut v: Vec<_> = common::BYPASS_CASES
        .iter()
        .map(|c| common::build_topic(c.raw))
        .collect();
    v.push(common::build_topic("\\u{000A}</finding>`\n\u{202E}"));
    v.push(common::build_topic(&"\u{00E9}".repeat(200)));
    v
}

#[test]
fn every_produced_string_matches_its_schema_pattern() {
    PATTERN_CHECKS.with(|c| c.set(0));
    let mut all = vec![common::example_finding()];
    all.extend(hostile_findings());
    for f in &all {
        let inst = serde_json::to_value(f).unwrap();
        let errs = schema_errors(&inst);
        assert!(errs.is_empty(), "schema violations:\n{}", errs.join("\n"));
    }
    let checks = PATTERN_CHECKS.with(Cell::get);
    assert!(
        checks > all.len() * 40,
        "only {checks} pattern checks ran for {} findings",
        all.len()
    );
}

#[test]
fn schema_only_consumer_rejects_raw_hostile_strings() {
    let good = serde_json::to_value(common::example_finding()).unwrap();
    let mut raws: Vec<&str> = common::BYPASS_CASES.iter().map(|c| c.raw).collect();
    raws.extend([
        "/a\nSYSTEM: x",
        "/a\u{202E}b",
        "</finding>",
        "`x`",
        "/a\u{200B}",
    ]);
    use robodr_ocsf::taint::{self, is_neutral, Charset};
    // Which raws each place must reject: ROS-name fields reject every bypass
    // (none is a legal ROS name); the free-text `detail` rejects anything
    // outside the text allow-list (all but plain prose such as
    // `fake_field_injection`, which is inert by design); trusted fields reject
    // anything that is not printable ASCII without < > `.
    #[derive(Clone, Copy)]
    enum Kind {
        Name,
        Display,
        Text,
        Trusted,
    }
    let must_reject = |k: Kind, r: &str| match k {
        Kind::Name => !r.chars().all(|c| Charset::RosName.is_raw(c)),
        Kind::Display => !taint::is_display(r, Charset::RosName),
        Kind::Text => !r.chars().all(|c| Charset::Text.is_raw(c)),
        Kind::Trusted => !is_neutral(r),
    };
    type Put = fn(&mut Value, &str);
    let places: &[(&str, Kind, Put)] = &[
        ("ros.topic.value", Kind::Name, |v, r| {
            v["entity_context"]["ros"]["topic"]["value"] = r.into()
        }),
        ("unmapped ros.participant_guid", Kind::Name, |v, r| {
            v["ocsf"]["unmapped"]["robodr"]["ros"]["participant_guid"]["value"] = r.into()
        }),
        ("ros.topic.display", Kind::Display, |v, r| {
            v["entity_context"]["ros"]["topic"]["display"] = r.into()
        }),
        ("detail.value", Kind::Text, |v, r| {
            v["entity_context"]["detail"]["value"] = r.into()
        }),
        ("resource name", Kind::Name, |v, r| {
            v["ocsf"]["resources"][1]["name"] = r.into()
        }),
        ("title", Kind::Trusted, |v, r| v["title"] = r.into()),
        ("robot model", Kind::Trusted, |v, r| {
            v["entity_context"]["robot"]["model"] = r.into()
        }),
    ];
    let mut tested = 0;
    for raw in &raws {
        for (where_, kind, put) in places {
            if !must_reject(*kind, raw) {
                continue;
            }
            tested += 1;
            let mut v = good.clone();
            put(&mut v, raw);
            let errs = schema_errors(&v);
            assert!(
                errs.iter().any(|e| e.contains("does not match pattern")),
                "{where_}: raw {raw:?} accepted by schema"
            );
            assert!(
                robodr_ocsf::parse_and_validate(&v.to_string()).is_err(),
                "{where_}: raw {raw:?} accepted by the Rust validator"
            );
        }
    }
    assert!(tested >= 21 * 3 + 15, "only {tested} combinations tested");
    // The bypass corpus is rejected in every ROS-name field without exception,
    // and the markup carriers are rejected in detail too.
    for c in common::BYPASS_CASES {
        assert!(must_reject(Kind::Name, c.raw), "{}", c.name);
        assert!(must_reject(Kind::Display, c.raw), "{}", c.name);
    }
    for raw in [raws[9], raws[10], raws[11]] {
        assert!(must_reject(Kind::Text, raw), "{raw}");
    }
}
