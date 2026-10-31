//! Commissioning report as a self-contained HTML page
//! (`robodr-commission report-html`).
//!
//! The review of a draft used to mean reading `report.json` and editing the
//! sign-off JSON by hand. This renders the report (and, when given, the
//! sign-off list with its confirmation state and the operator signatures'
//! digest) into one HTML file the OEM and the site can read, archive with
//! the commissioning record and print to PDF from any browser (print
//! styles included). It is a **view**: the files it was rendered from stay
//! the artifacts that are signed and verified; the page names their
//! SHA-256 so an archived copy can be matched to them.
//!
//! Hostile input: every string in the report came off the robot bus
//! (topic names, GUIDs, type names) or from an input file. Everything is
//! HTML-escaped and stripped of control characters; the page has no
//! script, no external resource and a restrictive `Content-Security-Policy`
//! meta tag, so a crafted topic name cannot run or load anything when the
//! page is opened. Tables are capped ([`MAX_ROWS`] rows each, the rest
//! counted), so a report from a flooded bus still renders.

use crate::learner::{CommissioningReport, ParticipantStatus, WarningLevel};
use crate::signoff::Signoff;
use crate::stats::SpeedStats;
use std::fmt::Write as _;

/// Most rows rendered per table (the rest is counted, not shown).
pub const MAX_ROWS: usize = 5000;

/// What to render besides the report.
#[derive(Debug, Clone, Default)]
pub struct RenderInputs<'a> {
    /// `sha256:<hex>` of the report file's exact bytes.
    pub report_digest: String,
    /// The sign-off list and `sha256:` of its bytes.
    pub signoff: Option<(&'a Signoff, String)>,
    /// `(signer key id, ...)` of `<signoff>.sig`, if any (listed; they are
    /// verified by `lock`, not here).
    pub signature_key_ids: Vec<String>,
    /// Free text, e.g. site / unit / date, shown in the header (escaped).
    pub title_note: Option<String>,
}

/// HTML-escape `s` and drop control characters (newline and tab become a
/// space).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' | '\t' | '\r' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn opt(v: Option<f64>) -> String {
    v.map_or_else(|| "unlimited (null)".into(), |v| v.to_string())
}

fn stats(s: &Option<SpeedStats>) -> String {
    match s {
        None => "-".into(),
        Some(s) => format!(
            "n={} min={} p50={} p99={} max={}{}",
            s.samples,
            s.min,
            s.p50,
            s.p99,
            s.max,
            if s.decimated { " (approx.)" } else { "" }
        ),
    }
}

fn set<'a>(it: impl IntoIterator<Item = &'a String>) -> String {
    it.into_iter()
        .map(|s| esc(s))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Write a table: header cells, then rows (already escaped cells). Rows
/// beyond [`MAX_ROWS`] are counted.
fn table(out: &mut String, id: &str, title: &str, head: &[&str], rows: Vec<Vec<String>>) {
    let total = rows.len();
    let _ = write!(
        out,
        "<section id=\"{id}\"><h2>{} ({total})</h2>",
        esc(title)
    );
    if total == 0 {
        out.push_str("<p class=\"muted\">none</p></section>");
        return;
    }
    out.push_str("<table><thead><tr>");
    for h in head {
        let _ = write!(out, "<th>{}</th>", esc(h));
    }
    out.push_str("</tr></thead><tbody>");
    for r in rows.into_iter().take(MAX_ROWS) {
        out.push_str("<tr>");
        for c in r {
            let _ = write!(out, "<td>{c}</td>");
        }
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table>");
    if total > MAX_ROWS {
        let _ = write!(
            out,
            "<p class=\"warn\">{} more row(s) not shown: see the report file</p>",
            total - MAX_ROWS
        );
    }
    out.push_str("</section>");
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;margin:24px;color:#111;background:#fff}\
h1{font-size:1.4em}h2{font-size:1.1em;margin-top:1.6em;border-bottom:1px solid #999}\
table{border-collapse:collapse;width:100%;font-size:.85em}\
th,td{border:1px solid #bbb;padding:3px 6px;text-align:left;vertical-align:top;word-break:break-all}\
th{background:#eee}.warn{color:#8a1f00;font-weight:600}.ok{color:#145a14}.muted{color:#666}\
.box{border:2px solid #8a1f00;padding:8px 12px;margin:12px 0}\
dl{display:grid;grid-template-columns:max-content auto;gap:2px 12px}dt{font-weight:600}\
@media print{body{margin:0}section{break-inside:auto}tr{break-inside:avoid}}";

/// Render the page (see the module docs).
pub fn render(report: &CommissioningReport, inp: &RenderInputs<'_>) -> String {
    let mut o = String::new();
    o.push_str(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
         style-src 'unsafe-inline'\"><meta name=\"viewport\" \
         content=\"width=device-width,initial-scale=1\">",
    );
    let _ = write!(
        o,
        "<title>Commissioning report {}</title><style>{STYLE}</style></head><body>",
        esc(&report.model)
    );
    let _ = write!(
        o,
        "<h1>RoboDR commissioning report: {}</h1>",
        esc(&report.model)
    );
    if let Some(n) = &inp.title_note {
        let _ = write!(o, "<p>{}</p>", esc(n));
    }
    let warns = report.warn_count();
    let unconfirmed = inp
        .signoff
        .as_ref()
        .map(|(s, _)| s.unconfirmed().count())
        .unwrap_or(0);
    let _ = write!(
        o,
        "<div class=\"box\"><strong>This page is a view.</strong> The signed artifacts are the \
         report file ({}), the sign-off list{} and the locked profile. A draft is \
         observe-only until it is locked with the operators' signatures. Review status: \
         <span class=\"{}\">{warns} warning(s)</span>{}.</div>",
        esc(&inp.report_digest),
        inp.signoff
            .as_ref()
            .map(|(_, d)| format!(" ({})", esc(d)))
            .unwrap_or_default(),
        if warns > 0 { "warn" } else { "ok" },
        inp.signoff
            .as_ref()
            .map(|_| format!(
                ", <span class=\"{}\">{unconfirmed} unconfirmed sign-off item(s)</span>",
                if unconfirmed > 0 { "warn" } else { "ok" }
            ))
            .unwrap_or_default()
    );
    // Configuration and runs.
    let c = &report.config;
    let _ = write!(
        o,
        "<section id=\"config\"><h2>Learning configuration</h2><dl>\
         <dt>margin</dt><dd>x{}</dd><dt>ceiling linear / joint</dt><dd>{} / {}</dd>\
         <dt>hard caps linear / joint</dt><dd>{} m/s / {} rad/s</dd>\
         <dt>min samples</dt><dd>{}</dd><dt>min announcements</dt><dd>{}</dd>\
         <dt>learn readers</dt><dd>{}</dd><dt>outlier ratio</dt><dd>{}</dd>\
         <dt>operator-accepted participants</dt><dd>{}</dd><dt>events</dt><dd>{}</dd></dl></section>",
        c.margin,
        opt(c.ceiling_linear),
        opt(c.ceiling_joint),
        c.hard_cap_linear,
        c.hard_cap_joint,
        c.min_samples,
        c.min_participant_announcements,
        c.learn_readers,
        c.outlier_ratio,
        set(&c.accept_participants),
        report.events_total
    );
    table(
        &mut o,
        "runs",
        "Runs",
        &["#", "input", "events"],
        report
            .runs
            .iter()
            .enumerate()
            .map(|(i, r)| vec![i.to_string(), esc(&r.label), r.events.to_string()])
            .collect(),
    );
    table(
        &mut o,
        "warnings",
        "Warnings",
        &["level", "code", "subject", "message"],
        report
            .warnings
            .iter()
            .map(|w| {
                let lvl = match w.level {
                    WarningLevel::Warn => "<span class=\"warn\">WARN</span>".to_string(),
                    WarningLevel::Info => "info".to_string(),
                };
                vec![lvl, esc(&w.code), esc(&w.subject), esc(&w.message)]
            })
            .collect(),
    );
    if let Some((so, _)) = &inp.signoff {
        let _ = write!(
            o,
            "<section id=\"signoff-meta\"><h2>Sign-off</h2><dl><dt>operator</dt><dd>{}</dd>\
             <dt>bound draft</dt><dd>{}</dd><dt>item digest</dt><dd>{}</dd>\
             <dt>signatures (key ids, verified by lock)</dt><dd>{}</dd></dl></section>",
            if so.operator.trim().is_empty() {
                "<span class=\"warn\">not named</span>".to_string()
            } else {
                esc(&so.operator)
            },
            esc(&so.profile_sha256),
            esc(&so.items_sha256),
            if inp.signature_key_ids.is_empty() {
                "<span class=\"warn\">none</span>".to_string()
            } else {
                set(&inp.signature_key_ids)
            }
        );
        table(
            &mut o,
            "signoff",
            "Sign-off items",
            &["confirmed", "kind", "subject", "why"],
            so.items
                .iter()
                .map(|i| {
                    vec![
                        if i.confirmed {
                            "<span class=\"ok\">yes</span>".into()
                        } else {
                            "<span class=\"warn\">NO</span>".into()
                        },
                        esc(&i.kind),
                        esc(&i.subject),
                        esc(&i.reason),
                    ]
                })
                .collect(),
        );
    } else {
        table(
            &mut o,
            "signoff",
            "Sign-off items (as generated)",
            &["kind", "subject", "why"],
            report
                .signoff
                .iter()
                .map(|i| vec![esc(&i.kind), esc(&i.subject), esc(&i.reason)])
                .collect(),
        );
    }
    table(
        &mut o,
        "motion",
        "Motion channels",
        &[
            "channel",
            "commands",
            "sources",
            "linear",
            "joint",
            "envelope linear / joint",
            "in profile",
        ],
        report
            .motion_channels
            .iter()
            .map(|(ch, m)| {
                vec![
                    esc(ch),
                    m.commands.to_string(),
                    format!(
                        "{}{}",
                        set(&m.sources),
                        if m.excluded_sources.is_empty() {
                            String::new()
                        } else {
                            format!(
                                " <span class=\"warn\">excluded: {}</span>",
                                set(&m.excluded_sources)
                            )
                        }
                    ),
                    esc(&stats(&m.linear)),
                    esc(&stats(&m.joint)),
                    format!(
                        "{} / {}{}",
                        esc(&opt(m.envelope.max_linear_speed)),
                        esc(&opt(m.envelope.max_joint_speed)),
                        if m.linear_capped_by_ceiling || m.joint_capped_by_ceiling {
                            " (capped)"
                        } else {
                            ""
                        }
                    ),
                    m.in_profile.to_string(),
                ]
            })
            .collect(),
    );
    table(
        &mut o,
        "participants",
        "Participants",
        &[
            "GUID prefix",
            "status",
            "announcements",
            "IPs",
            "writes",
            "flags",
        ],
        report
            .participants
            .iter()
            .map(|(g, p)| {
                let st = match p.status {
                    ParticipantStatus::Accepted => "learned".to_string(),
                    ParticipantStatus::OperatorAccepted => {
                        "<span class=\"warn\">accepted by operator</span>".into()
                    }
                    ParticipantStatus::Quarantined => format!(
                        "<span class=\"warn\">QUARANTINED: {}</span>",
                        set(&p.quarantine_reasons)
                    ),
                };
                vec![
                    esc(g),
                    st,
                    p.announcements.to_string(),
                    set(&p.src_ips),
                    set(&p.writer_topics),
                    set(&p.flags),
                ]
            })
            .collect(),
    );
    for (id, title, m) in [
        ("writers", "Writer topics", &report.writer_topics),
        ("readers", "Reader topics", &report.reader_topics),
    ] {
        table(
            &mut o,
            id,
            title,
            &["topic", "participants", "types", "in profile"],
            m.iter()
                .map(|(t, e)| {
                    vec![
                        esc(t),
                        set(&e.participants),
                        set(&e.type_names),
                        e.in_profile.to_string(),
                    ]
                })
                .collect(),
        );
    }
    for (id, title, m) in [
        ("services", "Services", &report.services),
        ("actions", "Actions", &report.actions),
    ] {
        table(
            &mut o,
            id,
            title,
            &["name", "clients", "servers", "in profile"],
            m.iter()
                .map(|(n, r)| {
                    vec![
                        esc(n),
                        set(&r.clients),
                        set(&r.servers),
                        r.in_profile.to_string(),
                    ]
                })
                .collect(),
        );
    }
    table(
        &mut o,
        "raw",
        "Raw DDS topics",
        &["topic", "writers", "readers", "ROS internal", "in profile"],
        report
            .raw_dds_topics
            .iter()
            .map(|(n, r)| {
                vec![
                    esc(n),
                    set(&r.writers),
                    set(&r.readers),
                    r.ros_internal.to_string(),
                    r.in_profile.to_string(),
                ]
            })
            .collect(),
    );
    table(
        &mut o,
        "overflow",
        "Capacity overflow (dropped at a cap)",
        &["category", "dropped"],
        report
            .overflow
            .iter()
            .map(|(k, v)| vec![esc(k), format!("<span class=\"warn\">{v}</span>")])
            .collect(),
    );
    table(
        &mut o,
        "anomalies",
        &format!("Anomalies (first stored; {} total)", report.anomalies_total),
        &["at", "kind", "subject", "detail"],
        report
            .anomalies
            .iter()
            .map(|a| {
                vec![
                    esc(&a.at.to_string()),
                    esc(&a.kind),
                    esc(&a.subject),
                    esc(&a.detail),
                ]
            })
            .collect(),
    );
    let _ = writeln!(
        o,
        "<footer class=\"muted\"><p>robodr-commission {} report-html. Archive this page with \
         the commissioning record; the digests above identify the files it shows.</p></footer>\
         </body></html>",
        env!("CARGO_PKG_VERSION")
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LearnConfig, Learner};
    use robodr_events::graph::{Endpoint, Participant};
    use robodr_events::RobotEvent;

    fn report_with(topic: &str) -> CommissioningReport {
        let mut l = Learner::new(LearnConfig {
            model: "ugv<b>".into(),
            min_participant_announcements: 1,
            ..LearnConfig::default()
        })
        .unwrap();
        let g = "0102030405060708090a0b0c";
        l.observe(&RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: g.into(),
            src_ip: "10.0.0.1".into(),
            locators: vec![],
        }));
        l.observe(&RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: g.into(),
            topic: topic.into(),
            type_name: "std_msgs::msg::dds_::String_".into(),
        }));
        l.finish().report
    }

    #[test]
    fn hostile_names_are_escaped_and_the_page_is_inert() {
        let r = report_with("rt/x<script>alert(1)</script>\u{7}\"'&");
        let html = render(
            &r,
            &RenderInputs {
                report_digest: "sha256:ab".into(),
                title_note: Some("<img src=x onerror=alert(1)>".into()),
                ..Default::default()
            },
        );
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("<img"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(!html.contains('\u{7}'));
        assert!(html.contains("ugv&lt;b&gt;"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("http://") && !html.contains("https://"));
    }

    #[test]
    fn signoff_state_is_shown() {
        let r = report_with("rt/chatter");
        let p = robodr_events::profile::Profile {
            model: r.model.clone(),
            ..Default::default()
        };
        let so = Signoff::new(
            &p,
            [crate::signoff::SignoffItem::new(
                "motion_writer",
                "/cmd_vel a",
                "why",
            )],
        );
        let html = render(
            &r,
            &RenderInputs {
                report_digest: "sha256:ab".into(),
                signoff: Some((&so, "sha256:cd".into())),
                ..Default::default()
            },
        );
        assert!(html.contains("1 unconfirmed sign-off item(s)"), "{html}");
        assert!(html.contains("<span class=\"warn\">NO</span>"));
        assert!(html.contains("not named"));
        let so = so.confirm_all("Alice");
        let html = render(
            &r,
            &RenderInputs {
                report_digest: "sha256:ab".into(),
                signoff: Some((&so, "sha256:cd".into())),
                signature_key_ids: vec!["alice".into()],
                ..Default::default()
            },
        );
        assert!(html.contains("0 unconfirmed sign-off item(s)"), "{html}");
        assert!(html.contains("Alice"));
    }

    #[test]
    fn tables_are_capped() {
        let mut out = String::new();
        let rows = (0..(MAX_ROWS + 3)).map(|i| vec![i.to_string()]).collect();
        table(&mut out, "t", "T", &["n"], rows);
        assert!(out.contains("3 more row(s) not shown"));
        assert_eq!(out.matches("<tr>").count(), MAX_ROWS + 1);
    }
}
