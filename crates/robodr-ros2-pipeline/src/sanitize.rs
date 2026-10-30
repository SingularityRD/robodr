//! Sanitising attacker-controlled text before it reaches a threat, a log line
//! or a terminal.
//!
//! Topic names, type names, GUIDs rendered from the wire and capture-file
//! paths can all be chosen by whoever puts bytes on the DDS bus. [`sanitize`]
//! escapes every control character (newline, ESC, NUL, DEL, C1 controls, ...),
//! line / paragraph separator and format character (general categories Cc,
//! Zl, Zp, Cf: bidi overrides, zero-width characters, soft hyphen, the tag
//! block, interlinear annotation, ...) with Rust's `escape_default`
//! notation and caps the length, so such text cannot forge log lines,
//! inject terminal escape sequences, hide or reorder what an operator sees,
//! or bloat a threat.
//!
//! A detail is cut in the **middle** (head, [`TRUNCATION_MARKER`], tail), so
//! the GUID / source address that most details end with survives a long
//! name; finding builders also clip each attacker-controlled name to
//! [`MAX_NAME_CHARS`] with [`clip_name`] before formatting it in.

/// Upper bound (in chars) on attacker-influenced text copied into a finding.
pub const MAX_TEXT_CHARS: usize = 512;

/// Chars of the end of a text that [`sanitize`] keeps when it truncates.
pub const TAIL_CHARS: usize = 128;

/// Upper bound (in chars) on one attacker-controlled name (topic, type,
/// node) formatted into a finding detail, see [`clip_name`].
pub const MAX_NAME_CHARS: usize = 128;

/// Marker put where [`sanitize`] / [`clip_name`] cut text out.
pub const TRUNCATION_MARKER: &str = "...[truncated]";

/// Bidirectional-text controls, line / paragraph separators and every
/// format character (Unicode 15.1 general categories Zl, Zp and Cf), plus
/// the invisible Hangul fillers and the whole tag block: not
/// `is_control()`, but they reorder, hide or break what an operator sees in
/// a terminal, log viewer or SIEM ("Trojan Source", CVE-2021-42574), so a
/// topic name could display as something else. Escaped like controls.
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn push_escaped(out: &mut String, c: char) {
    if c.is_control() || is_bidi_or_invisible(c) {
        out.extend(c.escape_default());
    } else {
        out.push(c);
    }
}

/// Escape control, separator and format characters and cap the length at
/// [`MAX_TEXT_CHARS`] input chars (counted in `char`s, so a multi-byte
/// character is never split). A longer text keeps its first
/// `MAX_TEXT_CHARS - TAIL_CHARS` and last [`TAIL_CHARS`] chars around
/// [`TRUNCATION_MARKER`]. Deterministic: the pipeline deduplicates findings
/// on this output, so two details that display the same are one finding.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_TEXT_CHARS + 16));
    let n = text.chars().count();
    if n <= MAX_TEXT_CHARS {
        for c in text.chars() {
            push_escaped(&mut out, c);
        }
        return out;
    }
    let head = MAX_TEXT_CHARS - TAIL_CHARS;
    for c in text.chars().take(head) {
        push_escaped(&mut out, c);
    }
    out.push_str(TRUNCATION_MARKER);
    for c in text.chars().skip(n - TAIL_CHARS) {
        push_escaped(&mut out, c);
    }
    out
}

/// Clip one attacker-controlled name to [`MAX_NAME_CHARS`] chars (plus
/// [`TRUNCATION_MARKER`]) before it is formatted into a finding detail, so
/// a long name cannot push the rest of the detail (GUID, source address)
/// out of [`sanitize`]'s budget. No escaping: the detail is sanitized as a
/// whole on output.
pub fn clip_name(name: &str) -> String {
    let mut chars = name.chars();
    let mut out: String = chars.by_ref().take(MAX_NAME_CHARS).collect();
    if chars.next().is_some() {
        out.push_str(TRUNCATION_MARKER);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bidi_and_invisible_characters_are_escaped() {
        let s = sanitize("rt/cmd\u{202e}lev_\u{200b}x\u{2066}\u{feff}");
        assert_eq!(s, "rt/cmd\\u{202e}lev_\\u{200b}x\\u{2066}\\u{feff}");
        assert_eq!(sanitize("ünïcødé /ok"), "ünïcødé /ok");
    }

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(sanitize("plain /cmd_vel"), "plain /cmd_vel");
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn controls_are_escaped() {
        assert_eq!(sanitize("a\nb"), "a\\nb");
        assert_eq!(sanitize("a\r\tb"), "a\\r\\tb");
        assert_eq!(sanitize("\u{1b}[31mred"), "\\u{1b}[31mred");
        assert_eq!(sanitize("nul\0"), "nul\\u{0}");
        assert_eq!(sanitize("del\u{7f}"), "del\\u{7f}");
        assert_eq!(sanitize("c1\u{9b}"), "c1\\u{9b}");
        assert!(!sanitize("x\ny\rz\u{1b}").chars().any(char::is_control));
    }

    /// Review: line / paragraph separators and format characters other
    /// than the bidi set were passed through (soft hyphen, Mongolian vowel
    /// separator, interlinear annotation, tag characters, ...).
    #[test]
    fn separators_and_format_characters_are_escaped() {
        for c in [
            '\u{2028}',
            '\u{2029}',
            '\u{00AD}',
            '\u{180E}',
            '\u{FFF9}',
            '\u{FFFA}',
            '\u{FFFB}',
            '\u{E0000}',
            '\u{E0001}',
            '\u{E0041}',
            '\u{E007F}',
            '\u{0600}',
            '\u{2064}',
            '\u{206F}',
            '\u{1D173}',
            '\u{3164}',
        ] {
            let s = sanitize(&format!("a{c}b"));
            assert_eq!(s, format!("a{}b", c.escape_default()), "U+{:04X}", c as u32);
        }
    }

    /// Review: a long name in front of the GUID / source address pushed them
    /// out of the 512-char budget. The tail of a long detail survives.
    #[test]
    fn long_detail_keeps_its_tail() {
        let detail = format!(
            "writer on unprofiled topic /{} (eeeeeeeeeeeeeeeeeeeeeeee) from 10.0.0.66",
            "x".repeat(4000)
        );
        let s = sanitize(&detail);
        assert!(
            s.ends_with("(eeeeeeeeeeeeeeeeeeeeeeee) from 10.0.0.66"),
            "{s}"
        );
        assert!(s.starts_with("writer on unprofiled topic /x"));
        assert!(s.contains(TRUNCATION_MARKER));
        assert_eq!(
            clip_name(&"y".repeat(MAX_NAME_CHARS)),
            "y".repeat(MAX_NAME_CHARS)
        );
        let c = clip_name(&"y".repeat(MAX_NAME_CHARS + 1));
        assert_eq!(
            c,
            format!("{}{TRUNCATION_MARKER}", "y".repeat(MAX_NAME_CHARS))
        );
    }

    #[test]
    fn long_text_is_truncated_on_char_boundaries() {
        let long = "x".repeat(MAX_TEXT_CHARS + 10);
        let s = sanitize(&long);
        assert!(s.contains(TRUNCATION_MARKER));
        assert_eq!(s.chars().filter(|&c| c == 'x').count(), MAX_TEXT_CHARS);
        let exact = "y".repeat(MAX_TEXT_CHARS);
        assert_eq!(sanitize(&exact), exact);
        let wide = "ç".repeat(MAX_TEXT_CHARS + 1);
        assert_eq!(
            sanitize(&wide).chars().filter(|&c| c == 'ç').count(),
            MAX_TEXT_CHARS
        );
        // Escapes expand the output but the *input* budget is what is capped.
        let ctl = "\n".repeat(MAX_TEXT_CHARS * 4);
        assert!(sanitize(&ctl).len() <= MAX_TEXT_CHARS * 2 + TRUNCATION_MARKER.len());
    }
}
