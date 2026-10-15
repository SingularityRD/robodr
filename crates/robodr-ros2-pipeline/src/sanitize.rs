//! Sanitising attacker-controlled text before it reaches a threat, a log line
//! or a terminal.
//!
//! Topic names, type names, GUIDs rendered from the wire and capture-file
//! paths can all be chosen by whoever puts bytes on the DDS bus. [`sanitize`]
//! escapes every control character (newline, ESC, NUL, DEL, C1 controls, ...)
//! with Rust's `escape_default` notation and caps the length, so such text
//! cannot forge log lines, inject terminal escape sequences or bloat a threat.

/// Upper bound (in chars) on attacker-influenced text copied into a finding.
pub const MAX_TEXT_CHARS: usize = 512;

/// Marker appended when [`sanitize`] truncates.
pub const TRUNCATION_MARKER: &str = "...[truncated]";

/// Escape control characters and cap the length at [`MAX_TEXT_CHARS`] chars
/// (counted in `char`s, so a multi-byte character is never split).
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_TEXT_CHARS + 16));
    for (kept, c) in text.chars().enumerate() {
        if kept == MAX_TEXT_CHARS {
            out.push_str(TRUNCATION_MARKER);
            return out;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn long_text_is_truncated_on_char_boundaries() {
        let long = "x".repeat(MAX_TEXT_CHARS + 10);
        let s = sanitize(&long);
        assert!(s.ends_with(TRUNCATION_MARKER));
        assert_eq!(s.chars().filter(|&c| c == 'x').count(), MAX_TEXT_CHARS);
        let exact = "y".repeat(MAX_TEXT_CHARS);
        assert_eq!(sanitize(&exact), exact);
        let wide = "ç".repeat(MAX_TEXT_CHARS + 1);
        assert!(sanitize(&wide).starts_with(&"ç".repeat(MAX_TEXT_CHARS)));
        // Escapes expand the output but the *input* budget is what is capped.
        let ctl = "\n".repeat(MAX_TEXT_CHARS * 4);
        assert!(sanitize(&ctl).len() <= MAX_TEXT_CHARS * 2 + TRUNCATION_MARKER.len());
    }
}
