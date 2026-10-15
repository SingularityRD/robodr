//! Input layer: where commissioning events come from.
//!
//! Everything downstream (learner, checker) consumes an [`EventSource`], a
//! minimal pull-style trait. Today there is one implementation,
//! [`JsonlSource`], reading JSON Lines of [`RobotEvent`] in the serde tagged
//! format (`{"kind":"ros2_participant_discovered", ...}`).
//!
//! # Adding pcap input (seam)
//!
//! TODO(pcap): `robodr-capture` provides a pcap reader that decodes RTPS and
//! yields `RobotEvent`s. Wiring it is meant to be a few lines:
//! 1. add `robodr-capture = { workspace = true }` to this crate's Cargo.toml;
//! 2. write `struct PcapSource { label, inner: <capture's reader> }` and
//!    `impl EventSource for PcapSource` (position = packet ordinal);
//! 3. replace the `InputSpec::Pcap` arm in [`open`] with `PcapSource::open`.
//!
//! The CLI already accepts `--pcap <file>` and routes it through [`open`].
//!
//! # Strictness
//!
//! A commissioning run is supposed to be clean, so the reader is strict: the
//! first malformed line is an error that aborts the source (the learner never
//! silently drops input). Blank lines and lines whose first non-blank char is
//! `#` are skipped, so example files can carry a provenance comment; this is
//! an extension to plain JSONL. Lines are capped at [`MAX_LINE_BYTES`] so a
//! hostile or corrupt file cannot make us buffer unbounded memory.

use robodr_events::RobotEvent;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;

/// Maximum accepted length of one JSONL line, in bytes (newline excluded).
pub const MAX_LINE_BYTES: usize = 1 << 20;

/// One event plus where it came from inside its source (1-based line number
/// for JSONL; packet ordinal for pcap once wired).
#[derive(Debug, Clone, PartialEq)]
pub struct SourcedEvent {
    pub position: u64,
    pub event: RobotEvent,
}

/// A stream of robot events. Pull-based so sources can be files, captures or
/// in-memory test vectors without the consumer caring.
pub trait EventSource {
    /// Human-readable name of the source (usually the file path); it appears
    /// in reports so the OEM can trace a finding back to its run.
    fn label(&self) -> &str;
    /// Next event, `None` at end of stream. After an `Err`, a source returns
    /// `None` from then on.
    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>>;
}

/// Errors from reading an event source.
#[derive(Debug)]
pub enum InputError {
    Io {
        source: String,
        error: io::Error,
    },
    LineTooLong {
        source: String,
        line: u64,
    },
    InvalidUtf8 {
        source: String,
        line: u64,
    },
    Parse {
        source: String,
        line: u64,
        message: String,
    },
    Unsupported(String),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Io { source, error } => write!(f, "{source}: {error}"),
            InputError::LineTooLong { source, line } => {
                write!(
                    f,
                    "{source}:{line}: line longer than {MAX_LINE_BYTES} bytes"
                )
            }
            InputError::InvalidUtf8 { source, line } => {
                write!(f, "{source}:{line}: line is not valid UTF-8")
            }
            InputError::Parse {
                source,
                line,
                message,
            } => write!(f, "{source}:{line}: not a RobotEvent: {message}"),
            InputError::Unsupported(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for InputError {}

/// JSON Lines reader over any `BufRead`.
pub struct JsonlSource<R> {
    label: String,
    reader: R,
    line: u64,
    done: bool,
    buf: Vec<u8>,
}

impl JsonlSource<BufReader<File>> {
    /// Open a JSONL file; the label is the path as given.
    pub fn open(path: &std::path::Path) -> Result<Self, InputError> {
        let label = path.display().to_string();
        let file = File::open(path).map_err(|error| InputError::Io {
            source: label.clone(),
            error,
        })?;
        Ok(Self::new(label, BufReader::new(file)))
    }
}

impl<R: BufRead> JsonlSource<R> {
    pub fn new(label: impl Into<String>, reader: R) -> Self {
        Self {
            label: label.into(),
            reader,
            line: 0,
            done: false,
            buf: Vec::new(),
        }
    }

    fn fail(&mut self, e: InputError) -> Option<Result<SourcedEvent, InputError>> {
        self.done = true;
        Some(Err(e))
    }
}

impl<R: BufRead> EventSource for JsonlSource<R> {
    fn label(&self) -> &str {
        &self.label
    }

    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>> {
        while !self.done {
            self.buf.clear();
            self.line += 1;
            let limit = MAX_LINE_BYTES as u64 + 2; // room for "\r\n"
            let n = match (&mut self.reader)
                .take(limit)
                .read_until(b'\n', &mut self.buf)
            {
                Ok(n) => n,
                Err(error) => {
                    let source = self.label.clone();
                    return self.fail(InputError::Io { source, error });
                }
            };
            if n == 0 {
                self.done = true;
                return None;
            }
            if self.buf.last() == Some(&b'\n') {
                self.buf.pop();
            }
            if self.buf.last() == Some(&b'\r') {
                self.buf.pop();
            }
            if self.buf.len() > MAX_LINE_BYTES {
                let (source, line) = (self.label.clone(), self.line);
                return self.fail(InputError::LineTooLong { source, line });
            }
            let Ok(text) = std::str::from_utf8(&self.buf) else {
                let (source, line) = (self.label.clone(), self.line);
                return self.fail(InputError::InvalidUtf8 { source, line });
            };
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            return match serde_json::from_str::<RobotEvent>(trimmed) {
                Ok(event) => Some(Ok(SourcedEvent {
                    position: self.line,
                    event,
                })),
                Err(e) => {
                    let (source, line) = (self.label.clone(), self.line);
                    self.fail(InputError::Parse {
                        source,
                        line,
                        message: e.to_string(),
                    })
                }
            };
        }
        None
    }
}

/// In-memory source, handy for tests and for callers that already hold events.
pub struct VecSource {
    label: String,
    events: std::vec::IntoIter<RobotEvent>,
    position: u64,
}

impl VecSource {
    pub fn new(label: impl Into<String>, events: Vec<RobotEvent>) -> Self {
        Self {
            label: label.into(),
            events: events.into_iter(),
            position: 0,
        }
    }
}

impl EventSource for VecSource {
    fn label(&self) -> &str {
        &self.label
    }
    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>> {
        let event = self.events.next()?;
        self.position += 1;
        Some(Ok(SourcedEvent {
            position: self.position,
            event,
        }))
    }
}

/// What the user asked us to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSpec {
    /// JSON Lines of `RobotEvent`.
    Jsonl(PathBuf),
    /// A packet capture. Not wired yet, see the module docs (TODO(pcap)).
    Pcap(PathBuf),
}

/// Open an input. The single place new input kinds are plugged in.
pub fn open(spec: &InputSpec) -> Result<Box<dyn EventSource>, InputError> {
    match spec {
        InputSpec::Jsonl(p) => Ok(Box::new(JsonlSource::open(p)?)),
        // TODO(pcap): Ok(Box::new(PcapSource::open(p)?)) once robodr-capture lands.
        InputSpec::Pcap(p) => Err(InputError::Unsupported(format!(
            "{}: pcap input is not wired yet (needs robodr-capture); convert to JSONL for now",
            p.display()
        ))),
    }
}

/// Drain a source into a vector (strict: the first error is returned).
pub fn read_all(src: &mut dyn EventSource) -> Result<Vec<SourcedEvent>, InputError> {
    let mut out = Vec::new();
    while let Some(r) = src.next_event() {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(text: &str) -> JsonlSource<&[u8]> {
        JsonlSource::new("mem", text.as_bytes())
    }

    #[test]
    fn reads_tagged_events_with_comments_and_blanks() {
        let text = "# synthetic\n\n{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"aa\",\"src_ip\":\"10.0.0.1\"}\r\n   \n{\"kind\":\"motion_command\",\"channel\":\"/cmd_vel\",\"source_guid\":null,\"linear_speed\":0.5,\"joint_speed\":null}";
        let evs = read_all(&mut src(text)).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].position, 3);
        assert_eq!(evs[1].position, 5);
        assert!(matches!(evs[1].event, RobotEvent::MotionCommand(_)));
    }

    #[test]
    fn malformed_line_is_error_with_line_number_then_stops() {
        let mut s = src("{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"aa\",\"src_ip\":\"x\"}\n{\"kind\":\"bogus\"}\n{}\n");
        assert!(s.next_event().unwrap().is_ok());
        let err = s.next_event().unwrap().unwrap_err();
        assert!(matches!(err, InputError::Parse { line: 2, .. }), "{err}");
        assert!(err.to_string().contains("mem:2"));
        assert!(s.next_event().is_none());
    }

    #[test]
    fn invalid_utf8_rejected() {
        let bytes: &[u8] = b"\xff\xfe{}\n";
        let mut s = JsonlSource::new("mem", bytes);
        assert!(matches!(
            s.next_event().unwrap().unwrap_err(),
            InputError::InvalidUtf8 { line: 1, .. }
        ));
    }

    #[test]
    fn overlong_line_rejected_without_buffering_it_all() {
        let long = "x".repeat(MAX_LINE_BYTES + 10);
        let mut s = src(&long);
        assert!(matches!(
            s.next_event().unwrap().unwrap_err(),
            InputError::LineTooLong { line: 1, .. }
        ));
        assert!(s.next_event().is_none());
    }

    #[test]
    fn nan_literal_is_a_parse_error() {
        // JSON has no NaN; serde_json rejects it, so NaN can only reach the
        // learner through non-JSON sources (or as huge exponents -> inf).
        let mut s = src("{\"kind\":\"motion_command\",\"channel\":\"/c\",\"source_guid\":null,\"linear_speed\":NaN,\"joint_speed\":null}");
        assert!(s.next_event().unwrap().is_err());
    }

    #[test]
    fn pcap_is_a_clear_unsupported_error() {
        let e = open(&InputSpec::Pcap("x.pcap".into())).err().unwrap();
        assert!(e.to_string().contains("not wired yet"));
    }

    #[test]
    fn missing_file_is_io_error() {
        let e = open(&InputSpec::Jsonl("/nonexistent/robodr/x.jsonl".into()))
            .err()
            .unwrap();
        assert!(matches!(e, InputError::Io { .. }));
    }
}
