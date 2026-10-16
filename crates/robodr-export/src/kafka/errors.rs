//! Kafka error codes this producer distinguishes, and how it reacts.

/// How the producer reacts to a broker error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    None,
    /// Try again after a backoff; `refresh` = refresh metadata first
    /// (leadership or topic layout may have changed).
    Retriable {
        refresh: bool,
    },
    /// The records themselves are unacceptable (too large, invalid): split
    /// the batch to find the offender, then reject that record only.
    Record,
    /// Configuration / authorisation / protocol problem: stop and report.
    Fatal,
}

pub const NONE: i16 = 0;
pub const UNKNOWN_SERVER_ERROR: i16 = -1;
pub const CORRUPT_MESSAGE: i16 = 2;
pub const UNKNOWN_TOPIC_OR_PARTITION: i16 = 3;
pub const LEADER_NOT_AVAILABLE: i16 = 5;
pub const NOT_LEADER_OR_FOLLOWER: i16 = 6;
pub const REQUEST_TIMED_OUT: i16 = 7;
pub const MESSAGE_TOO_LARGE: i16 = 10;
pub const NETWORK_EXCEPTION: i16 = 13;
pub const INVALID_TOPIC_EXCEPTION: i16 = 17;
pub const RECORD_LIST_TOO_LARGE: i16 = 18;
pub const NOT_ENOUGH_REPLICAS: i16 = 19;
pub const NOT_ENOUGH_REPLICAS_AFTER_APPEND: i16 = 20;
pub const INVALID_REQUIRED_ACKS: i16 = 21;
pub const TOPIC_AUTHORIZATION_FAILED: i16 = 29;
pub const CLUSTER_AUTHORIZATION_FAILED: i16 = 31;
pub const INVALID_TIMESTAMP: i16 = 32;
pub const UNSUPPORTED_VERSION: i16 = 35;
pub const KAFKA_STORAGE_ERROR: i16 = 56;
pub const FENCED_LEADER_EPOCH: i16 = 74;
pub const UNKNOWN_LEADER_EPOCH: i16 = 75;
pub const INVALID_RECORD: i16 = 87;
pub const THROTTLING_QUOTA_EXCEEDED: i16 = 89;

pub fn classify(code: i16) -> ErrorClass {
    use ErrorClass::*;
    match code {
        NONE => None,
        UNKNOWN_TOPIC_OR_PARTITION
        | LEADER_NOT_AVAILABLE
        | NOT_LEADER_OR_FOLLOWER
        | NETWORK_EXCEPTION
        | KAFKA_STORAGE_ERROR
        | FENCED_LEADER_EPOCH
        | UNKNOWN_LEADER_EPOCH => Retriable { refresh: true },
        // UNKNOWN_SERVER_ERROR is not retriable in the Java client; we retry
        // it (bounded): delivery is at-least-once anyway.
        UNKNOWN_SERVER_ERROR
        | CORRUPT_MESSAGE
        | REQUEST_TIMED_OUT
        | NOT_ENOUGH_REPLICAS
        | NOT_ENOUGH_REPLICAS_AFTER_APPEND
        | THROTTLING_QUOTA_EXCEEDED => Retriable { refresh: false },
        MESSAGE_TOO_LARGE | RECORD_LIST_TOO_LARGE | INVALID_RECORD | INVALID_TIMESTAMP => Record,
        _ => Fatal,
    }
}

/// Short name for logs.
pub fn name(code: i16) -> &'static str {
    match code {
        NONE => "NONE",
        UNKNOWN_SERVER_ERROR => "UNKNOWN_SERVER_ERROR",
        CORRUPT_MESSAGE => "CORRUPT_MESSAGE",
        UNKNOWN_TOPIC_OR_PARTITION => "UNKNOWN_TOPIC_OR_PARTITION",
        LEADER_NOT_AVAILABLE => "LEADER_NOT_AVAILABLE",
        NOT_LEADER_OR_FOLLOWER => "NOT_LEADER_OR_FOLLOWER",
        REQUEST_TIMED_OUT => "REQUEST_TIMED_OUT",
        MESSAGE_TOO_LARGE => "MESSAGE_TOO_LARGE",
        NETWORK_EXCEPTION => "NETWORK_EXCEPTION",
        INVALID_TOPIC_EXCEPTION => "INVALID_TOPIC_EXCEPTION",
        RECORD_LIST_TOO_LARGE => "RECORD_LIST_TOO_LARGE",
        NOT_ENOUGH_REPLICAS => "NOT_ENOUGH_REPLICAS",
        NOT_ENOUGH_REPLICAS_AFTER_APPEND => "NOT_ENOUGH_REPLICAS_AFTER_APPEND",
        INVALID_REQUIRED_ACKS => "INVALID_REQUIRED_ACKS",
        TOPIC_AUTHORIZATION_FAILED => "TOPIC_AUTHORIZATION_FAILED",
        CLUSTER_AUTHORIZATION_FAILED => "CLUSTER_AUTHORIZATION_FAILED",
        INVALID_TIMESTAMP => "INVALID_TIMESTAMP",
        UNSUPPORTED_VERSION => "UNSUPPORTED_VERSION",
        KAFKA_STORAGE_ERROR => "KAFKA_STORAGE_ERROR",
        FENCED_LEADER_EPOCH => "FENCED_LEADER_EPOCH",
        UNKNOWN_LEADER_EPOCH => "UNKNOWN_LEADER_EPOCH",
        INVALID_RECORD => "INVALID_RECORD",
        THROTTLING_QUOTA_EXCEEDED => "THROTTLING_QUOTA_EXCEEDED",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(classify(0), ErrorClass::None);
        assert_eq!(classify(6), ErrorClass::Retriable { refresh: true });
        assert_eq!(classify(7), ErrorClass::Retriable { refresh: false });
        assert_eq!(classify(10), ErrorClass::Record);
        assert_eq!(classify(29), ErrorClass::Fatal);
        assert_eq!(classify(12345), ErrorClass::Fatal);
        assert_eq!(name(6), "NOT_LEADER_OR_FOLLOWER");
        assert_eq!(name(999), "OTHER");
    }
}
