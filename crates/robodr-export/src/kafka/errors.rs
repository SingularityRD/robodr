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
    /// The broker's idempotent-producer state disagrees with ours
    /// (`OUT_OF_ORDER_SEQUENCE_NUMBER`, `UNKNOWN_PRODUCER_ID`,
    /// `INVALID_PRODUCER_EPOCH`, `PRODUCER_FENCED`): the batch was **not**
    /// appended; get a new producer id, restart the sequences at 0 and
    /// re-send (see [`super::client`], "Idempotence").
    Sequence,
    /// `DUPLICATE_SEQUENCE_NUMBER`: the broker already holds this batch
    /// (a re-send after a lost acknowledgement): success.
    Duplicate,
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
pub const COORDINATOR_LOAD_IN_PROGRESS: i16 = 14;
pub const COORDINATOR_NOT_AVAILABLE: i16 = 15;
pub const NOT_COORDINATOR: i16 = 16;
pub const TOPIC_AUTHORIZATION_FAILED: i16 = 29;
pub const CLUSTER_AUTHORIZATION_FAILED: i16 = 31;
pub const INVALID_TIMESTAMP: i16 = 32;
pub const UNSUPPORTED_VERSION: i16 = 35;
pub const OUT_OF_ORDER_SEQUENCE_NUMBER: i16 = 45;
pub const DUPLICATE_SEQUENCE_NUMBER: i16 = 46;
pub const INVALID_PRODUCER_EPOCH: i16 = 47;
pub const KAFKA_STORAGE_ERROR: i16 = 56;
pub const UNKNOWN_PRODUCER_ID: i16 = 59;
pub const FENCED_LEADER_EPOCH: i16 = 74;
pub const UNKNOWN_LEADER_EPOCH: i16 = 75;
pub const INVALID_RECORD: i16 = 87;
pub const THROTTLING_QUOTA_EXCEEDED: i16 = 89;
pub const PRODUCER_FENCED: i16 = 90;

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
        | THROTTLING_QUOTA_EXCEEDED
        // InitProducerId: the transaction coordinator is moving or loading.
        | COORDINATOR_LOAD_IN_PROGRESS
        | COORDINATOR_NOT_AVAILABLE
        | NOT_COORDINATOR => Retriable { refresh: false },
        MESSAGE_TOO_LARGE | RECORD_LIST_TOO_LARGE | INVALID_RECORD | INVALID_TIMESTAMP => Record,
        OUT_OF_ORDER_SEQUENCE_NUMBER | UNKNOWN_PRODUCER_ID | INVALID_PRODUCER_EPOCH
        | PRODUCER_FENCED => Sequence,
        DUPLICATE_SEQUENCE_NUMBER => Duplicate,
        _ => Fatal,
    }
}

pub const UNSUPPORTED_SASL_MECHANISM: i16 = 33;
pub const ILLEGAL_SASL_STATE: i16 = 34;
pub const SASL_AUTHENTICATION_FAILED: i16 = 58;

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
        COORDINATOR_LOAD_IN_PROGRESS => "COORDINATOR_LOAD_IN_PROGRESS",
        COORDINATOR_NOT_AVAILABLE => "COORDINATOR_NOT_AVAILABLE",
        NOT_COORDINATOR => "NOT_COORDINATOR",
        OUT_OF_ORDER_SEQUENCE_NUMBER => "OUT_OF_ORDER_SEQUENCE_NUMBER",
        DUPLICATE_SEQUENCE_NUMBER => "DUPLICATE_SEQUENCE_NUMBER",
        INVALID_PRODUCER_EPOCH => "INVALID_PRODUCER_EPOCH",
        UNKNOWN_PRODUCER_ID => "UNKNOWN_PRODUCER_ID",
        PRODUCER_FENCED => "PRODUCER_FENCED",
        TOPIC_AUTHORIZATION_FAILED => "TOPIC_AUTHORIZATION_FAILED",
        CLUSTER_AUTHORIZATION_FAILED => "CLUSTER_AUTHORIZATION_FAILED",
        INVALID_TIMESTAMP => "INVALID_TIMESTAMP",
        UNSUPPORTED_VERSION => "UNSUPPORTED_VERSION",
        KAFKA_STORAGE_ERROR => "KAFKA_STORAGE_ERROR",
        FENCED_LEADER_EPOCH => "FENCED_LEADER_EPOCH",
        UNKNOWN_LEADER_EPOCH => "UNKNOWN_LEADER_EPOCH",
        INVALID_RECORD => "INVALID_RECORD",
        THROTTLING_QUOTA_EXCEEDED => "THROTTLING_QUOTA_EXCEEDED",
        UNSUPPORTED_SASL_MECHANISM => "UNSUPPORTED_SASL_MECHANISM",
        ILLEGAL_SASL_STATE => "ILLEGAL_SASL_STATE",
        SASL_AUTHENTICATION_FAILED => "SASL_AUTHENTICATION_FAILED",
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
        assert_eq!(name(58), "SASL_AUTHENTICATION_FAILED");
        assert_eq!(classify(58), ErrorClass::Fatal);
        for c in [45, 47, 59, 90] {
            assert_eq!(classify(c), ErrorClass::Sequence, "{c}");
        }
        assert_eq!(classify(46), ErrorClass::Duplicate);
        assert_eq!(classify(15), ErrorClass::Retriable { refresh: false });
        assert_eq!(classify(31), ErrorClass::Fatal);
        assert_eq!(name(45), "OUT_OF_ORDER_SEQUENCE_NUMBER");
        assert_eq!(name(59), "UNKNOWN_PRODUCER_ID");
    }
}
