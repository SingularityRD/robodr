//! Crash simulation for tests: a named point armed on the current thread
//! makes [`hit`] fail once there, and the engine returns at once without
//! touching anything else, as if the process had died at that point. The
//! test then drops the engine and opens a new one on the same directories
//! (recovery). Nothing is armed in production: [`hit`] is a thread-local
//! read that returns `Ok`.

use std::cell::RefCell;

thread_local! {
    static ARMED: RefCell<Option<String>> = const { RefCell::new(None) };
    static FIRED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The simulated crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash(pub String);

impl std::fmt::Display for Crash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "simulated crash at {}", self.0)
    }
}

/// Arm `point` on this thread (the next [`hit`] there fails, once).
pub fn arm(point: &str) {
    ARMED.with(|a| *a.borrow_mut() = Some(point.to_string()));
    FIRED.with(|f| *f.borrow_mut() = None);
}

/// Disarm.
pub fn disarm() {
    ARMED.with(|a| *a.borrow_mut() = None);
}

/// The point that fired since the last [`arm`], if any.
pub fn fired() -> Option<String> {
    FIRED.with(|f| f.borrow().clone())
}

/// A crash point: `Err` once if armed here.
pub fn hit(point: &str) -> Result<(), Crash> {
    let armed = ARMED.with(|a| a.borrow().as_deref() == Some(point));
    if armed {
        ARMED.with(|a| *a.borrow_mut() = None);
        FIRED.with(|f| *f.borrow_mut() = Some(point.to_string()));
        return Err(Crash(point.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_once() {
        assert!(hit("a").is_ok());
        arm("a");
        assert!(hit("b").is_ok());
        assert_eq!(hit("a"), Err(Crash("a".into())));
        assert!(hit("a").is_ok());
        assert_eq!(fired().as_deref(), Some("a"));
        disarm();
    }
}
