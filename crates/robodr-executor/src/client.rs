//! The agentd side of the protocol ([`crate::proto`]): blocking calls with
//! a deadline. agentd runs them on its own worker thread, never on its
//! detection loop.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use robodr_responder::SafetyState;

use crate::engine::Outcome;
use crate::journal::{Event, JournalHead};
use crate::order::Order;
use crate::proto::{self, Key, Msg};

/// A connection factory for one executor socket.
#[derive(Debug, Clone)]
pub struct Client {
    pub socket: PathBuf,
    pub key: Key,
    pub timeout: Duration,
}

struct Conn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Client {
    pub fn new(socket: PathBuf, key: Key, timeout: Duration) -> Self {
        Self {
            socket,
            key,
            timeout,
        }
    }

    fn connect(&self) -> Result<Conn, String> {
        let s = UnixStream::connect(&self.socket)
            .map_err(|e| format!("executor socket {}: {e}", self.socket.display()))?;
        s.set_read_timeout(Some(self.timeout))
            .and_then(|()| s.set_write_timeout(Some(self.timeout)))
            .map_err(|e| e.to_string())?;
        let w = s.try_clone().map_err(|e| e.to_string())?;
        Ok(Conn {
            reader: BufReader::new(s),
            writer: w,
        })
    }

    fn send(&self, c: &mut Conn, reply_to: &str, msg: &Msg) -> Result<String, String> {
        let n = proto::new_nonce()?;
        let line = proto::seal(&self.key, proto::wall_ms(), &n, reply_to, msg)?;
        proto::write_line(&mut c.writer, &line)?;
        Ok(n)
    }

    fn recv(&self, c: &mut Conn, reply_to: &str) -> Result<proto::Received, String> {
        let raw = proto::read_line(&mut c.reader)?;
        proto::open(&self.key, &raw, proto::wall_ms(), Some(reply_to))
            .map_err(|e| format!("executor answer refused: {e}"))
    }

    fn call(&self, msg: &Msg) -> Result<Msg, String> {
        let mut c = self.connect()?;
        let n = self.send(&mut c, "", msg)?;
        Ok(self.recv(&mut c, &n)?.msg)
    }

    /// Submit an order. `safety` is called when the executor asks for the
    /// current safety state (immediately before it applies): it returns the
    /// state and how old agentd's view of it is (ms), or why it has none.
    pub fn submit(
        &self,
        order: &Order,
        safety: &mut dyn FnMut() -> Result<(SafetyState, u64), String>,
    ) -> Result<Outcome, String> {
        let mut c = self.connect()?;
        let n = self.send(
            &mut c,
            "",
            &Msg::Submit {
                order: Box::new(order.clone()),
            },
        )?;
        let r = self.answer_confirm(&mut c, &n, &order.id, safety)?;
        match r.msg {
            Msg::Outcome { outcome } => Ok(*outcome),
            Msg::Error { code, message } => Err(format!("executor error {code}: {message}")),
            _ => Err("unexpected executor answer".into()),
        }
    }

    /// Receive the answer to request `n`; when the executor first asks for
    /// the safety state (`confirm` naming `expect_id`), answer it with
    /// `safety` and receive again.
    fn answer_confirm(
        &self,
        c: &mut Conn,
        n: &str,
        expect_id: &str,
        safety: &mut dyn FnMut() -> Result<(SafetyState, u64), String>,
    ) -> Result<proto::Received, String> {
        let r = self.recv(c, n)?;
        let Msg::Confirm { id } = &r.msg else {
            return Ok(r);
        };
        if id != expect_id {
            return Err("executor confirmed another order".into());
        }
        let answer = match safety() {
            Ok((state, age_ms)) => Msg::Safety { state, age_ms },
            Err(reason) => Msg::NoSafety { reason },
        };
        self.send(c, &r.nonce, &answer)?;
        self.recv(c, n)
    }

    /// An unsigned revert (planner actions; a SOC-approved action answers
    /// with a `soc_signature_invalid` refusal and stays in force).
    pub fn revert(&self, id: &str, reason: &str) -> Result<Outcome, String> {
        self.revert_signed(id, reason, None)
    }

    /// A revert with the SOC's signed revert request (review finding F3),
    /// telling the executor that no safety state is available (an active
    /// `safe_pause` then stays in force: [`Client::revert_with_safety`]).
    pub fn revert_signed(
        &self,
        id: &str,
        reason: &str,
        soc: Option<&crate::soc::SocRequest>,
    ) -> Result<Outcome, String> {
        self.revert_with_safety(id, reason, soc, &mut || {
            Err("this client supplies no safety state".into())
        })
    }

    /// A revert with the SOC's signed revert request. Lifting an active
    /// `safe_pause` (review finding 1) first asks for the safety state now
    /// (`safety`): it must be known, fresh, not engaged and one the
    /// pause's adapters allow, or the pause stays in force.
    pub fn revert_with_safety(
        &self,
        id: &str,
        reason: &str,
        soc: Option<&crate::soc::SocRequest>,
        safety: &mut dyn FnMut() -> Result<(SafetyState, u64), String>,
    ) -> Result<Outcome, String> {
        let mut c = self.connect()?;
        let n = self.send(
            &mut c,
            "",
            &Msg::Revert {
                id: id.into(),
                reason: reason.into(),
                soc: soc.map(|s| Box::new(s.clone())),
            },
        )?;
        match self.answer_confirm(&mut c, &n, id, safety)?.msg {
            Msg::Outcome { outcome } => Ok(*outcome),
            _ => Err("unexpected executor answer".into()),
        }
    }

    pub fn status(&self, id: &str) -> Result<Outcome, String> {
        match self.call(&Msg::Status { id: id.into() })? {
            Msg::Outcome { outcome } => Ok(*outcome),
            _ => Err("unexpected executor answer".into()),
        }
    }

    /// Events since `since`, telling the executor that no safety state is
    /// available (actions held after a reboot then stay held).
    pub fn events(&self, since: u64) -> Result<Vec<Event>, String> {
        self.events_with_safety(since, &mut || {
            Err("this client supplies no safety state".into())
        })
    }

    /// Events since `since`. While actions are held after a reboot, the
    /// executor first asks for the safety state now (`safety`), and re-arms
    /// them only with a fresh, known state that is not engaged.
    pub fn events_with_safety(
        &self,
        since: u64,
        safety: &mut dyn FnMut() -> Result<(SafetyState, u64), String>,
    ) -> Result<Vec<Event>, String> {
        self.events_anchored(since, None, safety).map(|(e, _)| e)
    }

    /// [`Client::events_with_safety`] sending the journal head agentd
    /// anchored (`anchor`, review of gap 1) and returning the executor's
    /// current head with the events (`None` from an executor that does not
    /// report one).
    pub fn events_anchored(
        &self,
        since: u64,
        anchor: Option<&JournalHead>,
        safety: &mut dyn FnMut() -> Result<(SafetyState, u64), String>,
    ) -> Result<(Vec<Event>, Option<JournalHead>), String> {
        let mut c = self.connect()?;
        let n = self.send(
            &mut c,
            "",
            &Msg::Events {
                since,
                anchor: anchor.cloned(),
            },
        )?;
        match self.answer_confirm(&mut c, &n, "rearm", safety)?.msg {
            Msg::EventList { events, head } => Ok((events, head)),
            _ => Err("unexpected executor answer".into()),
        }
    }

    pub fn ping(&self) -> Result<(usize, String), String> {
        let h = self.health()?;
        Ok((h.active, h.boot_id))
    }

    /// The executor's status flags.
    pub fn health(&self) -> Result<Health, String> {
        match self.call(&Msg::Ping)? {
            Msg::Pong {
                active,
                boot_id,
                operator_disabled,
                journal_reset,
                held,
            } => Ok(Health {
                active,
                boot_id,
                operator_disabled,
                journal_reset,
                held,
            }),
            _ => Err("unexpected executor answer".into()),
        }
    }
}

/// The executor's answer to `ping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub active: usize,
    pub boot_id: String,
    /// The operator removed the table: orders are refused until `rearm`.
    pub operator_disabled: bool,
    /// The journal was unreadable and reset (High; cleared by `rearm`).
    pub journal_reset: bool,
    /// Actions held after a reboot.
    pub held: usize,
}
