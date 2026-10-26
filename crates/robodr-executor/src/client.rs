//! The agentd side of the protocol ([`crate::proto`]): blocking calls with
//! a deadline. agentd runs them on its own worker thread, never on its
//! detection loop.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use robodr_responder::SafetyState;

use crate::engine::Outcome;
use crate::journal::Event;
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
        let mut r = self.recv(&mut c, &n)?;
        if let Msg::Confirm { id } = &r.msg {
            if id != &order.id {
                return Err("executor confirmed another order".into());
            }
            let answer = match safety() {
                Ok((state, age_ms)) => Msg::Safety { state, age_ms },
                Err(reason) => Msg::NoSafety { reason },
            };
            self.send(&mut c, &r.nonce, &answer)?;
            r = self.recv(&mut c, &n)?;
        }
        match r.msg {
            Msg::Outcome { outcome } => Ok(*outcome),
            Msg::Error { code, message } => Err(format!("executor error {code}: {message}")),
            _ => Err("unexpected executor answer".into()),
        }
    }

    pub fn revert(&self, id: &str, reason: &str) -> Result<Outcome, String> {
        match self.call(&Msg::Revert {
            id: id.into(),
            reason: reason.into(),
        })? {
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

    pub fn events(&self, since: u64) -> Result<Vec<Event>, String> {
        match self.call(&Msg::Events { since })? {
            Msg::EventList { events } => Ok(events),
            _ => Err("unexpected executor answer".into()),
        }
    }

    pub fn ping(&self) -> Result<(usize, String), String> {
        match self.call(&Msg::Ping)? {
            Msg::Pong { active, boot_id } => Ok((active, boot_id)),
            _ => Err("unexpected executor answer".into()),
        }
    }
}
