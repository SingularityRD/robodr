#![allow(dead_code)]

use robodr_ops::exec::{Output, Runner};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A temporary directory removed on drop.
pub struct Tmp(pub PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Self {
        // Only [A-Za-z0-9-] in the name: the paths end up in shell stubs.
        let thread: String = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        let d =
            std::env::temp_dir().join(format!("robodr-ops-{tag}-{}-{thread}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    /// Write `rel` (an absolute host path) under the root.
    pub fn put(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.0.join(rel.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel.trim_start_matches('/'))
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Canned command outputs: "prog arg arg" -> (exit, stdout). Anything else
/// is "not installed".
#[derive(Default)]
pub struct Fake(pub HashMap<String, (i32, String)>);

impl Fake {
    pub fn with(mut self, cmd: &str, code: i32, out: &str) -> Self {
        self.0.insert(cmd.to_string(), (code, out.to_string()));
        self
    }
}

impl Runner for Fake {
    fn run(&self, prog: &str, args: &[&str]) -> std::io::Result<Output> {
        let key = std::iter::once(prog)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        // Prefix match on the program alone too ("df" for any df call).
        let hit = self.0.get(&key).or_else(|| self.0.get(prog));
        match hit {
            Some((code, out)) => Ok(Output {
                code: Some(*code),
                stdout: out.clone().into_bytes(),
                ..Default::default()
            }),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{key}: not installed"),
            )),
        }
    }
}

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

pub fn mkdir_mode(p: &Path, m: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}
