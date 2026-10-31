//! A small, strict command-line parser shared by the three tools:
//! `--name VALUE` / `--name=VALUE` options (repeatable where the caller
//! allows it), `--flag` switches, positionals. Unknown options, a missing
//! value, a repeated single option and non-UTF-8 arguments are usage errors.

/// Parsed arguments.
#[derive(Debug, Default, Clone)]
pub struct Args {
    opts: Vec<(String, String)>,
    flags: Vec<String>,
    pub positional: Vec<String>,
}

impl Args {
    /// Parse `raw` against the accepted option names (`values`, without
    /// `--`) and switch names (`flags`).
    pub fn parse(raw: &[String], values: &[&str], flags: &[&str]) -> Result<Self, String> {
        let mut a = Args::default();
        let mut it = raw.iter();
        while let Some(arg) = it.next() {
            if arg == "--" {
                a.positional.extend(it.by_ref().cloned());
                break;
            }
            let Some(name) = arg.strip_prefix("--") else {
                if arg.starts_with('-') && arg.len() > 1 {
                    return Err(format!("unknown option {arg}"));
                }
                a.positional.push(arg.clone());
                continue;
            };
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };
            if values.contains(&name) {
                let v = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("--{name} needs a value"))?,
                };
                a.opts.push((name.to_string(), v));
            } else if flags.contains(&name) {
                if inline.is_some() {
                    return Err(format!("--{name} takes no value"));
                }
                a.flags.push(name.to_string());
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(a)
    }

    /// The value of a single-use option.
    pub fn one(&self, name: &str) -> Result<Option<&str>, String> {
        let mut vals = self
            .opts
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str());
        match (vals.next(), vals.next()) {
            (None, _) => Ok(None),
            (Some(v), None) => Ok(Some(v)),
            (Some(_), Some(_)) => Err(format!("--{name} given more than once")),
        }
    }

    /// Every value of a repeatable option, in order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.opts
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// A switch was given.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    /// A numeric option.
    pub fn u64_or(&self, name: &str, default: u64) -> Result<u64, String> {
        match self.one(name)? {
            None => Ok(default),
            Some(v) => v
                .parse()
                .map_err(|_| format!("--{name} {v:?}: expected a non-negative integer")),
        }
    }
}

/// `std::env::args_os` without the program name, refusing non-UTF-8.
pub fn argv() -> Result<Vec<String>, String> {
    std::env::args_os()
        .skip(1)
        .map(|a| {
            a.into_string()
                .map_err(|a| format!("argument {a:?} is not UTF-8"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_and_refuses() {
        let a = Args::parse(&v(&["x", "--a", "1", "--b=2", "--f"]), &["a", "b"], &["f"]).unwrap();
        assert_eq!(a.positional, ["x"]);
        assert_eq!(a.one("a").unwrap(), Some("1"));
        assert_eq!(a.one("b").unwrap(), Some("2"));
        assert!(a.flag("f"));
        assert!(Args::parse(&v(&["--zz"]), &[], &[]).is_err());
        assert!(Args::parse(&v(&["--a"]), &["a"], &[]).is_err());
        assert!(Args::parse(&v(&["--f=1"]), &[], &["f"]).is_err());
        assert!(Args::parse(&v(&["-x"]), &[], &[]).is_err());
        let a = Args::parse(&v(&["--a", "1", "--a", "2"]), &["a"], &[]).unwrap();
        assert!(a.one("a").is_err());
        assert_eq!(a.all("a").collect::<Vec<_>>(), ["1", "2"]);
        assert!(a.u64_or("n", 5).is_ok());
    }
}
