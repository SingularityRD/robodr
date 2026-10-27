//! The `robodr-firewall-gw` binary: command-line handling.

/// `--version` prints `<name> <version>` and `--help` the usage, both on
/// stdout with exit 0 (the release .deb smoke test runs both on every
/// shipped binary); misuse of either stays a usage error (exit 2).
#[test]
fn version_and_help_exit_0() {
    for (name, exe) in [(
        "robodr-firewall-gw",
        env!("CARGO_BIN_EXE_robodr-firewall-gw"),
    )] {
        let o = std::process::Command::new(exe)
            .arg("--version")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{name} --version");
        assert_eq!(
            String::from_utf8_lossy(&o.stdout),
            format!("{name} {}\n", env!("CARGO_PKG_VERSION")),
            "{name} --version"
        );
        let o = std::process::Command::new(exe)
            .arg("--help")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{name} --help");
        assert!(
            String::from_utf8_lossy(&o.stdout).contains(name),
            "{name} --help prints the usage on stdout"
        );
        for bad in [&["--version", "--bogus"][..], &["--bogus"][..]] {
            let o = std::process::Command::new(exe).args(bad).output().unwrap();
            assert_eq!(o.status.code(), Some(2), "{name} {bad:?}");
            assert!(o.stdout.is_empty(), "{name} {bad:?}");
        }
    }
}
