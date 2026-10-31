//! The sensor box image recipe (packaging/sensor-box/image, T77): the boot
//! scripts against a temporary root with stub commands, and build-image.sh
//! against real minisign signatures with a stub mkosi.

mod common;

use common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn recipe() -> PathBuf {
    repo().join("packaging/sensor-box/image")
}

fn copy_tree(src: &Path, dst: &Path) {
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            copy_tree(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

fn stub(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A box root with the image's files, the package's examples and stubs.
struct BoxRoot {
    t: Tmp,
    stubs: PathBuf,
    log: PathBuf,
}

impl BoxRoot {
    fn new(tag: &str, cmdline: &str, setup_rc: i32) -> Self {
        let t = Tmp::new(tag);
        copy_tree(&recipe().join("mkosi.extra"), &t.0);
        let ex = t.path("/usr/share/doc/robodr/examples/sensor-box");
        std::fs::create_dir_all(&ex).unwrap();
        std::fs::copy(
            repo().join("packaging/sensor-box/10-robodr-capture.network.example"),
            ex.join("10-robodr-capture.network.example"),
        )
        .unwrap();
        t.put("/proc/cmdline", cmdline);
        std::fs::create_dir_all(t.path("/etc/robodr")).unwrap();
        let stubs = t.path("/stubs");
        std::fs::create_dir_all(&stubs).unwrap();
        let log = t.path("/calls.log");
        let l = log.display();
        stub(
            &stubs,
            "robodr-setup",
            &format!(
                "echo \"robodr-setup $*\" >>{l}\ncase \"$1\" in fingerprints) echo 'key id ed25519:00112233';; \
                 *) echo '{{\"result\":\"ok\"}}'; exit {setup_rc};; esac"
            ),
        );
        stub(&stubs, "systemctl", &format!("echo \"systemctl $*\" >>{l}"));
        stub(&stubs, "findmnt", "echo /dev/vda3");
        // nft refuses a ruleset that contains BROKEN.
        stub(
            &stubs,
            "nft",
            &format!("echo \"nft $*\" >>{l}\n! grep -q BROKEN \"$2\""),
        );
        BoxRoot { t, stubs, log }
    }

    fn run(&self, script: &str) -> Output {
        Command::new("sh")
            .arg(self.t.path(&format!("/usr/lib/robodr-image/{script}")))
            .env("ROBODR_IMAGE_ROOT", &self.t.0)
            .env("ROBODR_IMAGE_TEST_PATH", &self.stubs)
            .output()
            .unwrap()
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn read(&self, p: &str) -> String {
        std::fs::read_to_string(self.t.path(p)).unwrap_or_default()
    }
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn early_provisions_from_the_command_line_and_renders_runtime_config() {
    let b = BoxRoot::new(
        "img-early",
        "ro quiet robodr.unit_id=sb-07 robodr.capture_if=enp2s0 robodr.uplink_if=enp1s0 \
         robodr.site=plant-a robodr.ntp=192.0.2.123 robodr.exporter=uplink \
         robodr.role=$(reboot) robodr.capture_if2=x\n",
        0,
    );
    let o = b.run("robodr-image-early");
    assert!(o.status.success(), "{}", err(&o));
    let p = b.read("/etc/robodr/provision.env");
    for want in [
        "ROBODR_UNIT_ID=sb-07",
        "ROBODR_CAPTURE_IF=enp2s0",
        "ROBODR_UPLINK_IF=enp1s0",
        "ROBODR_SITE=plant-a",
        "ROBODR_NTP=192.0.2.123",
        "ROBODR_EXPORTER=uplink",
    ] {
        assert!(p.lines().any(|l| l == want), "{want}: {p}");
    }
    assert!(!p.contains("ROBODR_ROLE"), "invalid role accepted: {p}");
    assert!(
        err(&o).contains("ignoring invalid robodr.role"),
        "{}",
        err(&o)
    );
    assert_eq!(mode(&b.t.path("/etc/robodr/provision.env")), 0o640);
    let cap = b.read("/run/systemd/network/10-robodr-capture.network");
    assert!(cap.lines().any(|l| l == "Name=enp2s0"), "{cap}");
    assert!(
        cap.contains("Promiscuous=yes") && cap.contains("ARP=no"),
        "{cap}"
    );
    let up = b.read("/run/systemd/network/20-robodr-uplink.network");
    assert!(
        up.contains("Name=enp1s0") && up.contains("DHCP=yes"),
        "{up}"
    );
    assert!(b
        .read("/run/systemd/timesyncd.conf.d/50-robodr.conf")
        .contains("NTP=192.0.2.123"));
    let fw = b.read("/etc/robodr/nftables.conf");
    assert!(
        fw.contains("policy drop") && fw.contains("robodr_sensor_box"),
        "{fw}"
    );
    // A provisioning file that exists is never rewritten from the
    // command line; a site firewall is never replaced.
    b.t.put(
        "/etc/robodr/provision.env",
        "ROBODR_UNIT_ID=kept\nROBODR_CAPTURE_IF=eth9\n",
    );
    b.t.put("/etc/robodr/nftables.conf", "site rules\n");
    b.t.put(
        "/etc/robodr/network/uplink.network",
        "[Match]\nName=enp1s0\n[Network]\nAddress=10.0.0.5/24\n",
    );
    let o = b.run("robodr-image-early");
    assert!(o.status.success(), "{}", err(&o));
    assert!(b
        .read("/etc/robodr/provision.env")
        .contains("ROBODR_UNIT_ID=kept"));
    assert_eq!(b.read("/etc/robodr/nftables.conf"), "site rules\n");
    assert!(b
        .read("/run/systemd/network/10-robodr-capture.network")
        .contains("Name=eth9"));
    assert!(b
        .read("/run/systemd/network/50-site-uplink.network")
        .contains("10.0.0.5"));
}

/// robodr.ntp must be an IP address: the strict default firewall lets no
/// DNS out, so a host name would never resolve.
#[test]
fn early_accepts_only_an_ip_address_for_ntp() {
    let b = BoxRoot::new(
        "img-ntp-name",
        "robodr.unit_id=sb-07 robodr.ntp=pool.ntp.example\n",
        0,
    );
    let o = b.run("robodr-image-early");
    assert!(o.status.success(), "{}", err(&o));
    assert!(!b.read("/etc/robodr/provision.env").contains("NTP"));
    assert!(err(&o).contains("not an IP address"), "{}", err(&o));
    assert!(!b
        .t
        .path("/run/systemd/timesyncd.conf.d/50-robodr.conf")
        .exists());
    // From provision.env too.
    b.t.put("/etc/robodr/provision.env", "ROBODR_NTP=ntp.site.example\n");
    let o = b.run("robodr-image-early");
    assert!(o.status.success(), "{}", err(&o));
    assert!(err(&o).contains("not an IP address"), "{}", err(&o));
    // IPv6 is an address.
    let b = BoxRoot::new("img-ntp-v6", "robodr.ntp=2001:db8::123\n", 0);
    assert!(b.run("robodr-image-early").status.success());
    assert!(b
        .read("/run/systemd/timesyncd.conf.d/50-robodr.conf")
        .contains("NTP=2001:db8::123"));
}

/// The firewall goes in before anything else can fail; and whatever
/// happens to robodr-image-early, nftables.service (robodr-nft-load) loads
/// a ruleset: the site's, or the strict default (fail closed).
#[test]
fn the_host_firewall_never_depends_on_early_succeeding() {
    let b = BoxRoot::new("img-fw-first", "robodr.unit_id=sb-07\n", 0);
    // Provisioning cannot be written (here: its temporary name is taken).
    std::fs::create_dir_all(b.t.path("/etc/robodr/provision.env.tmp")).unwrap();
    let o = b.run("robodr-image-early");
    assert!(!o.status.success());
    assert!(
        b.read("/etc/robodr/nftables.conf").contains("policy drop"),
        "firewall not installed before the failure: {}",
        err(&o)
    );

    let unit = std::fs::read_to_string(
        recipe().join("mkosi.extra/usr/lib/systemd/system/nftables.service.d/50-robodr-image.conf"),
    )
    .unwrap();
    assert!(unit.contains("ExecStart=\nExecStart=/usr/lib/robodr-image/robodr-nft-load"));
    assert!(unit.contains("After=robodr-image-early.service"));

    // The site's ruleset loads: only it.
    let b = BoxRoot::new("img-nft-site", "\n", 0);
    b.t.put("/etc/robodr/nftables.conf", "site rules\n");
    let o = b.run("robodr-nft-load");
    assert!(o.status.success(), "{}", err(&o));
    let root = b.t.0.display().to_string();
    assert_eq!(
        b.calls(),
        format!("nft -f {root}/etc/robodr/nftables.conf\n")
    );
    // Refused by nft: the default instead, and the unit fails visibly.
    b.t.put("/etc/robodr/nftables.conf", "BROKEN\n");
    std::fs::remove_file(&b.log).unwrap();
    let o = b.run("robodr-nft-load");
    assert_eq!(o.status.code(), Some(1));
    assert!(
        b.calls().ends_with(&format!(
            "nft -f {root}/usr/lib/robodr-image/nftables.default.conf\n"
        )),
        "{}",
        b.calls()
    );
    assert!(err(&o).contains("did not load"), "{}", err(&o));
    // Missing (overlay or early failed): the default.
    std::fs::remove_file(b.t.path("/etc/robodr/nftables.conf")).unwrap();
    std::fs::remove_file(&b.log).unwrap();
    let o = b.run("robodr-nft-load");
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        b.calls(),
        format!("nft -f {root}/usr/lib/robodr-image/nftables.default.conf\n")
    );
    assert!(err(&o).contains("missing"), "{}", err(&o));
}

#[test]
fn early_never_fails_the_boot_when_unprovisioned() {
    let b = BoxRoot::new("img-unprov", "ro quiet\n", 0);
    let o = b.run("robodr-image-early");
    assert!(o.status.success(), "{}", err(&o));
    assert!(err(&o).contains("not provisioned"));
    assert!(!b.t.path("/etc/robodr/provision.env").exists());
    // The strict firewall is in place anyway.
    assert!(b.read("/etc/robodr/nftables.conf").contains("policy drop"));
    // Late refuses to generate keys without a unit id, and says why.
    let o = b.run("robodr-image-late");
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("ROBODR_UNIT_ID"), "{}", err(&o));
    assert!(!b.calls().contains("robodr-setup"));
    assert!(!b.t.path("/var/lib/robodr-image/firstboot.done").exists());
}

#[test]
fn late_generates_keys_once_and_starts_only_what_is_commissioned() {
    let b = BoxRoot::new(
        "img-late",
        "robodr.unit_id=sb-07 robodr.capture_if=enp2s0 robodr.site=plant-a robodr.exporter=uplink\n",
        0,
    );
    assert!(b.run("robodr-image-early").status.success());
    let o = b.run("robodr-image-late");
    assert!(o.status.success(), "{}", err(&o));
    let calls = b.calls();
    let root = b.t.0.display().to_string();
    assert!(
        calls.contains(&format!(
            "robodr-setup init --role unitree-sensor-box --unit-id sb-07 --interface enp2s0 --json --site plant-a --root {root}"
        )),
        "{calls}"
    );
    assert!(
        err(&o).contains("ed25519:00112233"),
        "fingerprints shown: {}",
        err(&o)
    );
    assert!(err(&o).contains("not on dm-crypt"), "{}", err(&o));
    assert!(b
        .read("/var/lib/robodr-image/fingerprints.txt")
        .contains("ed25519:00112233"));
    assert_eq!(mode(&b.t.path("/var/lib/robodr-image/setup.json")), 0o600);
    // Not commissioned: nothing started.
    assert!(!calls.contains("systemctl start"), "{calls}");
    // Commissioned, exporter configured: started (this boot only); no
    // second init.
    b.t.put("/etc/robodr/agentd.json", "{}");
    b.t.put("/etc/robodr/profile.json", "{}");
    b.t.put("/etc/robodr/uplink.env", "X=1\n");
    std::fs::remove_file(&b.log).unwrap();
    let o = b.run("robodr-image-late");
    assert!(o.status.success(), "{}", err(&o));
    let calls = b.calls();
    assert!(!calls.contains("robodr-setup init"), "{calls}");
    assert!(
        calls.contains("systemctl start --no-block robodr-agentd.service"),
        "{calls}"
    );
    assert!(
        calls.contains("systemctl start --no-block robodr-uplink.service"),
        "{calls}"
    );
    assert!(!calls.contains("enable"), "{calls}");
}

#[test]
fn a_failed_preflight_leaves_no_marker_and_retries() {
    let b = BoxRoot::new(
        "img-fail",
        "robodr.unit_id=sb-07 robodr.capture_if=enp2s0\n",
        1,
    );
    assert!(b.run("robodr-image-early").status.success());
    let o = b.run("robodr-image-late");
    assert_eq!(o.status.code(), Some(1));
    assert!(
        err(&o).contains("runs again at the next boot"),
        "{}",
        err(&o)
    );
    // It was the preflight's refusal, not a broken stub.
    assert!(
        b.calls().contains("robodr-setup init --role"),
        "{}",
        b.calls()
    );
    assert!(!err(&o).contains("Syntax error"), "{}", err(&o));
    assert!(!b.t.path("/var/lib/robodr-image/firstboot.done").exists());
    assert!(!b.t.path("/var/lib/robodr-image/setup.json").exists());
}

fn have(tool: &str) -> bool {
    robodr_ops::exec::which(tool).is_some()
}

/// A fake offline bundle signed with a fresh minisign key (minisign's
/// default trusted comment).
fn signed_bundle(t: &Tmp, tamper: bool) -> (PathBuf, PathBuf) {
    signed_bundle_tc(t, tamper, "0.1", None)
}

/// A fake offline bundle of `version`, signed with trusted comment `tc`
/// (`None`: minisign's default, `timestamp:... file:<name> hashed`).
fn signed_bundle_tc(t: &Tmp, tamper: bool, version: &str, tc: Option<&str>) -> (PathBuf, PathBuf) {
    let keys = t.path("/keys");
    std::fs::create_dir_all(&keys).unwrap();
    let o = Command::new("minisign")
        .args(["-G", "-W", "-p"])
        .arg(keys.join("release.pub"))
        .arg("-s")
        .arg(keys.join("release.key"))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let stage = t.path(&format!("/stage/robodr-{version}-amd64"));
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("robodr_0.1-1_amd64.deb"), b"not really a deb").unwrap();
    let o = Command::new("sh")
        .arg("-c")
        .arg("sha256sum robodr_0.1-1_amd64.deb >SHA256SUMS")
        .current_dir(&stage)
        .output()
        .unwrap();
    assert!(o.status.success());
    if tamper {
        std::fs::write(stage.join("robodr_0.1-1_amd64.deb"), b"tampered").unwrap();
    }
    let dl = t.path("/download");
    std::fs::create_dir_all(&dl).unwrap();
    let bundle = dl.join(format!("robodr-{version}-amd64-offline.tar.gz"));
    let o = Command::new("tar")
        .arg("-czf")
        .arg(&bundle)
        .arg("-C")
        .arg(t.path("/stage"))
        .arg(format!("robodr-{version}-amd64"))
        .output()
        .unwrap();
    assert!(o.status.success());
    let mut sign = Command::new("minisign");
    sign.args(["-S", "-s"])
        .arg(keys.join("release.key"))
        .arg("-m")
        .arg(&bundle);
    if let Some(tc) = tc {
        sign.arg("-t").arg(tc);
    }
    let o = sign.output().unwrap();
    assert!(o.status.success(), "{}", err(&o));
    (bundle, keys.join("release.pub"))
}

fn build(t: &Tmp, bundle: &Path, pubkey: &Path) -> (Output, String) {
    build_with(t, bundle, pubkey, &[])
}

fn build_with(t: &Tmp, bundle: &Path, pubkey: &Path, extra: &[&str]) -> (Output, String) {
    let stubs = t.path("/mkosi-stub");
    std::fs::create_dir_all(&stubs).unwrap();
    let log = t.path("/mkosi.log");
    stub(
        &stubs,
        "mkosi",
        &format!(
            "echo \"$*\" >{l}\nfor a; do case \"$a\" in --extra-tree=*) find \"${{a#--extra-tree=}}\" -type f | sort >>{l};; esac; done\nmkdir -p \"$PWD/out\"",
            l = log.display()
        ),
    );
    let o = Command::new("sh")
        .arg(recipe().join("build-image.sh"))
        .arg("--bundle")
        .arg(bundle)
        .arg("--pubkey")
        .arg(pubkey)
        .arg("--out")
        .arg(t.path("/out"))
        .arg("--mkosi")
        .arg(stubs.join("mkosi"))
        .args(extra)
        .output()
        .unwrap();
    (o, std::fs::read_to_string(&log).unwrap_or_default())
}

#[test]
fn build_image_verifies_the_signed_bundle_before_mkosi() {
    if !have("minisign") {
        assert!(std::env::var("ROBODR_REQUIRE_MINISIGN_TEST").as_deref() != Ok("1"));
        eprintln!("SKIPPED build_image: needs minisign");
        return;
    }
    // Good bundle: mkosi gets the verified .deb and its digest.
    let t = Tmp::new("img-build");
    let (bundle, pubkey) = signed_bundle(&t, false);
    let (o, log) = build(&t, &bundle, &pubkey);
    assert!(o.status.success(), "{}", err(&o));
    assert!(log.contains("--architecture=x86-64"), "{log}");
    assert!(
        log.contains("/var/cache/robodr-image/robodr_0.1-1_amd64.deb"),
        "{log}"
    );
    assert!(
        log.contains("/var/cache/robodr-image/robodr.deb.sha256"),
        "{log}"
    );
    assert!(
        log.contains("/usr/share/doc/robodr/sensor-box-image/README.md"),
        "{log}"
    );

    // A bundle modified after signing: refused, mkosi never runs.
    let t2 = Tmp::new("img-build-badsig");
    let (bundle2, pubkey2) = signed_bundle(&t2, false);
    let mut b = std::fs::read(&bundle2).unwrap();
    let n = b.len() - 1;
    b[n] ^= 1;
    std::fs::write(&bundle2, b).unwrap();
    let (o, log) = build(&t2, &bundle2, &pubkey2);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("signature check FAILED"), "{}", err(&o));
    assert!(log.is_empty(), "{log}");

    // Signed, but its content does not match its SHA256SUMS.
    let t3 = Tmp::new("img-build-sums");
    let (bundle3, pubkey3) = signed_bundle(&t3, true);
    let (o, log) = build(&t3, &bundle3, &pubkey3);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("SHA256SUMS check FAILED"), "{}", err(&o));
    assert!(log.is_empty());

    // No signature at all; the key next to the bundle.
    std::fs::remove_file(bundle.with_extension("gz.minisig")).unwrap();
    let (o, _) = build(&t, &bundle, &pubkey);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("only signed bundles"), "{}", err(&o));
    let t4 = Tmp::new("img-build-keynext");
    let (bundle4, _) = signed_bundle(&t4, false);
    let next_to = bundle4.parent().unwrap().join("release.pub");
    std::fs::copy(t4.path("/keys/release.pub"), &next_to).unwrap();
    let (o, _) = build(&t4, &bundle4, &next_to);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("out of band"), "{}", err(&o));
}

/// The signed trusted comment binds the signature to the bundle's name and,
/// with --expect-version, to the release: an older, correctly signed bundle
/// (renamed or not) is not built by mistake.
#[test]
fn build_image_checks_the_trusted_comment() {
    if !have("minisign") {
        assert!(std::env::var("ROBODR_REQUIRE_MINISIGN_TEST").as_deref() != Ok("1"));
        eprintln!("SKIPPED build_image trusted comment: needs minisign");
        return;
    }
    // Signed as release.yml signs: "robodr <version> <file>".
    let t = Tmp::new("img-tc");
    let (bundle, pubkey) = signed_bundle_tc(
        &t,
        false,
        "0.1",
        Some("robodr 0.1 robodr-0.1-amd64-offline.tar.gz"),
    );
    let (o, log) = build_with(&t, &bundle, &pubkey, &["--expect-version", "0.1"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        String::from_utf8_lossy(&o.stdout)
            .contains("trusted comment: robodr 0.1 robodr-0.1-amd64-offline.tar.gz"),
        "{o:?}"
    );
    assert!(!log.is_empty());
    std::fs::remove_file(t.path("/mkosi.log")).unwrap();
    // The older release when 0.2 was meant: refused, mkosi never runs.
    let (o, log) = build_with(&t, &bundle, &pubkey, &["--expect-version", "0.2"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("another release"), "{}", err(&o));
    assert!(log.is_empty(), "{log}");
    // The older bundle renamed to pass for 0.2 (signature still valid).
    let renamed = bundle.with_file_name("robodr-0.2-amd64-offline.tar.gz");
    std::fs::copy(&bundle, &renamed).unwrap();
    std::fs::copy(
        bundle.with_extension("gz.minisig"),
        renamed.with_extension("gz.minisig"),
    )
    .unwrap();
    let (o, log) = build(&t, &renamed, &pubkey);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("names another file"), "{}", err(&o));
    assert!(log.is_empty(), "{log}");
    // minisign's default comment names the file but no version: fine
    // without --expect-version, refused with it.
    let t2 = Tmp::new("img-tc-default");
    let (b2, k2) = signed_bundle(&t2, false);
    let (o, _) = build(&t2, &b2, &k2);
    assert!(o.status.success(), "{}", err(&o));
    let (o, _) = build_with(&t2, &b2, &k2, &["--expect-version", "0.1"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    // A version with shell or path characters is a usage error.
    let (o, _) = build_with(&t2, &b2, &k2, &["--expect-version", "0.1;x"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
}
