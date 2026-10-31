# RoboDR packaging

This directory holds everything that turns the workspace into something an
operator installs on a robot. The procedures that use it are in
[`docs/OPERATIONS.md`](../docs/OPERATIONS.md).

| Path | Installed as | Purpose |
|---|---|---|
| `systemd/robodr-pulsard.service` | `/usr/lib/systemd/system/` | eBPF + ROS 2 sensor daemon |
| `systemd/robodr-agentd.service` | `/usr/lib/systemd/system/` | decision chain, black box, OCSF spool (only if the binary is built) |
| `systemd/robodr-agentd.service.d/20-finding-key.conf.example` | `/usr/share/doc/robodr/examples/` | optional drop-in: `LoadCredential=` for the per-finding signing key (OPERATIONS 6.4) |
| `systemd/robodr-agentd.service.d/30-control-plane.conf.example` | `/usr/share/doc/robodr/examples/` | optional drop-in for the control plane v2: `ReadWritePaths=` for its state directory, `LoadCredential=` for its TLS server key, `IPAddressAllow=` for the SOC network (OPERATIONS 6.4) |
| `systemd/robodr-agentd.service.d/40-sensor-box.conf.example` | `/usr/share/doc/robodr/examples/` | **sensor box only**: passive tap / port-mirror mode of `robodr-agentd` (`CAP_NET_RAW` only, all IP denied, waits for the writable data mount; [`docs/UNITREE.md`](../docs/UNITREE.md)) |
| `sensor-box/10-robodr-capture.network.example` | `/usr/share/doc/robodr/examples/sensor-box/` | **sensor box only**: systemd-networkd file for the capture NIC (no address, no ARP, no IPv6 link-local, promiscuous) |
| `sensor-box/nftables.conf.example` | `/usr/share/doc/robodr/examples/sensor-box/` | **sensor box only**: host firewall (capture NIC silent, uplink to the Kafka broker set, NTP and admin SSH only, no forwarding) |
| `sensor-box/image/` | (build time) | **sensor box image recipe** (mkosi, Ubuntu 24.04): `build-image.sh` verifies a signed offline bundle (minisign, then `SHA256SUMS`) and builds a disk image with a read-only root, writable `/var`, `/etc/robodr` as an overlay on `/var`, a strict default host firewall, and keys generated on the box at first boot (`robodr-setup init`); see its [README](sensor-box/image/README.md). Not yet built and booted on reference hardware (B7) |
| `systemd/robodr-spool-export.service` | `/usr/lib/systemd/system/` | robot-side findings exporter for **diode sites**: agentd spool -> signed batches in `/var/lib/robodr/export/diode`; `User=robodr-spool` (its own user, group `robodr`), `PrivateNetwork=yes`, key via `LoadCredential=` (`/etc/robodr/keys/diode.key`), settings in `/etc/robodr/spool-export.env` (only if the binary is built) |
| `systemd/robodr-kafka-publish.service` | `/usr/lib/systemd/system/` | findings publisher for **connected sites**, running on the unit or sensor box: agentd spool -> Kafka; `User=robodr-kafka`, `IPAddressDeny=any` plus the broker drop-in, settings in `/etc/robodr/kafka-publish.env`. Conflicts with the exporter above (only if the binary is built) |
| `systemd/robodr-kafka-publish.service.d/50-brokers.conf.example` | `/usr/share/doc/robodr/examples/` | `IPAddressAllow=` for **every** Kafka broker (the publisher connects to each partition leader, not only to the bootstrap broker) |
| `systemd/robodr-kafka-publish.service.d/60-tls-credentials.conf.example` | `/usr/share/doc/robodr/examples/` | `LoadCredential=` for the mutual-TLS client key and the SASL/SCRAM password file, named in `ROBODR_KAFKA_TLS_ARGS` (`--tls-key`, `--sasl-password-file`); in **`robodr-focal`** the same path holds `systemd/focal/robodr-kafka-publish.service.d/60-tls-credentials.conf.example`, which does it with `robodr-load-credential` (systemd 245) |
| `systemd/robodr-uplink.service` | `/usr/lib/systemd/system/` | findings uplink to the SOC's AutoSecOps ingest API for **connected sites**, running on the unit or sensor box: agentd spool -> HTTPS (signed batches, CA bundle `/etc/robodr/uplink-ca.pem`, optional SPKI pin); `User=robodr-uplink`, key via `LoadCredential=` (`/etc/robodr/keys/uplink.key`), `IPAddressDeny=any` plus the SOC drop-in, settings in `/etc/robodr/uplink.env`. Conflicts with both units above (only if the binary is built) |
| `systemd/robodr-uplink.service.d/50-soc.conf.example` | `/usr/share/doc/robodr/examples/` | `IPAddressAllow=` for the SOC ingest address(es) (map the URL's host name in `/etc/hosts`: DNS is not reachable) |
| `etc/spool-export.env.example`, `etc/kafka-publish.env.example`, `etc/uplink.env.example` | `/usr/share/doc/robodr/examples/` | the three exporter units' site settings (unit id; bootstrap brokers; ingest URL and pin) |
| `systemd/focal/*.service`, `systemd/focal/<unit>.service.d/*.conf.example` | `/usr/lib/systemd/system/` (and examples) of **`robodr-focal`** | systemd 245 variants (Ubuntu 20.04 / JetPack 5): `LoadCredential=` replaced by `robodr-load-credential`, no `ProtectProc=` / `ProcSubset=`; otherwise identical, enforced by `scripts/check-focal-units.py`. `build-deb.sh --variant focal` takes a drop-in example from `systemd/focal/` when it exists there and the regular one otherwise; the checker then requires the regular one to need nothing newer than systemd 245 |
| `focal/robodr-load-credential` | `/usr/lib/robodr/` of **`robodr-focal`** | POSIX sh helper run as root (`ExecStartPre=+`): copies a root-only key to `/run/credentials/<unit>/<name>`, `0400` owned by the service user, in a root-owned `0711` directory; `clear` on stop. Refuses `root` as the owner except for `robodr-deliverd.service` (`root_units`, checked by `scripts/check-focal-units.py`; tests: `scripts/test-load-credential.sh`) |
| `systemd/robodr-anchor-receiver.service` | `/usr/lib/systemd/system/` | **base station only**: remote head-anchor receiver (only if the binary is built; OPERATIONS 6.4, "Remote anchor"). Not yet checked with `systemd-analyze` |
| `systemd/robodr-pulsard.service.d/10-cap-sys-admin.conf.example` | `/usr/share/doc/robodr/examples/` | opt-in for kernels < 5.8 |
| `btf/robodr-btf-check` | `/usr/lib/robodr/` of **`robodr`** (with `robodr-pulsard`) | `ExecStartPre=` of `robodr-pulsard.service`: on a kernel without BTF, reads `[pulsar] btf_path` from `pulsar.toml`, refuses any path but `/etc/robodr/btf/vmlinux`, and refuses to start when that file was not generated for the running kernel or was replaced (stamp `vmlinux.kernel` = `uname -r`, `uname -v`, SHA-256 of the file); no-op while `btf_path` is unset (tests: `scripts/test-btf-check.sh`) ([`docs/UNITREE.md`](../docs/UNITREE.md) 3.2.1) |
| `systemd/robodr-pulsard.service.d/30-host-threats.conf.example` | `/usr/share/doc/robodr/examples/` | optional drop-in: `SupplementaryGroups=robodr-agentd` so `robodr-threat-forward` can reach agentd's `0660` host-threat socket (OPERATIONS 6.4) |
| `metrics/robodr-metrics.service`, `metrics/robodr-metrics.timer` | `/usr/lib/systemd/system/` (disabled; `systemctl enable --now robodr-metrics.timer`) | optional: refresh `/run/robodr-metrics/robodr.prom` every 15 s with `robodr-metrics` for node_exporter's textfile collector (no listening port; root with `CAP_DAC_READ_SEARCH` only, `PrivateNetwork=yes`, key and evidence trees hidden); `man robodr-metrics` |
| `metrics/robodr-alerts.example.yml` | `/usr/share/doc/robodr/examples/metrics/` | example Prometheus alert rules (exporter stale, agent unreadable / stale / blind / degraded, evidence degraded, spool dropping, queue near full, anchor failures, uplink blocked / not delivering); `crates/robodr-ops/tests/metrics.rs` fails if a rule names a metric the exporter does not write |
| `modules-load.d/robodr.conf.example` | `/usr/share/doc/robodr/examples/modules-load.d/` | kernel modules of the enforcing units (`nf_tables` for `robodr-executor`; the gateway's, commented out) for `/etc/modules-load.d/` |
| `demo/README.md` (+ `fixtures/captures/ros2-jazzy/fastrtps_{baseline,rogue_cmd_vel}.pcap`) | `/usr/share/doc/robodr/demo/` (with `SHA256SUMS`) | demo without a robot: learn a profile from the clean run, replay the rogue `/cmd_vel` run with `robodr-ros2-watch` |
| `../docs/customer/*.md` except `*-draft.md` | `/usr/share/doc/robodr/customer/` | the customer documents (quick start, known limitations, support matrix, security white paper, PSIRT process); drafts are never shipped (`scripts/check-packages.py`) |
| `tmpfiles.d/robodr.conf` | `/usr/lib/tmpfiles.d/` | directories, modes, owners |
| `sysusers.d/robodr.conf` | `/usr/lib/sysusers.d/` | the `robodr` system user |
| `etc/pulsar.base.toml` | header of `/etc/robodr/pulsar.toml` | daemon config (conffile) |
| `deb/` | `DEBIAN/` | control template, maintainer scripts |
| `rpm/robodr.spec.in`, `rpm/{pre,post,preun,postun}` | RPM header / scriptlets | spec template and the scriptlets, the counterparts of `deb/preinst`, `postinst`, `prerm`, `postrm` (`scripts/check-packages.py` checks both stop and restart the same units, and that the pre-install scripts carry the same gateway migration gate as the post-install scripts) |
| `build-deb.sh` | (build time) | reproducible `.deb` from built binaries: `robodr` (default) or `robodr-focal` (`--variant focal`, static binaries only); `--stage-only DIR` writes just the file tree (for `build-rpm.sh`). `Depends:` from `dpkg-shlibdeps` and a soname table, libc6 floor from `readelf -V` (docs/BUILD.md "Release build userlands") |
| `build-rpm.sh` | (build time) | `robodr` RPM (RHEL / Rocky / Alma 9, Fedora) from binaries built on Rocky Linux 9, with the `.deb`'s file tree; reproducible mtimes and build time |
| `make-bundle.sh` | (build time) | offline install bundle: `--deb` (Debian / Ubuntu / JetPack) or `--rpm` (`robodr-<ver>-<arch>-rpm-offline.tar.gz`, RHEL / Rocky / Alma 9, Fedora) |
| `install-bundle.sh` | inside the bundle; `/usr/lib/robodr/install-bundle.sh` | verify (signature, then a private extraction), install, list, roll back on the robot, with dpkg or `rpm -U` (same checks for both formats); the installed copy is the trusted verifier for the next upgrade. Signatures are checked with the installed release's built-in verifier (`robodr-deliverd verify-minisign`), gateway / executor restarts go through the safety-state gate, every install is health-checked with automatic rollback, `--keep N` prunes kept releases (`docs/SECURE-DEFAULTS.md`) |
| `release-maintainer.sh` | (build time; sourced by `build-deb.sh`, `build-rpm.sh`) | with `ROBODR_RELEASE=1` (release.yml) the `.deb` `Maintainer:` / RPM `Packager:` (`DEB_MAINTAINER`, `RPM_PACKAGER`; repository variable `ROBODR_MAINTAINER`) must be `Name <address>` and not a placeholder (`@invalid`, `example.*`, `localhost`); development builds keep `robodr-maintainers@invalid` |
| `licenses/MIT.txt` | (build time) | MIT template for `THIRD_PARTY_NOTICES`: filled only with a crate's real copyright holders (`OVERRIDES` in `scripts/third_party_notices.py`) or the Rust project's; never shipped with a placeholder |
| `licenses/musl-1.2.5-COPYRIGHT`, `licenses/Unicode-3.0.txt`, `licenses/LLVM-exception.txt` | (build time) | texts of the statically linked runtime code in `THIRD_PARTY_NOTICES`: musl libc and LLVM libunwind (robodr-focal), the Rust standard library |
| `../THIRD_PARTY_NOTICES`, `../GPL-2.0-SOURCE-OFFER` | `/usr/share/doc/robodr/` (RPM: `%license`); `doc/` of every bundle | third-party crate notices and the written source offer for the Pulsar eBPF probes; committed, generated by `scripts/third_party_notices.py`, checked by CI job `deny` |
| `security-floor` | inside the bundle | `min_version=`: no install or rollback below it (recorded per unit, only rises) |

The units, tmpfiles and sysusers fragments were checked with
`systemd-analyze verify`, `systemd-analyze security --offline`,
`systemd-sysusers --root` and `systemd-tmpfiles --root` (systemd 255).
`systemd-analyze security` exposure is 3.0 for `robodr-pulsard` and 1.5 for
`robodr-agentd` (lower is better). None of them has run on a robot yet. See "Not verified" at the end.

## Services and what is not a service

| Program | How it runs | Why |
|---|---|---|
| `robodr-pulsard` | systemd service, root with a bounded capability set | Pulsar requires euid 0 and loads eBPF |
| `robodr-agentd` | systemd service, user `robodr-agentd` (member of `robodr`), `CAP_NET_RAW` only | long-running decision chain; needs nothing else |
| `robodr-commission` | **not a service**: run by an operator, as needed | commissioning is a deliberate, human-reviewed act (learn, sign off, lock). A timer or unit that re-learns a profile automatically would let an attacker who is present during learning become "normal". |
| `robodr-replay`, `robodr-ros2-watch` | operator tools | offline analysis and lab replay |
| `robodr-enroll` | **not a service**: root-only operator tool (`/usr/sbin`) | enrollment, key rotation, revocation lists, SOC profiles and ring information (OPERATIONS 8.6); every step is a deliberate operator act, nothing is applied by the SOC on its own |
| `robodr-setup`, `robodr-support-bundle` | **not services**: root-only operator tools (`/usr/sbin`) | first-boot preflight, keys, role configuration and key fingerprints; a redacted diagnostics bundle for support (never keys, credentials or evidence). Deliberate operator acts; neither overwrites anything |
| `robodr-metrics` | operator tool (`/usr/bin`), optionally run by `robodr-metrics.timer` (installed disabled) | renders the status files as a Prometheus textfile; opens no port |
| `robodr-deliverd` | systemd service on the **unit**, root with a bounded capability set, no network | installs delivered RPKs (dpkg, `/opt` / `/etc` install roots, dropping to probe users); runs only after commissioning and `init-anchor` (OPERATIONS 11) |
| `robodr-seal` | **not a service**: root-only operator tool (`/usr/sbin`) | the unit's TPM (provisioning, refused without an owner and lockout authorization), enrolment, signed PCR policies, the sealed runtime volume, crypto-erase (OPERATIONS 12). `robodr-deliverd.service` reaches the TPM through `DeviceAllow=/dev/tpmrm0 rw` under `DevicePolicy=closed` (not `PrivateDevices=yes`, which would hide it); TPM session files go to `/run/robodr-seal` (tmpfs) |
| `robodr-depot` | systemd service on the **depot box** (never a robot), user `robodr-depot` (member of `robodr` for the spool), no capabilities, `ProtectSystem=strict`, TCP only; its other commands are operator tools run as the same user | the site depot (Sprint 14a, OPERATIONS 13): `serve` gives each enrolled unit its own pack over mutual TLS and takes its reports; imports, enrolments, approvals, rollouts and media packs are deliberate operator acts. The database anchor uses the box's TPM (`DeviceAllow=/dev/tpmrm0 rw`, group `tss` through the drop-in `50-tpm-anchor.conf.example`). `robodr-deliverd.service` needs the drop-in `50-depot-lan.conf.example` for LAN pulls (TCP to the depot only) and the erase trigger socket |
| `robodr-anchor-receiver` | systemd service on a **base station**, dynamic user, no capabilities; never enabled on a robot | holds the robots' black-box head marks off the robots |
| `robodr-spool-export` | systemd service (`User=robodr-spool`, no network, no capabilities) on the **unit or sensor box** of a diode site | loops on agentd's spool and writes signed diode batches; the transfer to the diode is the site's procedure |
| `robodr-kafka-publish` | systemd service (`User=robodr-kafka`, brokers only) on the **unit or sensor box** of a connected site; on a diode site it runs on the **SOC (high) side** after `robodr-diode-unpack`, from the SOC's own unit or procedure (`--diode-out`) | publishes findings to Kafka; one consumer per spool, so it conflicts with `robodr-spool-export` and `robodr-uplink` |
| `robodr-uplink` | systemd service (`User=robodr-uplink`, SOC address only) on the **unit or sensor box** of a connected site; on a diode site it runs on the **SOC (high) side** after `robodr-diode-unpack` (`--diode-out`, a `relay` key), from the SOC's own unit or procedure | sends findings to the AutoSecOps ingest API over TLS; one consumer per spool, so it conflicts with the two units above |

All services are installed **disabled**. A robot is commissioned first and its
locked profile installed; then the operator enables the services
(`docs/OPERATIONS.md`).

Neither service may become a dependency of the robot's motion stack, e-stop or
command authority. RoboDR is protective only. If it fails, the robot behaves
exactly as it would without RoboDR, and the failure shows in the journal.

## Why `robodr-pulsard` runs as root

Pulsar refuses to start unless `geteuid() == 0`
(`vendor/pulsar/src/pulsard.rs`), so a dedicated user is not possible without
patching Pulsar. The unit confines that root process instead:

- `CapabilityBoundingSet=` lists the only capabilities it can ever hold:
  `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_IPC_LOCK`, `CAP_NET_RAW`,
  `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` and `CAP_MAC_ADMIN`. The unit file
  justifies each one against the Pulsar code that needs it. It does **not** get
  `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_SETUID` or
  `CAP_SYS_MODULE`. Without `CAP_DAC_OVERRIDE` this root process cannot write
  files it does not own.
- `AmbientCapabilities=` is the same list. The unit sets
  `SecureBits=noroot-locked`, under which a uid-0 `execve()` gets no
  capabilities from the bounding set, only the ambient ones: without the
  ambient list the daemon would start with an empty effective set and
  `bpf()` would fail with `EPERM` (shown with `setpriv`; fixed
  2026-10-30, `scripts/check-packages.py` keeps the two lists equal for
  every `noroot` unit and drop-in). Not yet run on a BTF kernel.
- `NoNewPrivileges=yes`. It only affects `execve()` of setuid or file-cap
  binaries, so it does not affect `bpf()` or `perf_event_open()`, and Pulsar
  never execs.
- `ProtectSystem=strict`. The only writable paths are
  `/var/lib/robodr/{blackbox,spool}/pulsard` and `/run/robodr-pulsard`.
- `/proc` stays fully visible, because Pulsar must see every process.
  `/sys` is read-only and `bpffs` must already be mounted: the unit asserts it,
  and the `@mount` syscalls are not allowed.
- `SystemCallFilter=@system-service bpf perf_event_open` adds the two eBPF
  syscalls one by one, not the whole `@privileged` and `@debug` groups.
- `MemoryDenyWriteExecute=yes`. This applies only to the process's own memory
  mappings. The BPF JIT runs in the kernel and is not affected.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET`,
  with `SystemCallArchitectures=native`.

vendor/pulsar ships no systemd unit and no capability list (its README says to
run it "with administrator privileges"). The capability set above is derived
from Pulsar's code. **It has not been tested on a kernel.** If probes fail to
load with `EPERM` on a target, use the drop-in example and record why.

`robodr-agentd` is `Type=notify` with `WatchdogSec=60s`: it sends `READY=1`
after start-up and `WATCHDOG=1` from its main loop (at most once a second), so a
stalled loop (slow fsync, hang) is killed and restarted. `robodr-pulsard` stays
`Type=simple` without a watchdog, because Pulsar does not call `sd_notify()`;
with `WatchdogSec=` set, systemd would kill a healthy daemon. For it,
`Restart=on-failure` (every 10 s, `OOMPolicy=stop`, no start limit so that
repeated kills at its memory cap cannot switch host detection off for good)
covers crashes; `robodr-metrics` exports each unit's restarts, failed,
active and enabled state for alerting.
Neither watchdog has been exercised under a real systemd yet.

Every long-running unit caps its own cgroup with `MemoryMax=` (and most with
`MemoryHigh=`), so a runaway RoboDR daemon is killed inside its own limit and
restarted, instead of pushing the kernel's OOM killer onto the robot's motion
stack. `robodr-pulsard` keeps `OOMScoreAdjust=-500` (detection outlives
ordinary services) but is now bounded: `MemoryHigh=384M`, `MemoryMax=512M`
(BPF maps and perf buffers are charged to this cgroup on kernels >= 5.11),
`MemorySwapMax=0`, `CPUQuota=100%` (one CPU for the user-space side; the eBPF
programs run in the kernel) and `TasksMax=128`. These values are provisional,
estimated on a development VM; size them on the target from the commissioning
run (`systemctl show -p MemoryPeak,CPUUsageNSec robodr-pulsard`) and override
them with a drop-in, never by removing them. `scripts/check-packages.py`
(check 11) fails a long-running unit without `MemoryMax=` and
`robodr-pulsard.service` without `CPUQuota=`.

## Filesystem layout

```
/etc/robodr/                     0750 root:robodr   configuration (read-only to services)
├── pulsar.toml                  0640 root:root     robodr-pulsard config (dpkg conffile)
├── agentd.json                  0640 root:robodr   robodr-agentd config (operator-created)
├── profile.json                 0640 root:robodr   LOCKED model profile (from robodr-commission)
├── response-policy.json         0640 root:robodr   response policy (operator-created)
├── fleet.json                   0644 root:root     robodr-enroll config (operator-created)
├── fleet-soc.pub                0644 root:root     SOC fleet public key (vetted media)
└── keys/                        0700 root:root     key material, root only
    ├── agentd-blackbox.key      0600 root:root     black-box key of robodr-agentd
    ├── agentd-finding.key       0600 root:root     optional per-finding signing key (drop-in 20-finding-key)
    ├── agentd-cp-tls.key        0600 root:root     optional control-plane TLS server key (drop-in 30-control-plane)
    ├── executor.key             0600 root:root     agentd <-> robodr-executor protocol key (unit + drop-in 30-executor)
    ├── uplink.key               0600 root:root     uplink key (robodr-uplink, fleet API requests; robodr-enroll)
    ├── pulsard-blackbox.key     0600 root:root     (when the Pulsar module records)
    └── retired/                 0700 root:root     rotated keys kept for verification
/var/lib/robodr/                 0750 root:robodr
├── blackbox/                    0750 root:robodr
│   ├── agentd/                  0750 robodr-agentd:robodr single writer: robodr-agentd
│   ├── deliverd/                0750 root:robodr   single writer: robodr-deliverd (delivery evidence, signed highwater.json)
│   └── pulsard/                 0750 root:robodr   single writer: robodr-pulsard
├── spool/                       0750 root:robodr   OCSF findings awaiting export
│   ├── agentd/                  2750 robodr-agentd:robodr  written by agentd (and robodr-deliverd through fds)
│   │   └── ready/ acked/ rejected/  2770 robodr-agentd:robodr  exporters (their own users, group robodr) read and rename here
│   └── pulsard/                 0750 root:robodr
├── control-plane/               0750 root:robodr
│   └── agentd/                  0700 robodr-agentd:robodr control_plane.state_dir: request journal, replay store, evidence exports
├── profile-state/               0750 robodr-agentd:robodr profile anti-rollback state of robodr-agentd
├── profile-state-pulsard/       0750 root:robodr   profile anti-rollback state of the Pulsar sensor
├── commission/                  0750 root:robodr   operator workspace: runs, drafts, sign-offs
├── export/                      0750 root:robodr   bundles staged for the diode / media
│   ├── diode/ spool-export/     0750 robodr-spool:robodr   robodr-spool-export: diode outbox, its state
│   ├── kafka-publish/           0750 robodr-kafka:robodr   robodr-kafka-publish's state
│   └── uplink/                  0750 robodr-uplink:robodr  robodr-uplink's state
├── firewall-gw/                 0750 robodr-gw:robodr      robodr-firewall-gw (StateDirectory=)
├── archive/                     0750 root:robodr   black boxes closed by a key rotation
├── executor/                    0700 robodr-exec:robodr journal of robodr-executor (active actions, TTL deadlines)
├── fleet/                       0700 root:root     robodr-enroll state, staged profile, fleet journal (black box)
├── deliverd/                    0700 root:root     robodr-deliverd: state, trust anchor, content-addressed store, imported packs
├── deliverd-media/              0700 root:root     media packs put here for robodr-deliverd (untrusted)
├── depot/                       0700 robodr-depot:robodr-depot  robodr-depot (depot box only): database, store, deployments, unit CA, depot.lock
├── releases/<version>/          0750 root:root     .deb kept for rollback (install-bundle.sh)
├── releases/security-floor      0644 root:root     lowest release install/rollback may reach (only rises)
├── releases/formats-archive/    0750 root:root     formats files of kept releases pruned by --keep (format gate)
└── pending-restart              0644 root:root     gateway / executor units waiting for a safety-gated restart
/run/robodr-pulsard/pulsar.sock                     Pulsar API socket (RuntimeDirectory)
/run/robodr-executor/executor.sock                  agentd -> robodr-executor (0660 robodr-exec:robodr, dir 0750)
/run/robodr-agentd/                                 agentd's sockets (0751 robodr-agentd:robodr-agentd): status.sock
                                                    (0600, read by robodr-deliverd, SO_PEERCRED), safety.sock (0600, or
                                                    0660 group robodr-safety; SO_PEERCRED), events.sock, host-threats.sock
/run/credentials/<unit>/<name>                      key copies for the service (systemd; robodr-focal:
                                                    robodr-load-credential), 0400, owned by that service's
                                                    own user; units see only their own directory
/usr/share/robodr/rules/{robodr,pulsar}/            Pulsar rules, read-only
/usr/share/robodr/formats                           black-box formats the release writes / reads (install-bundle.sh gate)
/opt/robodr-delivered/<name>/{<serial>-<digest>,current}  delivered files (robodr-deliverd only)
/etc/robodr-delivered/<name>/{<serial>-<digest>,current}  delivered configuration (robodr-deliverd only)
/etc/robodr-delivered-rules/<name>                  link to the active delivered Pulsar rules
/etc/robodr-depot/                0750 root:robodr-depot  depot.json (depot box only)
/etc/robodr-depot/keys/           0700 robodr-depot:robodr-depot  the depot's signing, wrap, lease and unit-CA keys
/run/robodr-depot/                                  TPM session contexts of the depot's anchor (RuntimeDirectory)
```

`tmpfiles.d/robodr.conf` creates every directory and **resets** mode and owner
at each boot, so drift such as a manual `chmod` does not persist. Files inside
`/etc/robodr` are the operator's, and tmpfiles does not touch them.

Why each directory has the owner and mode it has:

- **One writer per black box.** The recorder takes a lock per directory, and
  a hash chain has one head. `agentd/` and `pulsard/` are therefore separate,
  and each service's `ReadWritePaths=` names only its own subdirectory.
- **Group `robodr` can read** state and spool. This lets the export tooling
  and an operator in group `robodr` read evidence without root. It cannot
  modify evidence: only the owner can write. The exporters may write only
  agentd's spool queues (`ready/`, `acked/`, `rejected/`, setgid so
  records keep group `robodr`).
- **agentd is not the exporters' user.** `robodr-agentd` (agentd) and
  `robodr` (the exporters, two of them network-facing) are different
  users, so a compromised exporter cannot write agentd's black box, its
  state, its sockets or the safety state the delivery agent gates on
  (SECURE-DELIVERY §6.3).
- **`/var/lib/robodr/releases` is root-only**. It holds what `dpkg -i` will
  install on a rollback.

## Key material: `/etc/robodr/keys`, `0700 root:root`, files `0600 root:root`

The brief asked whether key files should be `0600 root:robodr` or similar. The
choice here is **root-only files, handed to each service by systemd**
(`LoadCredential=`). The reasons:

1. **Least access.** At start, systemd (PID 1) reads
   `/etc/robodr/keys/agentd-blackbox.key` and places a copy at
   `/run/credentials/robodr-agentd.service/blackbox.key`. The copy is on a
   private, non-swappable ramfs, readable only by that unit's `User=`.
   No other process running as `robodr` gets access, and neither does a
   future second `robodr` service, a debugging shell under `sudo -u robodr`,
   or a compromised tool in group `robodr`. With a group-readable `0640
   root:robodr` file, every one of them could read the key.
2. **The service cannot change or delete its own key.** A compromised agent
   can neither swap the key nor destroy it. Destroying it would make past
   evidence unverifiable (with HMAC, the only copy of the verifying key).
3. **No group membership to manage.** Root-owned files need no group
   membership, which could drift or be granted by mistake.
4. **`InaccessiblePaths=-/etc/robodr/keys`** in both units hides the directory
   even from `robodr-pulsard`, which runs as root.

**systemd < 247** (no `LoadCredential=`: Ubuntu 20.04 and NVIDIA JetPack 5
have 245). The `robodr-focal` units keep the files root-only and use
`/usr/lib/robodr/robodr-load-credential` from `ExecStartPre=+` instead: it
places the same copy at the same `/run/credentials/<unit>/<name>` path
(`0400`, owned by the service user, in a root-owned `0711` directory the
service cannot write) and `ExecStopPost=+` removes it. Points 2 to 4 above
hold; point 1 holds except that the copy is on `/run` (tmpfs, swappable)
rather than a private ramfs. A group-readable `0640 root:robodr` key is
**not** an option: agentd and the blackbox key loader refuse any key file
with a group or other permission bit.

**Ed25519 is the default** (`robodr-blackbox keygen` writes the secret
`FILE`, `0600`, and the public `FILE.pub`). Only the secret goes into
`/etc/robodr/keys/` and through `LoadCredential=`; verifiers (the SOC, the
diode importer, `robodr-replay verify`) get only `FILE.pub` and cannot forge
evidence. **A legacy HMAC-SHA256 key is a shared secret** and still loads,
with a warning: whoever can read it can forge evidence as well as verify it,
so treat every HMAC key copy, on the robot and at the verifier, as forging
capability. Remaining limit: the Ed25519 seed is still a file that root on
the unit can read. A TPM-held, non-exportable key is the planned fix; the
`LoadCredential=` path stays the same, and with a TPM,
`LoadCredentialEncrypted=` can seal the key to the machine.

## Package variants

| Package | Built in | For | Contents |
|---|---|---|---|
| `robodr` `.deb` | Ubuntu 22.04 container (glibc 2.35) | Ubuntu 22.04 / 24.04, JetPack 6, Debian 12 / 13 | everything, `robodr-pulsard` included |
| `robodr` `.rpm` | Rocky Linux 9 container (glibc 2.34) | RHEL / Rocky / Alma 9, Fedora | the same file tree as the `.deb` |
| `robodr-focal` `.deb` | Ubuntu 24.04 runner, static musl | Ubuntu 20.04, JetPack 5 (systemd 245) | no `robodr-pulsard`, no `robodr-anchor-receiver`; systemd 245 units and drop-in examples, `robodr-load-credential` |

`scripts/check-packages.py` holds the list of programs per variant (a new
program fails CI until it is classified) and compares built packages
(docs/BUILD.md "Package matrix"); `scripts/pkg-install-smoke.sh` installs
one in a real userland.

## Building a package locally

```sh
cargo build --release --workspace --locked   # plus Pulsar deps for robodr-pulsard
packaging/build-deb.sh --bin-dir target/release --arch amd64 --out dist
packaging/make-bundle.sh --deb dist/robodr_*_amd64.deb --sbom-dir dist/sbom --out dist

# robodr RPM (on Rocky Linux 9, or any host with rpmbuild for a test build):
packaging/build-rpm.sh --bin-dir target/release --arch amd64 --out dist

# robodr-focal (static, systemd 245; docs/BUILD.md "Static (musl) build"):
rustup target add aarch64-unknown-linux-musl
scripts/build-static.sh aarch64-unknown-linux-musl          # -> dist/static/<triple>
packaging/build-deb.sh --variant focal --bin-dir dist/static/aarch64-unknown-linux-musl --arch arm64 --out dist
# Per-crate (cargo-cyclonedx) SBOMs: keep those of the crates this package
# ships, as release.yml does (no robodr-pulsard for robodr-focal); use a
# separate SBOM directory per package.
python3 scripts/sbom-select.py dist/sbom --package dist/robodr-focal_*_arm64.deb
packaging/make-bundle.sh --deb dist/robodr-focal_*_arm64.deb --sbom-dir dist/sbom --out dist
```

`build-deb.sh` requires `robodr-commission`, `robodr-replay`,
`robodr-ros2-watch` and the operator tools `robodr-setup`,
`robodr-support-bundle` and `robodr-metrics` (pure, built by every
workspace build). It adds every other packaged program if it was built
(`robodr-pulsard`, `robodr-agentd`, `robodr-blackbox`, `robodr-diode-pack`,
`robodr-diode-unpack`, `robodr-spool-export`, `robodr-kafka-publish`,
`robodr-uplink`, `robodr-enroll`, `robodr-executor`, `robodr-firewall-gw`,
`robodr-anchor-receiver`, `robodr-deliverd`, `robodr-seal`, `robodr-depot`; the list per
variant is `PROGRAMS` in `scripts/check-packages.py`), and installs each
unit (and each man page) only together with its binary. Every
`ROBODR_DEB_REQUIRE` in the workflows names all of the variant's
programs (checked by `scripts/check-packages.py`), so neither a release
nor CI can silently ship without one. Both exporters ship with a unit (`robodr-spool-export.service`,
`robodr-kafka-publish.service`, conflicting with each other) for the
robot / sensor-box side; see `docs/OPERATIONS.md` section 8.3.

`--variant focal` builds `robodr-focal` instead: it takes the same binaries
built static (`scripts/build-static.sh`) and **refuses** any binary with a
program interpreter or a shared-library dependency, so its only dependency
is `systemd (>= 245)` (no libc6 at all). It uses the units in
`systemd/focal/`, adds `robodr-load-credential`, and leaves out
`robodr-pulsard` (needs a BTF kernel; JetPack 5 has none) and
`robodr-anchor-receiver` (base station: use `robodr` there). The two
packages `Conflicts:`/`Replaces:` each other; switching is one `dpkg -i`
(checked: dpkg removes the other package; configuration, keys and evidence
stay).
Building twice with the same `SOURCE_DATE_EPOCH` gives an identical `.deb`;
this was checked with stub binaries (`robodr`) and with the real static
binaries (`robodr-focal`, arm64).

## Not verified

- The RPM and the Ubuntu 22.04 / Rocky 9 builds (added 2026-10-30) were
  built and installed locally for **amd64 only** (docs/BUILD.md,
  "Package userlands, local run 2026-10-30"); the arm64 builds, the CI
  jobs and the release workflow have not run. No RPM scriptlet ran under a
  booted systemd (containers: no `systemctl` branch), and none of the
  packages ran on a Jetson.
- External BTF (`robodr-btf-check`, `btf_path`): the check script and the
  unit's assert logic were tested; no BTF file was ever generated for or
  loaded on an L4T kernel.

- `robodr-depot.service` and its focal variant (added 2026-10-30, Sprint
  14a) pass `scripts/check-focal-units.py` and `systemd-analyze verify`
  apart from the missing binary; not started by systemd. The
  depot's tests run `serve` in-process on loopback with software TPMs.
  `/etc/robodr-depot` (0750 root:robodr-depot) and its `keys/` (0700
  robodr-depot) are created by tmpfiles; the keys are read by path, not
  through `LoadCredential=`, because the operator commands load the same
  keys.

- `robodr-deliverd.service` and its focal variant (added 2026-10-26, Sprint
  13b) pass `scripts/check-focal-units.py` and `systemd-analyze verify`
  apart from the missing binary; not started by systemd. Its tests run the
  agent itself on temporary directories, `deb` with the host's dpkg
  against a separate dpkg root.

- No unit has been started on a real kernel. In particular these are
  unverified: the capability set, `SystemCallFilter=`, the read-only `/sys`
  together with Pulsar's "multiple bpf fs mounts" check, and AF_PACKET
  capture under `IPAddressDeny=any`.
- `robodr-agentd`'s flags, config path, key path and directories were
  checked against the merged daemon (the unit's header lists them).
  `config/agentd.example.json` and `config/agentd.full.example.json`
  (installed under `/usr/share/doc/robodr/examples/`) use exactly the
  unit's paths; unit tests in `robodr-agentd` keep them in sync. The base
  example passes `--check-config` as copied on a commissioned robot; the
  full one also needs the trust-root and revocation files and the
  finding-signing key with its drop-in (`20-finding-key.conf.example`). The daemon itself has not
  run under this unit on a real host (see the first point).
- `install-bundle.sh install` and `rollback` have not been run against `dpkg`
  on a robot. In a Ubuntu 24.04 container (not booted with systemd) they
  were: `install` of a `robodr-focal` bundle, then of a `robodr` bundle
  (dpkg removed `robodr-focal` in favour of `robodr`), then `rollback`.
- `robodr-executor.service` (executor v1, the only `CAP_NET_ADMIN` unit on the robot
  besides the sensor box's inline gateway) and
  its focal variant (added 2026-10-26) pass `systemd-analyze verify` apart
  from the missing binaries in the check environment and score 1.1 / 1.3
  with `systemd-analyze security --offline=yes` (systemd 255); not started
  by systemd: its syscall filter has not been exercised with `nft` under
  systemd.
- `robodr-uplink.service` and its focal variant (added 2026-10-26) pass
  `systemd-analyze verify` apart from the missing binary in the check
  environment, and score 1.1 / 1.2 with `systemd-analyze security
  --offline=yes` (systemd 255); not started by systemd, not checked from an
  installed package.
- The exporter units (`robodr-spool-export`, `robodr-kafka-publish`) and the
  `robodr-focal` units pass `systemd-analyze verify` (systemd 255, installed
  package, no warnings). `systemd-analyze security --offline=yes`
  (systemd 255; lower is better): spool-export 0.4, kafka-publish 1.1,
  agentd 1.5; their focal variants 0.5, 1.2 and 1.6 (no `ProtectProc=` /
  `ProcSubset=`). None has
  been started by systemd. The `robodr-focal` start sequence was simulated
  without systemd as root: `robodr-load-credential load`, then the static
  `robodr-agentd` (`--check-config`, a 5 s run on `lo`, black box verified
  intact) and `robodr-spool-export --once` as user `robodr` with the copied
  keys, then `clear`. systemd 245 itself was not available: its handling of
  these units (the `+` prefix, `@system-service` of 245, cgroup v1) is
  unverified, and so is `robodr-kafka-publish` against a broker from the
  unit (the binary is covered by `scripts/kafka-it.sh`).
