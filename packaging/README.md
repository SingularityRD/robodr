# RoboDR packaging

This directory holds everything that turns the workspace into something an
operator installs on a robot. The procedures that use it are in
[`docs/OPERATIONS.md`](../docs/OPERATIONS.md).

| Path | Installed as | Purpose |
|---|---|---|
| `systemd/robodr-pulsard.service` | `/usr/lib/systemd/system/` | eBPF + ROS 2 sensor daemon |
| `systemd/robodr-agentd.service` | `/usr/lib/systemd/system/` | decision chain, black box, OCSF spool (only if the binary is built) |
| `systemd/robodr-agentd.service.d/20-finding-key.conf.example` | `/usr/share/doc/robodr/examples/` | optional drop-in: `LoadCredential=` for the per-finding signing key (OPERATIONS 6.4) |
| `systemd/robodr-agentd.service.d/40-sensor-box.conf.example` | `/usr/share/doc/robodr/examples/` | **sensor box only**: passive tap / port-mirror mode of `robodr-agentd` (`CAP_NET_RAW` only, all IP denied, waits for the writable data mount; [`docs/UNITREE.md`](../docs/UNITREE.md)) |
| `sensor-box/10-robodr-capture.network.example` | `/usr/share/doc/robodr/examples/sensor-box/` | **sensor box only**: systemd-networkd file for the capture NIC (no address, no ARP, no IPv6 link-local, promiscuous) |
| `sensor-box/nftables.conf.example` | `/usr/share/doc/robodr/examples/sensor-box/` | **sensor box only**: host firewall (capture NIC silent, uplink to the Kafka broker set, NTP and admin SSH only, no forwarding) |
| `systemd/robodr-spool-export.service` | `/usr/lib/systemd/system/` | robot-side findings exporter for **diode sites**: agentd spool -> signed batches in `/var/lib/robodr/export/diode`; `User=robodr`, `PrivateNetwork=yes`, key via `LoadCredential=` (`/etc/robodr/keys/diode.key`), settings in `/etc/robodr/spool-export.env` (only if the binary is built) |
| `systemd/robodr-kafka-publish.service` | `/usr/lib/systemd/system/` | findings publisher for **connected sites**, running on the unit or sensor box: agentd spool -> Kafka; `User=robodr`, `IPAddressDeny=any` plus the broker drop-in, settings in `/etc/robodr/kafka-publish.env`. Conflicts with the exporter above (only if the binary is built) |
| `systemd/robodr-kafka-publish.service.d/50-brokers.conf.example` | `/usr/share/doc/robodr/examples/` | `IPAddressAllow=` for **every** Kafka broker (the publisher connects to each partition leader, not only to the bootstrap broker) |
| `systemd/robodr-uplink.service` | `/usr/lib/systemd/system/` | findings uplink to the SOC's AutoSecOps ingest API for **connected sites**, running on the unit or sensor box: agentd spool -> HTTPS (signed batches, CA bundle `/etc/robodr/uplink-ca.pem`, optional SPKI pin); `User=robodr`, key via `LoadCredential=` (`/etc/robodr/keys/uplink.key`), `IPAddressDeny=any` plus the SOC drop-in, settings in `/etc/robodr/uplink.env`. Conflicts with both units above (only if the binary is built) |
| `systemd/robodr-uplink.service.d/50-soc.conf.example` | `/usr/share/doc/robodr/examples/` | `IPAddressAllow=` for the SOC ingest address(es) (map the URL's host name in `/etc/hosts`: DNS is not reachable) |
| `etc/spool-export.env.example`, `etc/kafka-publish.env.example`, `etc/uplink.env.example` | `/usr/share/doc/robodr/examples/` | the three exporter units' site settings (unit id; bootstrap brokers; ingest URL and pin) |
| `systemd/focal/*.service`, `systemd/focal/robodr-agentd.service.d/20-finding-key.conf.example` | `/usr/lib/systemd/system/` (and examples) of **`robodr-focal`** | systemd 245 variants (Ubuntu 20.04 / JetPack 5): `LoadCredential=` replaced by `robodr-load-credential`, no `ProtectProc=` / `ProcSubset=`; otherwise identical, enforced by `scripts/check-focal-units.py` |
| `focal/robodr-load-credential` | `/usr/lib/robodr/` of **`robodr-focal`** | POSIX sh helper run as root (`ExecStartPre=+`): copies a root-only key to `/run/credentials/<unit>/<name>`, `0400` owned by the service user, in a root-owned `0711` directory; `clear` on stop |
| `systemd/robodr-anchor-receiver.service` | `/usr/lib/systemd/system/` | **base station only**: remote head-anchor receiver (only if the binary is built; OPERATIONS 6.4, "Remote anchor"). Not yet checked with `systemd-analyze` |
| `systemd/robodr-pulsard.service.d/10-cap-sys-admin.conf.example` | `/usr/share/doc/robodr/examples/` | opt-in for kernels < 5.8 |
| `systemd/robodr-pulsard.service.d/30-host-threats.conf.example` | `/usr/share/doc/robodr/examples/` | optional drop-in: `SupplementaryGroups=robodr` so `robodr-threat-forward` can reach agentd's `0660` host-threat socket (OPERATIONS 6.4) |
| `tmpfiles.d/robodr.conf` | `/usr/lib/tmpfiles.d/` | directories, modes, owners |
| `sysusers.d/robodr.conf` | `/usr/lib/sysusers.d/` | the `robodr` system user |
| `etc/pulsar.base.toml` | header of `/etc/robodr/pulsar.toml` | daemon config (conffile) |
| `deb/` | `DEBIAN/` | control template, maintainer scripts |
| `build-deb.sh` | (build time) | reproducible `.deb` from built binaries: `robodr` (default) or `robodr-focal` (`--variant focal`, static binaries only) |
| `make-bundle.sh` | (build time) | offline install bundle |
| `install-bundle.sh` | inside the bundle | verify, install, list, roll back on the robot |

The units, tmpfiles and sysusers fragments were checked with
`systemd-analyze verify`, `systemd-analyze security --offline`,
`systemd-sysusers --root` and `systemd-tmpfiles --root` (systemd 255).
`systemd-analyze security` exposure is 3.0 for `robodr-pulsard` and 1.5 for
`robodr-agentd` (lower is better). None of them has run on a robot yet. See "Not verified" at the end.

## Services and what is not a service

| Program | How it runs | Why |
|---|---|---|
| `robodr-pulsard` | systemd service, root with a bounded capability set | Pulsar requires euid 0 and loads eBPF |
| `robodr-agentd` | systemd service, user `robodr`, `CAP_NET_RAW` only | long-running decision chain; needs nothing else |
| `robodr-commission` | **not a service**: run by an operator, as needed | commissioning is a deliberate, human-reviewed act (learn, sign off, lock). A timer or unit that re-learns a profile automatically would let an attacker who is present during learning become "normal". |
| `robodr-replay`, `robodr-ros2-watch` | operator tools | offline analysis and lab replay |
| `robodr-anchor-receiver` | systemd service on a **base station**, dynamic user, no capabilities; never enabled on a robot | holds the robots' black-box head marks off the robots |
| `robodr-spool-export` | systemd service (`User=robodr`, no network, no capabilities) on the **unit or sensor box** of a diode site | loops on agentd's spool and writes signed diode batches; the transfer to the diode is the site's procedure |
| `robodr-kafka-publish` | systemd service (`User=robodr`, brokers only) on the **unit or sensor box** of a connected site; on a diode site it runs on the **SOC (high) side** after `robodr-diode-unpack`, from the SOC's own unit or procedure (`--diode-out`) | publishes findings to Kafka; one consumer per spool, so it conflicts with `robodr-spool-export` and `robodr-uplink` |
| `robodr-uplink` | systemd service (`User=robodr`, SOC address only) on the **unit or sensor box** of a connected site; on a diode site it runs on the **SOC (high) side** after `robodr-diode-unpack` (`--diode-out`, a `relay` key), from the SOC's own unit or procedure | sends findings to the AutoSecOps ingest API over TLS; one consumer per spool, so it conflicts with the two units above |

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
`Restart=on-failure` with a start limit (5 starts in 300 s) covers crashes.
Neither watchdog has been exercised under a real systemd yet.

## Filesystem layout

```
/etc/robodr/                     0750 root:robodr   configuration (read-only to services)
├── pulsar.toml                  0640 root:root     robodr-pulsard config (dpkg conffile)
├── agentd.json                  0640 root:robodr   robodr-agentd config (operator-created)
├── profile.json                 0640 root:robodr   LOCKED model profile (from robodr-commission)
├── response-policy.json         0640 root:robodr   response policy (operator-created)
└── keys/                        0700 root:root     key material, root only
    ├── agentd-blackbox.key      0600 root:root     black-box key of robodr-agentd
    ├── agentd-finding.key       0600 root:root     optional per-finding signing key (drop-in 20-finding-key)
    ├── pulsard-blackbox.key     0600 root:root     (when the Pulsar module records)
    └── retired/                 0700 root:root     rotated keys kept for verification
/var/lib/robodr/                 0750 root:robodr
├── blackbox/                    0750 root:robodr
│   ├── agentd/                  0750 robodr:robodr single writer: robodr-agentd
│   └── pulsard/                 0750 root:robodr   single writer: robodr-pulsard
├── spool/                       0750 root:robodr   OCSF findings awaiting export
│   ├── agentd/                  0750 robodr:robodr
│   └── pulsard/                 0750 root:robodr
├── profile-state/               0750 robodr:robodr profile anti-rollback state of robodr-agentd
├── profile-state-pulsard/       0750 root:robodr   profile anti-rollback state of the Pulsar sensor
├── commission/                  0750 root:robodr   operator workspace: runs, drafts, sign-offs
├── export/                      0750 root:robodr   bundles staged for the diode / media
├── archive/                     0750 root:robodr   black boxes closed by a key rotation
└── releases/<version>/          0750 root:root     .deb kept for rollback (install-bundle.sh)
/run/robodr-pulsard/pulsar.sock                     Pulsar API socket (RuntimeDirectory)
/run/credentials/<unit>/blackbox.key                key copy for the service (systemd)
/usr/share/robodr/rules/{robodr,pulsar}/            Pulsar rules, read-only
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
  modify evidence: only the owner can write.
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

## Building a package locally

```sh
cargo build --release --workspace --locked   # plus Pulsar deps for robodr-pulsard
packaging/build-deb.sh --bin-dir target/release --arch amd64 --out dist
packaging/make-bundle.sh --deb dist/robodr_*_amd64.deb --sbom-dir dist/sbom --out dist

# robodr-focal (static, systemd 245; docs/BUILD.md "Static (musl) build"):
rustup target add aarch64-unknown-linux-musl
scripts/build-static.sh aarch64-unknown-linux-musl          # -> dist/static/<triple>
packaging/build-deb.sh --variant focal --bin-dir dist/static/aarch64-unknown-linux-musl --arch arm64 --out dist
packaging/make-bundle.sh --deb dist/robodr-focal_*_arm64.deb --sbom-dir dist/sbom --out dist
```

`build-deb.sh` requires `robodr-commission`, `robodr-replay` and
`robodr-ros2-watch`. It adds `robodr-pulsard`, `robodr-agentd`,
`robodr-blackbox`, `robodr-diode-pack`, `robodr-diode-unpack`,
`robodr-spool-export` (robot side of a diode site: agentd spool -> diode
outbox) and `robodr-kafka-publish` (on the unit or sensor box of a connected
site from agentd's spool, or on the SOC side of a diode site from the
importer's output) if they were built, and installs each unit (and each man
page) only together with its binary. The release workflow sets
`ROBODR_DEB_REQUIRE` to all seven, so a release cannot silently ship without
them. Both exporters ship with a unit (`robodr-spool-export.service`,
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
