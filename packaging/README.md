# RoboDR packaging

This directory holds everything that turns the workspace into something an
operator installs on a robot. The procedures that use it are in
[`docs/OPERATIONS.md`](../docs/OPERATIONS.md).

| Path | Installed as | Purpose |
|---|---|---|
| `systemd/robodr-pulsard.service` | `/usr/lib/systemd/system/` | eBPF + ROS 2 sensor daemon |
| `systemd/robodr-agentd.service` | `/usr/lib/systemd/system/` | decision chain, black box, OCSF spool (only if the binary is built) |
| `systemd/robodr-pulsard.service.d/10-cap-sys-admin.conf.example` | `/usr/share/doc/robodr/examples/` | opt-in for kernels < 5.8 |
| `tmpfiles.d/robodr.conf` | `/usr/lib/tmpfiles.d/` | directories, modes, owners |
| `sysusers.d/robodr.conf` | `/usr/lib/sysusers.d/` | the `robodr` system user |
| `etc/pulsar.base.toml` | header of `/etc/robodr/pulsar.toml` | daemon config (conffile) |
| `deb/` | `DEBIAN/` | control template, maintainer scripts |
| `build-deb.sh` | (build time) | reproducible `.deb` from built binaries |
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

Both services are installed **disabled**. A robot is commissioned first and its
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

`WatchdogSec=` is not set, because neither daemon calls `sd_notify()` yet. With
a watchdog set, systemd would kill a healthy daemon. `Restart=on-failure` with
a start limit (5 starts in 300 s) covers crashes in the meantime. Follow-up:
send `READY=1` and `WATCHDOG=1`, then switch to `Type=notify` and
`WatchdogSec=30s`.

## Filesystem layout

```
/etc/robodr/                     0750 root:robodr   configuration (read-only to services)
├── pulsar.toml                  0640 root:root     robodr-pulsard config (dpkg conffile)
├── agentd.json                  0640 root:robodr   robodr-agentd config (operator-created)
├── profile.json                 0640 root:robodr   LOCKED model profile (from robodr-commission)
├── response-policy.json         0640 root:robodr   response policy (operator-created)
└── keys/                        0700 root:root     key material, root only
    ├── agentd-blackbox.key      0600 root:root     black-box key of robodr-agentd
    ├── pulsard-blackbox.key     0600 root:root     (when the Pulsar module records)
    └── retired/                 0700 root:root     rotated keys kept for verification
/var/lib/robodr/                 0750 root:robodr
├── blackbox/                    0750 root:robodr
│   ├── agentd/                  0750 robodr:robodr single writer: robodr-agentd
│   └── pulsard/                 0750 root:robodr   single writer: robodr-pulsard
├── spool/                       0750 root:robodr   OCSF findings awaiting export
│   ├── agentd/                  0750 robodr:robodr
│   └── pulsard/                 0750 root:robodr
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
   evidence unverifiable while HMAC is in use.
3. **No group membership to manage.** Root-owned files need no group
   membership, which could drift or be granted by mistake.
4. **`InaccessiblePaths=-/etc/robodr/keys`** in both units hides the directory
   even from `robodr-pulsard`, which runs as root.

Fallback for systemd < 247 (no `LoadCredential=`; Ubuntu 22.04 has 249 and
24.04 has 255, so this should not arise): `0640 root:robodr`, and accept
point 1 above.

**While HMAC-SHA256 is the authenticator, the key is a shared secret.** Whoever
can read it can forge evidence as well as verify it. Treat each key copy, on
the robot and at the verifier, as forging capability. The planned move to
Ed25519 or a TPM-held ECDSA key (`crates/robodr-blackbox/README.md`) removes
this: the unit will hold a non-exportable signing key, and verifiers will need
only the public half. The `LoadCredential=` path stays the same, and with a
TPM, `LoadCredentialEncrypted=` can seal the key to the machine.

## Building a package locally

```sh
cargo build --release --workspace --locked   # plus Pulsar deps for robodr-pulsard
packaging/build-deb.sh --bin-dir target/release --arch amd64 --out dist
packaging/make-bundle.sh --deb dist/robodr_*_amd64.deb --sbom-dir dist/sbom --out dist
```

`build-deb.sh` requires `robodr-commission`, `robodr-replay` and
`robodr-ros2-watch`. It adds `robodr-pulsard`, `robodr-agentd`,
`robodr-blackbox`, `robodr-diode-pack` and `robodr-diode-unpack` if they were
built, and installs each unit (and each man page) only together with its
binary. The release workflow sets `ROBODR_DEB_REQUIRE` to all five, so a
release cannot silently ship without them.
Building twice with the same `SOURCE_DATE_EPOCH` gives an identical `.deb`;
this was checked with stub binaries.

## Not verified

- No unit has been started on a real kernel. In particular these are
  unverified: the capability set, `SystemCallFilter=`, the read-only `/sys`
  together with Pulsar's "multiple bpf fs mounts" check, and AF_PACKET
  capture under `IPAddressDeny=any`.
- `robodr-agentd`'s flags, config path, key path and directories were
  checked against the merged daemon (the unit's header lists them).
  `config/agentd.example.json` (installed under
  `/usr/share/doc/robodr/examples/`) uses exactly the unit's paths; a unit
  test in `robodr-agentd` keeps the two in sync. The daemon itself has not
  run under this unit on a real host (see the first point).
- `install-bundle.sh install` and `rollback` have not been run against `dpkg`
  on a target. Only `verify` and the bundle round-trip were exercised.
