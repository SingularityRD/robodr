# DDS transports, shared memory and SROS 2: what RoboDR can see

RoboDR's ROS 2 sensor inspects DDS (RTPS) traffic **on the wire**: the
passive capture (`AF_PACKET`) and the SPDP socket. Whatever the robot's DDS
stack sends another way is not inspected. This page says which transports
that is, how RoboDR reports it, and what to configure on the robot before
commissioning. Evidence: real captures in
[`fixtures/captures/ros2-humble/`](../fixtures/captures/ros2-humble/README.md)
and [`fixtures/captures/ros2-jazzy/`](../fixtures/captures/ros2-jazzy/README.md).

## 1. Shared-memory transports

| Stack | Shared memory | Default |
|---|---|---|
| Fast DDS 2.x (`rmw_fastrtps_cpp`; ROS 2 Humble, Jazzy) | SHM transport, and data sharing | **on**: participants on the same host exchange discovery and data over `/dev/shm` |
| Cyclone DDS 0.10 (`rmw_cyclonedds_cpp`) | iceoryx (`<SharedMemory><Enable>`) | off |
| RTI Connext | SHMEM | on for same-host peers |

Traffic between two processes on the **same host** over shared memory never
reaches a network interface, not even loopback. A same-host process that
publishes `/cmd_vel` to the robot's controller over shared memory is
invisible to the sensor: no participant check, no motion envelope. On the
Humble lab capture `fastrtps_shm_default.pcap` a local planner does exactly
that and none of its commands is on the wire.

### What RoboDR reports

- `robot.capture.unsupported_transport` (Medium), once per host: a
  participant's SPDP advertises shared-memory locators (Fast DDS / Cyclone
  kind 16, Connext `0x01000000`), or TCP / unknown locator kinds (RTPS over
  TCP is not decoded either). The detail names the host and the transports.
  Every Fast DDS participant with default transports raises it.
- `robodr-ros2-watch --check-config /etc/robodr/pulsar.toml` warns when
  `/dev/shm` of the host it runs on holds DDS segments (`fastrtps_port<N>`,
  `fastrtps_<hex>`, `fast_datasharing_*`, `iceoryx_mgmt`, `iox_*`): run it
  on the robot. Nothing in the configuration tells it which host is the
  robot: on a developer workstation running ROS the same warning appears
  (and fails `--strict`). When none are found, or `/dev/shm` cannot be
  listed, it prints a `note:` summary line instead. With the passive
  capture enabled it also prints a `note:` summary line that shared-memory
  transports are invisible (not a warning, so `--strict` can pass).
- `robodr-commission learn --pcap` warns `unsupported_transport` once per
  source host whose SPDP advertises such locators: what went over them is
  not in the capture, so it is not in the profile either. Learning from
  sensor events (JSON lines) has no locator kinds, so no such warning.
- The running daemon does not list `/dev/shm`: on the robot only the SPDP
  finding above reports shared memory.

### Commissioning prerequisite: UDP only

Configure every DDS process on the robot (and the operator stations) for
UDP before the capture you commission from, and keep it so:

**Fast DDS on ROS 2 Jazzy and later (Fast DDS ≥ 2.13):**

```sh
export FASTDDS_BUILTIN_TRANSPORTS=UDPv4
```

**Fast DDS on ROS 2 Humble (Fast DDS 2.6; the variable above is ignored):**
an XML profile with the builtin transports off and one UDPv4 transport, for
example [`tools/lab-capture/fastdds_udp_only.xml`](../tools/lab-capture/fastdds_udp_only.xml):

```sh
export FASTRTPS_DEFAULT_PROFILES_FILE=/etc/robodr/fastdds_udp_only.xml
```

If the robot already uses a profiles file, add the transport descriptor and
`<useBuiltinTransports>false</useBuiltinTransports>` to its default
participant profile instead. Check on a running robot that
`ls /dev/shm | grep fastrtps` is empty and that
`robot.capture.unsupported_transport` is no longer raised.

**Cyclone DDS:** leave `SharedMemory` disabled (the default); if the robot's
`CYCLONEDDS_URI` enables it, set `<SharedMemory><Enable>false</Enable></SharedMemory>`.

**Connext:** restrict the participant's builtin transports to UDPv4 (QoS
`<transport_builtin><mask>UDPv4</mask></transport_builtin>`). Connext is not
validated (support matrix V0).

Cost: same-host traffic then goes over loopback UDP, with more CPU and
latency for large messages (camera images, point clouds). If that is not
acceptable, the processes that must keep shared memory are outside what
RoboDR inspects: say so in the POC qualification and the deployment record.

## 2. RTPS over TCP

Fast DDS TCP transports and Connext TCP/TLS are not decoded. TCP locators in
SPDP raise `robot.capture.unsupported_transport` like shared memory.

## 3. SROS 2 (DDS-Security)

What stays visible depends on the governance:

| Governance (sros2 default in **bold**) | Visible to RoboDR |
|---|---|
| `discovery_protection_kind` / topic `enable_discovery_protection` / `metadata_protection_kind` **ENCRYPT** | participants (SPDP) and their claimed certificate subjects only: **no topic, no endpoint, no motion sample** |
| `data_protection_kind` **ENCRYPT**, discovery in clear | topics and endpoints; motion samples are not decoded |
| `rtps_protection_kind` **SIGN** / ENCRYPT | the announcements before authentication |

With the sros2 defaults, `robodr-commission learn` finds the participants and
nothing else (warning `protected_discovery`), and the writer and
motion-envelope checks have nothing to work on: topic access control is the
DDS stack's own (the permissions). RoboDR still sees who is on the domain.

`robodr-ros2-watch --check-config` with `sros2_keystore` set states this
(and the other rows of the table) as `note:` summary lines, **not as
warnings**: it is what a correctly secured deployment looks like, so
`--strict` passes on it. Read the notes: under discovery protection the
writer and motion-envelope checks inspect nothing, and `--strict` does not
flag that loss of coverage.

### Policy input: `sros2_keystore`

Point the sensor at the robot's keystore `enclaves/` directory (only
`governance.xml` and the `permissions.xml` files are read, never a key; a
copy of those files is enough):

```toml
[module.robodr-sensor-ros2]
sros2_keystore = "/etc/robodr/sros2/enclaves"
```

The governance rule used is the first `domain_rule` whose `<domains>`
covers the sensor's `domain_id`, as the DDS stack chooses it. If none covers
it, all rules are combined (most protective) and check-config warns.

Then:

- a participant whose **certificate subject no grant names** is
  `robot.ros2.untrusted_security_identity` (High): a participant from
  another keystore or CA;
- a participant without a **complete identity token** (class
  `DDS:Auth:PKI-DH` with a certificate subject) on a domain whose governance
  refuses unauthenticated participants is
  `robot.ros2.untrusted_security_identity` (Medium): the robot will not talk
  to it, but it is on the robot's network. This covers no DDS-Security
  parameter at all and partial claims (only `PID_PARTICIPANT_SECURITY_INFO`,
  only a permissions token, an identity token without a subject), which any
  sender can add to its announcement;
- `robodr-ros2-watch --check-config` lists the grants with the `rt/` topics
  each may publish (profile input for the operator) and prints what the
  governance leaves visible as `note:` summary lines.

A missing or unreadable keystore, or one without any grant, is a
configuration error like any other invalid value: the **whole sensor
module** does not start, so all DDS monitoring stops, not only the SROS 2
check. Moving or rotating the keystore therefore needs the same care as
the profile: update the files (or `sros2_keystore`), run
`robodr-ros2-watch --check-config`, then restart.

### Limits

- The subject in SPDP is a **claim**: a participant can announce a granted
  subject without its private key. The robot's DDS stack then refuses the
  authentication handshake; the sensor does not see that yet. On the lab
  capture a rogue with a certificate from a foreign keystore, for the same
  enclave name and the same default CA name (`sros2CA`), is only caught as
  an unknown participant by its address. Checking the certificate presented
  in the handshake against the keystore is planned.
- Identities of secured participants are bound by address and by the
  subject hash in their GUID prefix (`robodr-ros2-pipeline::identity`), not
  by node names (those are in the encrypted discovery). The hash is used
  only when the SPDP's PKI-DH identity token claims the subject the prefix
  is derived from (DDS-Security §9.3.3: SHA-256 of the subject's DER, which
  the sensor rebuilds from the claimed text). Subject and prefix are both
  claims: a crafted announcement can claim the subject and use its prefix,
  as it can claim any vendor id; it still has to come from one of the
  identity's addresses and find a free `max_instances` slot.
- Subject forms the sensor can rebuild (`robodr_rtps::secured_prefix`):
  the OpenSSL one-line form (`/CN=\/lab\/x`, what Fast DDS 2.6 sends) and
  the RFC 4514 form (`CN=/lab/x`), with attribute types by name (`CN`,
  `O`, `OU`, `C`, `L`, `ST`, `street`, `serialNumber`, `title`, `SN`,
  `GN`, `initials`, `postalCode`, `dnQualifier`, `pseudonym`,
  `emailAddress`, `DC`, `UID`) or as numeric OIDs, values as UTF8String or
  PrintableString (the type is not in the text, both are tried), and in
  the RFC 4514 form also multi-valued RDNs (`CN=a+UID=b`), `#hex` values
  of any string type and escaped spaces. Not rebuilt: multi-valued RDNs
  and values containing `/x=` in the one-line form, T61String / BMPString
  values not given as `#hex`, other attribute names. A secured participant
  whose subject is not rebuilt never resolves to its learned identity and
  is reported as an unknown participant (a false positive, not a missed
  detection); `robodr-commission learn --pcap` warns
  `identity_prefix_unverified` for it at commissioning. The default SROS 2
  subjects (`CN=<enclave>`) are rebuilt; Cyclone DDS's `dds.cert.sn` format
  has not been captured.
- Validated on Fast DDS 2.6 (Humble) only; Cyclone DDS with DDS-Security
  has not been captured.

## 4. Zenoh

`rmw_zenoh_cpp` carries no RTPS at all: detected and reported
(`robot.capture.unsupported_middleware`), never decoded.
