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
- `robodr-ros2-watch --check-config /etc/robodr/pulsar.toml` (on the robot)
  warns when `/dev/shm` holds DDS segments (`fastrtps_port<N>`,
  `fastrtps_<hex>`, `fast_datasharing_*`, `iceoryx_mgmt`, `iox_*`) and when
  the passive capture is enabled at all.

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

### Policy input: `sros2_keystore`

Point the sensor at the robot's keystore `enclaves/` directory (only
`governance.xml` and the `permissions.xml` files are read, never a key; a
copy of those files is enough):

```toml
[module.robodr-sensor-ros2]
sros2_keystore = "/etc/robodr/sros2/enclaves"
```

Then:

- a participant that announces **no DDS-Security identity** on a domain
  whose governance refuses unauthenticated participants is
  `robot.ros2.untrusted_security_identity` (Medium): the robot will not talk
  to it, but it is on the robot's network;
- a participant whose **certificate subject no grant names** is
  `robot.ros2.untrusted_security_identity` (High): a participant from
  another keystore or CA;
- `robodr-ros2-watch --check-config` lists the grants with the `rt/` topics
  each may publish (profile input for the operator) and states what the
  governance leaves visible.

A missing or unreadable keystore is a configuration error (the module does
not start), like any other invalid value.

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
  by node names (those are in the encrypted discovery).
- Validated on Fast DDS 2.6 (Humble) only; Cyclone DDS with DDS-Security
  has not been captured.

## 4. Zenoh

`rmw_zenoh_cpp` carries no RTPS at all: detected and reported
(`robot.capture.unsupported_middleware`), never decoded.
