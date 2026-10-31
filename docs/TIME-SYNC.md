# Time synchronisation baseline for RoboDR robots

Status: baseline for commissioning (sales-readiness T7, GAP-09). What
RoboDR checks is in the code and tested; what the site configures is its
own responsibility and is listed here as a checklist.

## Why the clock matters

RoboDR measures every duration (rate limits, escalation windows, motion
latency, staleness of the safety state) on the **monotonic** clock, so a
wrong or stepped wall clock cannot shorten a window or unlock an action.
The **wall** clock still matters for evidence and triage:

* finding times (`timestamp`, `first_seen_time`, `last_seen_time`) and
  black-box record times are wall-clock times;
* certificate and CRL validity (control plane mutual TLS, uplink, Kafka)
  is judged on the wall clock: a clock set far into the future makes valid
  CRLs look expired (every SOC client refused), one set into the past can
  make an expired certificate look valid;
* SOC request freshness (`max_clock_skew_s`, default 30 s) compares the
  SOC's signing time with the robot's wall clock.

## What RoboDR checks (findings contract 2.5)

| Check | Finding | Where |
|---|---|---|
| Kernel reports the clock unsynchronised (`adjtimex(2)`: `TIME_ERROR` / `STA_UNSYNC`) for `daemon.self_health.clock_unsynced_grace_ms` (default 5 min) | `robot.agent.clock_unsynced` (Medium), once per episode | `robodr-agentd` |
| Wall clock jumps against the monotonic clock (more than 1 s between two observations) | `robot.agent.clock_jump` (High), plus a signed `robodr.agent_fault` note per jump in the black box | `robodr-agentd` (agent time guard) |
| Current state | `status.json` `self_health.clock` and the `robot.agent.health` record: `synchronized`, `max_error_ms`, `source`, `adjtimex_errno`, `timesync_age_ms`, `wall_jumps` | `robodr-agentd` |

`adjtimex` is called read-only (`modes = 0`); no capability is needed,
but a seccomp filter can still refuse the call. **The shipped
`robodr-agentd.service` refuses it**: `ProtectClock=yes` and
`SystemCallFilter=~… @clock` deny `adjtimex` / `clock_adjtime` with
`EPERM` whatever their arguments. Under that unit:

* `robot.agent.clock_unsynced` is never raised (the kernel's view is not
  known);
* `self_health.clock.adjtimex_errno` is `1` (`EPERM`) in `status.json`
  and in every health record, so the gap is visible rather than silent;
* if systemd-timesyncd is the robot's time service, its marker file
  `/run/systemd/timesync/synchronized` (touched on each synchronisation)
  is used instead: touched within the last 4 096 s (twice timesyncd's
  default longest poll interval) gives `synchronized: true`, `source:
  "timesyncd"`, no `max_error_ms`. An older or missing marker gives no
  `synchronized` at all (`timesync_age_ms` shows the age): it is not taken
  as proof that the clock is unsynchronised;
* with chrony (recommended below) there is no such marker, and agentd
  does not query chrony (the unit's `IPAddressDeny=any` blocks its UDP
  command port anyway), so the clock state is unknown: check it at
  commissioning with `chronyc tracking` (step 5).

`clock_jump` comes from agentd's own time guard and works under the unit.
Letting agentd read `adjtimex` would need `ProtectClock=no` and `@clock`
removed from the unit's filter (the capability bounding set, `CAP_NET_RAW`
only, would still stop it from setting the clock); that is a packaging
decision the unit's owner has not taken. These findings are observe-only: a clock
problem never causes a response by itself.

Not yet done (tracked in `docs/SALES-READINESS.md`, T7): refusing to
record when the wall clock is behind the black box's newest record time
(the black box's own time-regression guard).

## Site checklist

1. **One time source per site, authenticated.** Run `chrony` on every
   robot controller, pointed at the site's time servers, with **NTS**
   (Network Time Security, RFC 8915) where the servers support it:

   ```text
   # /etc/chrony/chrony.conf (excerpt)
   server time1.site.example iburst nts
   server time2.site.example iburst nts
   ntsdumpdir /var/lib/chrony
   # Step only at boot, slew afterwards: a step while running is reported
   # as robot.agent.clock_jump.
   makestep 1.0 3
   # Refuse servers that disagree wildly (a spoofed source).
   maxdistance 1.0
   rtcsync
   ```

   Without NTS, restrict NTP to the site's management network and to the
   named servers (no pool, no broadcast client).
2. **Air-gapped sites.** Use a local stratum-1 source (GNSS receiver or a
   PTP grandmaster) on the management network; never let a robot take
   time from the robot data bus. A GNSS source can be spoofed: put it
   inside the site's physical perimeter and monitor it.
3. **PTP (IEEE 1588) robots.** Where the robot's controllers already run
   `ptp4l` / `phc2sys` (motion controllers with hardware timestamping),
   synchronise the system clock from the PHC (`phc2sys -s <iface> -w`) and
   let chrony use it as a reference clock (`refclock PHC /dev/ptp0 poll 0
   dpoll -2 offset 0`) so that `adjtimex` reports the clock synchronised.
   Use PTP profiles with authentication (IEEE 1588-2019 Annex P) where
   the equipment supports it.
4. **RTC.** Keep the hardware clock in UTC (`timedatectl set-local-rtc 0`)
   and `rtcsync` on, so a cold boot starts near the right time and the
   first `makestep` is small.
5. **Acceptance.** After commissioning: `chronyc tracking` shows
   `Leap status: Normal` (with chrony this is the only check of the sync
   state under the shipped unit), and no `robot.agent.clock_*` finding
   reached the SOC during the acceptance run. In `status.json`,
   `self_health.clock` shows either `synchronized: true` with `source:
   "adjtimex"` and a small `max_error_ms` (agentd run without the unit's
   `@clock` filter), `synchronized: true` with `source: "timesyncd"`
   (systemd-timesyncd), or no `synchronized` and `adjtimex_errno: 1`
   (shipped unit with chrony: the state is not visible to agentd; record
   that in the acceptance report).
6. **Certificates.** Renew control-plane certificates and CRLs before
   `robot.agent.credential_expiring` turns High (3 days by default); on an
   air-gapped site bring the fresh CRL in with the regular update media
   well before its `nextUpdate`. The HTTPS uplink's CRLs (`--crl-file`)
   are not seen by agentd: `uplink-status.json` lists them under
   `credentials` and `robodr-uplink` logs each one from 14 days before its
   `nextUpdate`. The Kafka publisher, enrolment and head-anchor clients
   do not report CRL expiry yet.
