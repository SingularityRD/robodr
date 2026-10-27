#!/usr/bin/env python3
"""Real-rate pcap replayer onto an interface (AF_PACKET), looping.

usage: replay.py IFACE --base PCAP [--inject PCAP --every SECONDS] [--log FILE]
                 [--duration SECONDS] [--gap SECONDS]

Plays --base in a loop at the capture's own packet timing; every --every
seconds the next iteration plays --inject instead (logged with its wall
time to --log, so the findings it causes can be accounted for).
"""
import argparse, os, socket, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

ap = argparse.ArgumentParser()
ap.add_argument("iface"); ap.add_argument("--base", required=True)
ap.add_argument("--inject"); ap.add_argument("--every", type=float, default=600)
ap.add_argument("--log"); ap.add_argument("--duration", type=float, default=0)
ap.add_argument("--gap", type=float, default=0.5)
a = ap.parse_args()

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((a.iface, 0))
base, _ = pcaplib.read(a.base)
inj = pcaplib.read(a.inject)[0] if a.inject else None
start = time.monotonic(); last_inj = start
sent = loops = injections = errors = 0
late_max = 0.0


def log(msg):
    if a.log:
        with open(a.log, "a") as f:
            f.write(f"{time.time():.3f} {msg}\n")


def play(frames):
    global sent, errors, late_max
    t0 = frames[0][0]; w0 = time.monotonic()
    for t, fr in frames:
        due = w0 + (t - t0)
        d = due - time.monotonic()
        if d > 0:
            time.sleep(d)
        late = time.monotonic() - due
        if late > 0:
            # Late (before or after sleeping): shift the rest of the timeline
            # instead of bursting to catch up; a burst would be a real rate
            # violation on a 500 Hz channel.
            late_max = max(late_max, late)
            w0 += late
        try:
            s.send(fr); sent += 1
        except OSError:
            errors += 1


log(f"start base={a.base} inject={a.inject} every={a.every}")
while not a.duration or time.monotonic() - start < a.duration:
    if inj and time.monotonic() - last_inj >= a.every:
        log(f"inject {injections + 1}"); play(inj); injections += 1
        last_inj = time.monotonic()
    else:
        play(base); loops += 1
    if loops % 50 == 0:
        log(f"stats sent={sent} loops={loops} injections={injections} errors={errors} late_max_ms={late_max*1000:.1f}")
    time.sleep(a.gap)
log(f"end sent={sent} loops={loops} injections={injections} errors={errors} late_max_ms={late_max*1000:.1f}")
