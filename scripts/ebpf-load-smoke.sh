#!/usr/bin/env bash
# Load robodr-pulsard's eBPF probes into the RUNNING kernel with the shipped
# rules (rules/robodr), set off one real event per rule family and check that
# each expected rule fires AND reaches the agentd-side socket through
# robodr-threat-forward (T27 of docs/SALES-READINESS.md). Run as root on a
# throwaway machine (the CI runner, a test VM): it writes into /etc and /tmp
# to set the rules off, and removes what it wrote.
#
#   scripts/ebpf-load-smoke.sh PULSARD_BINARY [RULES_DIR] [OUT_DIR]
#   scripts/ebpf-load-smoke.sh --self-test   (the /etc cleanup; no root)
#
# The agentd end is a stand-in: a unix stream socket that records the
# threat-forward protocol lines (`{"kind":"threat","rule":...}`), the same
# socket robodr-agentd's host_threats input listens on. What is checked:
#   1. the daemon starts, loads every probe and every rule file (a rule that
#      does not compile disables the whole rules engine: no rule would fire);
#   2. each trigger below makes its rule fire (threat-logger JSON on stdout);
#   3. each fired rule arrives on the host-threats socket, well formed;
#   4. the daemon is still running at the end.
# OUT_DIR (default: a temp dir) keeps pulsard.log, threats.jsonl and
# result.json (one line per expected rule: fired / forwarded).
#
# Needs: a kernel with BTF (/sys/kernel/btf/vmlinux), bash, python3, strace.
# Exit: 0 every expected rule fired and was forwarded, 1 otherwise, 2 usage.
set -euo pipefail

# What the triggers write under /etc is removed again on exit. `etc` is /etc
# except in --self-test, which runs the same cleanup against a temp dir.
etc=/etc
pids=()
work=""
etc_robodr_existed=0
# The /etc/robodr trigger creates /etc/robodr too when it is missing (a
# runner without robodr installed): remove it again then, and only then
# (rmdir: never a directory something else has put files into meanwhile).
note_etc_robodr() {
    etc_robodr_existed=0
    if [[ -d "$etc/robodr" ]]; then etc_robodr_existed=1; fi
}
# shellcheck disable=SC2317 # called by the EXIT trap
cleanup() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -f "$etc/ld.so.conf.d/zz-robodr-ebpf-smoke.conf" "$etc/modules-load.d/zz-robodr-ebpf-smoke.conf"
    rmdir "$etc/robodr/zz-ebpf-smoke" 2>/dev/null || true
    [[ $etc_robodr_existed == 1 ]] || rmdir "$etc/robodr" 2>/dev/null || true
    if [[ -n "$work" ]]; then rm -rf "$work"; fi
}

# The cleanup above against a temp dir standing in for /etc (no root, no
# eBPF): what the triggers write goes, /etc/robodr goes only when this run
# created it and it holds nothing else.
self_test() {
    local t ok=0
    t="$(mktemp -d)"
    etc="$t/etc"
    # check NAME BEFORE DURING EXPECT: bash snippets run in $etc before the
    # run starts, while it runs, and (must succeed) after the cleanup.
    check() {
        rm -rf "$etc" && mkdir -p "$etc/ld.so.conf.d" "$etc/modules-load.d"
        (cd "$etc" && bash -c "$2")
        work="$(mktemp -d "$t/work.XXXXXX")"
        note_etc_robodr
        mkdir -p "$etc/robodr/zz-ebpf-smoke"
        echo x >"$etc/ld.so.conf.d/zz-robodr-ebpf-smoke.conf"
        echo x >"$etc/modules-load.d/zz-robodr-ebpf-smoke.conf"
        (cd "$etc" && bash -c "$3")
        cleanup
        if [[ -e "$etc/ld.so.conf.d/zz-robodr-ebpf-smoke.conf" || -e "$etc/modules-load.d/zz-robodr-ebpf-smoke.conf" \
            || -e "$etc/robodr/zz-ebpf-smoke" || -e "$work" ]] || ! (cd "$etc" && bash -c "$4"); then
            echo "self-test FAIL: $1" >&2
        else
            ok=$((ok + 1))
        fi
    }
    check "absent before: /etc/robodr removed" "" "" "[[ ! -e robodr ]]"
    check "present and empty before: kept" "mkdir robodr" "" "[[ -d robodr ]]"
    check "present with a file before: kept with it" "mkdir robodr && echo c >robodr/agentd.toml" "" \
        "[[ -f robodr/agentd.toml ]]"
    check "absent before, a file added during the run: kept" "" "echo c >robodr/agentd.toml" \
        "[[ -f robodr/agentd.toml ]]"
    rm -rf "$t"
    echo "self-test: $ok/4 passed"
    [[ $ok -eq 4 ]]
}
if [[ "${1:-}" == --self-test ]]; then
    self_test
    exit
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
pulsard="${1:-}"
rules="${2:-$root/rules/robodr}"
out="${3:-$(mktemp -d /var/tmp/robodr-ebpf.XXXXXX)}"
[[ -x "$pulsard" ]] || { echo "usage: ebpf-load-smoke.sh PULSARD_BINARY [RULES_DIR] [OUT_DIR]" >&2; exit 2; }
[[ -d "$rules" ]] || { echo "ebpf-load-smoke: no rules directory $rules" >&2; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo "ebpf-load-smoke: run as root (eBPF)" >&2; exit 2; }
[[ -e /sys/kernel/btf/vmlinux ]] || { echo "ebpf-load-smoke: the kernel has no BTF" >&2; exit 1; }
command -v strace >/dev/null || { echo "ebpf-load-smoke: strace not installed (a trigger)" >&2; exit 2; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d /var/tmp/robodr-ebpf-work.XXXXXX)"

# rule name | trigger (bash, run as root; @WORK@ and @PORT@ filled in later)
TRIGGERS=(
    "RoboDR: Interactive shell started on robot controller|bash -i -c true </dev/null >/dev/null 2>&1"
    "RoboDR: Program executed from a temporary directory|cp /bin/true @WORK@/robodr-ebpf-true && @WORK@/robodr-ebpf-true"
    "RoboDR: Interpreter one-liner executed|python3 -c pass"
    "RoboDR: Debugger or tracer started on robot controller|strace -o /dev/null true"
    "RoboDR: Shell or netcat-style tool opened a network connection|bash -c 'exec 3<>/dev/tcp/127.0.0.1/@PORT@' || true"
    "RoboDR: Dynamic linker search path changed|echo '# robodr ebpf smoke' >/etc/ld.so.conf.d/zz-robodr-ebpf-smoke.conf"
    "RoboDR: Kernel module autoload configuration changed|echo '# robodr ebpf smoke' >/etc/modules-load.d/zz-robodr-ebpf-smoke.conf"
    "RoboDR: Directory created in a RoboDR or Pulsar protected path|mkdir -p /etc/robodr/zz-ebpf-smoke"
)

note_etc_robodr
trap cleanup EXIT

# A TCP listener for the connect trigger, and the agentd stand-in.
port_file="$work/port"
python3 - "$port_file" <<'PY' &
import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(16)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    c.close()
PY
pids+=($!)
sock="$work/host-threats.sock"
python3 - "$sock" "$out/threats.jsonl" <<'PY' &
import os, socket, sys, threading
path, log = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
os.chmod(path, 0o600)
s.listen(4)
lock = threading.Lock()
def serve(c):
    with c, c.makefile("rb") as f:
        for line in f:
            with lock, open(log, "ab") as o:
                o.write(line if line.endswith(b"\n") else line + b"\n")
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
pids+=($!)
for _ in $(seq 50); do [[ -s "$port_file" && -S "$sock" ]] && break; sleep 0.1; done
port="$(cat "$port_file")"
: >"$out/threats.jsonl"

cat >"$work/pulsar.toml" <<EOF
[pulsar]
api_socket_path = "$work/pulsar.sock"

[module.rules-engine]
rules_path = "$rules"

[module.threat-logger]
console = true
syslog = false
output_format = "json"

[module.robodr-threat-forward]
enabled = true
socket_path = "$sock"
EOF

echo "ebpf-load-smoke: kernel $(uname -r), $(find "$rules" -name '*.toml' | wc -l) rule files"
"$pulsard" --version | sed 's/^/ebpf-load-smoke: /'
"$pulsard" --config-file "$work/pulsar.toml" >"$out/pulsard.log" 2>&1 &
pulsard_pid=$!
pids+=("$pulsard_pid")

# Started: the API socket exists once every module is up.
for i in $(seq 120); do
    [[ -S "$work/pulsar.sock" ]] && break
    if ! kill -0 "$pulsard_pid" 2>/dev/null || [[ "$i" == 120 ]]; then
        tail -n 60 "$out/pulsard.log"
        echo "::error::ebpf-load-smoke: robodr-pulsard did not start (log above)"
        exit 1
    fi
    sleep 0.5
done
# Probes attach asynchronously after the socket: give them a moment.
sleep 5
# Log lines at ERROR level (env_logger "[... ERROR target]"); threat JSON
# lines are not log lines.
if grep -vE '^\{' "$out/pulsard.log" | grep -qE '\bERROR\b'; then
    grep -vE '^\{' "$out/pulsard.log" | grep -E '\bERROR\b' | head -n 20
    echo "::error::ebpf-load-smoke: robodr-pulsard reported errors while loading"
    exit 1
fi

for t in "${TRIGGERS[@]}"; do
    rule="${t%%|*}"
    cmd="${t#*|}"
    cmd="${cmd//@WORK@/$work}"
    cmd="${cmd//@PORT@/$port}"
    echo "ebpf-load-smoke: $rule <- $cmd"
    bash -c "$cmd" || true
done
sleep 5

fail=0
python3 - "$out/pulsard.log" "$out/threats.jsonl" "$out/result.json" "${TRIGGERS[@]%%|*}" <<'PY' || fail=1
import json, sys
log, fwd, result, *rules = sys.argv[1:]

def jsonl(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out

def descr(e):
    t = (e.get("header") or {}).get("threat") or {}
    return t.get("description")

fired = {descr(e) for e in jsonl(log)} - {None}
forwarded = {}
for e in jsonl(fwd):
    if e.get("kind") == "threat":
        forwarded.setdefault(e.get("rule"), e)
bad = 0
rows = []
for r in rules:
    f = r in fired
    w = forwarded.get(r)
    ok_wire = bool(w) and isinstance(w.get("pid"), int) and w.get("source") and w.get("v") == 1
    rows.append({"rule": r, "fired": f, "forwarded": bool(w), "wire_ok": ok_wire})
    status = "ok" if f and ok_wire else "MISSING"
    print(f"ebpf-load-smoke: {status:7} fired={f!s:5} forwarded={bool(w)!s:5} {r}")
    if status != "ok":
        print(f"::error::ebpf-load-smoke: {r}: fired={f} forwarded={bool(w)}")
        bad += 1
json.dump({"rules": rows, "fired_total": len(fired), "forwarded_total": len(forwarded)},
          open(result, "w"), indent=1)
sys.exit(1 if bad else 0)
PY
if ! kill -0 "$pulsard_pid" 2>/dev/null; then
    echo "::error::ebpf-load-smoke: robodr-pulsard exited during the run"
    fail=1
fi
if [[ "$fail" == 0 ]]; then
    echo "ebpf-load-smoke: OK (${#TRIGGERS[@]} rules fired and forwarded; logs in $out)"
fi
exit "$fail"
