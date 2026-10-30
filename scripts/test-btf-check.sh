#!/bin/sh
# Tests of packaging/btf/robodr-btf-check (robodr-pulsard.service,
# ExecStartPre=) against temporary configs and BTF directories.
#
#   sh scripts/test-btf-check.sh
#
# Exit: 0 all passed, 1 a case failed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
chk=$here/../packaging/btf/robodr-btf-check
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
pass=0
fail=0
case_() { # name expected-exit config-file
    if sh "$chk" --config "$3" --dir "$t/btf" >"$t/out" 2>&1; then rc=0; else rc=$?; fi
    if [ "$rc" -eq "$2" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "FAIL: $1: exit $rc, want $2" >&2
        sed 's/^/    /' "$t/out" >&2
    fi
}
conf() { # btf_path line (or empty) -> $t/pulsar.toml
    printf '[pulsar]\napi_socket_path = "/run/robodr-pulsard/pulsar.sock"\n%s\n\n[module.x]\nbtf_path = "/elsewhere"\n' "$1" >"$t/pulsar.toml"
}
stamp() { # [kernel-release] [sha256]
    printf '%s\n%s\n%s\n' "${1:-$(uname -r)}" "$(uname -v)" "${2:-$(sha256sum "$t/btf/vmlinux" | cut -d' ' -f1)}" >"$t/btf/vmlinux.kernel"
}
mkdir -p "$t/btf"

conf '#btf_path = "/etc/robodr/btf/vmlinux"'
case_ "no btf_path, no file" 0 "$t/pulsar.toml"
case_ "config missing: nothing to check" 0 "$t/missing.toml"
echo btf >"$t/btf/vmlinux"
case_ "no btf_path, unused file" 0 "$t/pulsar.toml"

conf 'btf_path = "/tmp/other.btf"'
case_ "btf_path elsewhere is refused" 1 "$t/pulsar.toml"
conf "btf_path = '/tmp/other.btf'"
case_ "btf_path elsewhere (single quotes) is refused" 1 "$t/pulsar.toml"

conf 'btf_path = "/etc/robodr/btf/vmlinux"'
rm -f "$t/btf/vmlinux.kernel"
case_ "btf_path set, no stamp" 1 "$t/pulsar.toml"
stamp
case_ "btf_path set, stamp matches" 0 "$t/pulsar.toml"
stamp 5.15.148-tegra
case_ "stamp of another kernel" 1 "$t/pulsar.toml"
stamp "" 0000000000000000000000000000000000000000000000000000000000000000
case_ "stamp with another file's hash" 1 "$t/pulsar.toml"
stamp
echo tampered >>"$t/btf/vmlinux"
case_ "file changed after stamping" 1 "$t/pulsar.toml"
printf '%s\n%s\n' "$(uname -r)" "$(uname -v)" >"$t/btf/vmlinux.kernel"
case_ "old two-line stamp (no hash)" 1 "$t/pulsar.toml"
rm -f "$t/btf/vmlinux" "$t/btf/vmlinux.kernel"
case_ "btf_path set, file missing" 1 "$t/pulsar.toml"
conf '  btf_path="/etc/robodr/btf/vmlinux"   # comment'
echo btf >"$t/btf/vmlinux"
stamp
case_ "spacing and trailing comment" 0 "$t/pulsar.toml"

echo "test-btf-check: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
