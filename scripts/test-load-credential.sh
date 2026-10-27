#!/bin/sh
# Tests of packaging/focal/robodr-load-credential (robodr-focal's stand-in
# for LoadCredential= on systemd 245).
#
#   sudo sh scripts/test-load-credential.sh
#
# Needs root (the helper refuses to run otherwise and chowns its copies).
# It never touches /run/credentials or systemd: it runs a copy of the helper
# whose only change is base=/run/credentials -> a private temporary
# directory, removed on exit. Uses the 'nobody' user as a service user.
# Exit 0 all passed, 1 a case failed, 2 cannot run.
set -eu
umask 022

here=$(cd "$(dirname "$0")" && pwd)
src=$here/../packaging/focal/robodr-load-credential

[ "$(id -u)" -eq 0 ] || { echo "test-load-credential: run as root (sudo); only a temporary directory is written" >&2; exit 2; }
id -u nobody >/dev/null 2>&1 || { echo "test-load-credential: no 'nobody' user" >&2; exit 2; }
[ -f "$src" ] || { echo "test-load-credential: $src missing" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT INT TERM
chmod 0755 "$tmp"
base=$tmp/run/credentials
helper=$tmp/robodr-load-credential

# The copy differs from the shipped helper in the base line only.
[ "$(grep -c '^base=/run/credentials$' "$src")" -eq 1 ] || { echo "test-load-credential: base= line not found once" >&2; exit 2; }
sed "s|^base=/run/credentials\$|base=$base|" "$src" >"$helper"
[ "$(diff "$src" "$helper" | grep -c '^[<>]')" -eq 2 ] || { echo "test-load-credential: copy differs in more than base=" >&2; exit 2; }
mkdir -p "$tmp/run"

keys=$tmp/keys
mkdir -m 0700 "$keys"
printf 'secret-key-material\n' >"$keys/blackbox.key"
chmod 0600 "$keys/blackbox.key"
ln -s "$keys/blackbox.key" "$keys/link.key"

pass=0
fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }

# expect <status> <description> <helper args...>
expect() {
    want=$1
    what=$2
    shift 2
    set +e
    sh "$helper" "$@" 2>"$tmp/stderr"
    got=$?
    set -e
    if [ "$got" -eq "$want" ]; then ok; else bad "$what: exit $got, expected $want ($(cat "$tmp/stderr"))"; fi
}

# check_file <path> <mode> <owner:group> <description>
check_file() {
    if [ ! -f "$1" ] || [ -L "$1" ]; then bad "$4: $1 missing"; return; fi
    m=$(stat -c '%a %U:%G' "$1")
    if [ "$m" = "$2 $3" ]; then ok; else bad "$4: $1 is '$m', expected '$2 $3'"; fi
    if cmp -s "$1" "$keys/blackbox.key"; then ok; else bad "$4: content differs"; fi
}

absent() {
    if [ -e "$1" ] || [ -L "$1" ]; then bad "$2: $1 exists"; else ok; fi
}

nobody_grp=$(id -gn nobody)
d=robodr-deliverd.service
a=robodr-agentd.service

# 1. robodr-deliverd runs as root: its credential goes to root.
expect 0 "deliverd clear" clear "$d"
expect 0 "deliverd load for root" load "$d" root "blackbox.key:$keys/blackbox.key"
check_file "$base/$d/blackbox.key" 400 root:root "deliverd credential"
m=$(stat -c '%a %U:%G' "$base/$d" 2>/dev/null || echo missing)
if [ "$m" = "711 root:root" ]; then ok; else bad "deliverd dir is '$m', expected '711 root:root'"; fi
expect 0 "deliverd load again (replaces)" load "$d" root "blackbox.key:$keys/blackbox.key"
check_file "$base/$d/blackbox.key" 400 root:root "deliverd credential reloaded"
expect 0 "deliverd clear after load" clear "$d"
absent "$base/$d" "deliverd clear"

# 2. Every other unit still refuses root (by name or by uid 0).
for u in "$a" robodr-uplink.service robodr-spool-export.service robodr-executor.service \
    x-robodr-deliverd.service robodr-deliverd.service.d robodr-deliverd; do
    expect 2 "$u load for root" load "$u" root "blackbox.key:$keys/blackbox.key"
    absent "$base/$u/blackbox.key" "$u refused root"
done
expect 2 "$a load for uid 0" load "$a" 0 "blackbox.key:$keys/blackbox.key"
absent "$base/$a/blackbox.key" "$a refused uid 0"

# 3. An unprivileged service user still works.
expect 0 "$a load for nobody" load "$a" nobody "blackbox.key:$keys/blackbox.key"
check_file "$base/$a/blackbox.key" 400 "nobody:$nobody_grp" "$a credential"
expect 0 "$a clear" clear "$a"

# 4. The existing safety checks hold for the root exception too.
expect 2 "deliverd relative source" load "$d" root "blackbox.key:keys/blackbox.key"
expect 1 "deliverd symlinked source" load "$d" root "blackbox.key:$keys/link.key"
expect 1 "deliverd missing source" load "$d" root "blackbox.key:$keys/none.key"
expect 2 "deliverd bad credential name" load "$d" root "../x:$keys/blackbox.key"
expect 2 "deliverd spec without source" load "$d" root "blackbox.key"
expect 1 "deliverd unknown user" load "$d" no-such-user-robodr "blackbox.key:$keys/blackbox.key"
expect 2 "deliverd invalid unit name" load "../$d" root "blackbox.key:$keys/blackbox.key"
expect 0 "deliverd clear" clear "$d"
mkdir -m 0700 "$tmp/elsewhere"
ln -s "$tmp/elsewhere" "$base/$d"
expect 1 "deliverd symlinked unit dir" load "$d" root "blackbox.key:$keys/blackbox.key"
absent "$tmp/elsewhere/blackbox.key" "symlinked unit dir not followed"
rm -f -- "$base/$d"
mv "$base" "$tmp/credentials.real"
ln -s "$tmp/credentials.real" "$base"
expect 1 "deliverd symlinked base" load "$d" root "blackbox.key:$keys/blackbox.key"
absent "$tmp/credentials.real/$d/blackbox.key" "symlinked base not followed"

echo "test-load-credential: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
