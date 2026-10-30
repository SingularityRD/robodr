#!/bin/sh
# Tests of the exporter / gateway user migration of the package's maintainer
# scripts (migrate_exporter_users in packaging/deb/postinst and
# packaging/rpm/post): the state that releases where robodr-spool-export,
# robodr-kafka-publish, robodr-uplink and robodr-firewall-gw shared the
# robodr user wrote moves to each service's own user, link-safely, once.
#
#   sudo sh scripts/test-exporter-migration.sh
#
# Needs root (chown). It never touches /var/lib/robodr or systemd: it runs a
# copy of the block whose only changes are /var/lib/robodr -> a private
# temporary directory, the systemd branch disabled, and the user names
# mapped to users every system has (robodr -> daemon, robodr-spool -> bin,
# robodr-kafka -> sys, robodr-uplink -> nobody, robodr-gw -> mail).
# Exit 0 all passed, 1 a case failed, 2 cannot run.
set -eu
umask 022

here=$(cd "$(dirname "$0")" && pwd)
deb=$here/../packaging/deb/postinst
rpm=$here/../packaging/rpm/post

[ "$(id -u)" -eq 0 ] || { echo "test-exporter-migration: run as root (sudo); only a temporary directory is written" >&2; exit 2; }
for u in daemon bin sys nobody mail; do
    id -u "$u" >/dev/null 2>&1 || { echo "test-exporter-migration: no '$u' user" >&2; exit 2; }
done

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT INT TERM
chmod 0755 "$tmp"

pass=0
fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }
check() { # description command...
    what=$1
    shift
    if "$@"; then ok; else bad "$what"; fi
}

block() { # file
    sed -n '/^# >>> migrate_agentd_tree/,/^# <<< migrate_exporter_users/p' "$1"
}

# 1. Both package formats carry the same block.
block "$deb" >"$tmp/deb.block"
block "$rpm" >"$tmp/rpm.block"
if [ -s "$tmp/deb.block" ] && cmp -s "$tmp/deb.block" "$tmp/rpm.block"; then ok; else bad "postinst and rpm post blocks differ or are missing"; fi
check "rpm post calls migrate_exporter_users" grep -q '^migrate_exporter_users$' "$rpm"
check "postinst calls migrate_exporter_users" grep -q '^    migrate_exporter_users$' "$deb"

lib=$tmp/var/lib/robodr
# shellcheck disable=SC2016 # ${meu_pair...} is text of the block, not expanded here
sed -e "s|/var/lib/robodr|$lib|g" \
    -e 's|\[ -d /run/systemd/system \]|false|' \
    -e 's|:robodr-spool|:bin|g; s|:robodr-kafka|:sys|g; s|:robodr-uplink|:nobody|g; s|:robodr-gw|:mail|g' \
    -e 's|" robodr "\${meu_pair#\*:}" robodr$|" daemon "${meu_pair#*:}" daemon|' \
    "$tmp/deb.block" >"$tmp/migrate.sh"
# shellcheck disable=SC2016 # literal text of the block
grep -q '" daemon "${meu_pair#\*:}" daemon$' "$tmp/migrate.sh" || { echo "test-exporter-migration: call line not found" >&2; exit 2; }
printf 'set -e\nstopped=""\nmigrate_exporter_users\nmigrate_exporter_users\n' >>"$tmp/migrate.sh"

# A tree as the old releases left it (everything owned by robodr = daemon).
mkdir -p "$lib/export/diode" "$lib/export/spool-export" "$lib/export/kafka-publish" \
    "$lib/export/uplink" "$lib/firewall-gw" "$tmp/elsewhere"
printf 'secret\n' >"$tmp/elsewhere/target"
printf 'batch\n' >"$lib/export/diode/batch-1.rbdb"
printf '{}\n' >"$lib/export/spool-export/state.json"
printf '{}\n' >"$lib/export/kafka-publish/state.json"
printf '{}\n' >"$lib/export/uplink/uplink-status.json"
printf '{}\n' >"$lib/firewall-gw/status.json"
chmod 0666 "$lib/export/uplink/uplink-status.json"
# Planted by one exporter in another's state: a link to a file elsewhere, a
# hard link to it, and a FIFO.
ln -s "$tmp/elsewhere/target" "$lib/export/uplink/evil-link"
ln "$tmp/elsewhere/target" "$lib/export/spool-export/evil-hardlink"
mkfifo "$lib/firewall-gw/evil-fifo"
chown -R -h daemon:daemon "$lib/export" "$lib/firewall-gw"
chown root:root "$tmp/elsewhere/target"
# A file of another owner stays that owner's.
printf 'root\n' >"$lib/export/diode/root-owned"

if sh "$tmp/migrate.sh" 2>"$tmp/stderr"; then ok; else bad "migration failed: $(cat "$tmp/stderr")"; fi

owner() { stat -c '%U' "$1"; }
expect_owner() { # path user
    if [ -e "$1" ] && [ "$(owner "$1")" = "$2" ]; then ok; else bad "$1: owner $(owner "$1" 2>/dev/null || echo missing), expected $2"; fi
}
expect_owner "$lib/export/diode" bin
expect_owner "$lib/export/diode/batch-1.rbdb" bin
expect_owner "$lib/export/diode/root-owned" root
expect_owner "$lib/export/spool-export/state.json" bin
expect_owner "$lib/export/kafka-publish" sys
expect_owner "$lib/export/kafka-publish/state.json" sys
expect_owner "$lib/export/uplink/uplink-status.json" nobody
expect_owner "$lib/firewall-gw/status.json" mail
if [ -e "$lib/export/uplink/evil-link" ] || [ -L "$lib/export/uplink/evil-link" ]; then bad "planted symlink kept"; else ok; fi
if [ -e "$lib/firewall-gw/evil-fifo" ]; then bad "planted FIFO kept"; else ok; fi
expect_owner "$tmp/elsewhere/target" root
# The hard link is replaced by a copy; it keeps the shared inode's owner (root).
expect_owner "$lib/export/spool-export/evil-hardlink" root
check "hard link not broken" [ "$(stat -c '%h' "$tmp/elsewhere/target")" = 1 ]
check "group/other write not removed" [ "$(stat -c '%a' "$lib/export/uplink/uplink-status.json")" = 644 ]
check "marker missing" [ -e "$lib/.exporter-users-migrated" ]

# 3. Once done, it does not run again (a file robodr writes later stays).
printf 'later\n' >"$lib/export/uplink/later"
chown daemon:daemon "$lib/export/uplink/later"
if sh "$tmp/migrate.sh" 2>"$tmp/stderr"; then ok; else bad "second run failed: $(cat "$tmp/stderr")"; fi
expect_owner "$lib/export/uplink/later" daemon

echo "test-exporter-migration: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
