#!/usr/bin/env bash
# Tests of scripts/build-pkg-repo.sh with throwaway keys and minimal
# packages (no real release needed):
#   * a correctly signed asset set gives apt suites whose InRelease verifies
#     and that `apt-get update` accepts with only the exported keyring
#     (signed-by), and a dnf repository whose RPMs pass `rpm -K` and whose
#     repomd.xml.asc verifies;
#   * refused, with nothing written: a tampered .deb, a signature by another
#     minisign key, a wrong trusted comment, a missing .minisig.
# Needs: minisign, gpg, gpgv, apt-ftparchive, createrepo_c, rpmbuild, rpmsign,
# dpkg-deb, apt-get.
# Exit: 0 pass, 1 fail.
# ok() never fails: `test && ok || bad` is an if-then-else here.
# Functions run through the trap and refuse() look unreachable to shellcheck.
# shellcheck disable=SC2015,SC2317
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
cleanup() { GNUPGHOME="$work/gnupg" gpgconf --kill all 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
fail=0
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1" >&2; fail=1; }

version=0.3.0-rc.1
debver="${version/-/\~}-1"
rpmver="${version/-/\~}"
a="$work/assets"
mkdir -p "$a"

# Minimal packages.
for arch in amd64 arm64; do
    for p in robodr robodr-focal; do
        d="$work/deb-$p-$arch"
        mkdir -p "$d/DEBIAN" "$d/usr/share/doc/$p"
        printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <t@robodr.test>\nDescription: test\n' \
            "$p" "$debver" "$arch" >"$d/DEBIAN/control"
        echo "$p" >"$d/usr/share/doc/$p/README"
        dpkg-deb --root-owner-group -Zgzip --build "$d" "$a/${p}_${debver}_$arch.deb" >/dev/null
    done
done
mkdir -p "$work/rpmbuild/SPECS"
cat >"$work/rpmbuild/SPECS/robodr.spec" <<EOF
Name: robodr
Version: $rpmver
Release: 1
Summary: test
License: Proprietary
%description
test
%install
mkdir -p %{buildroot}/usr/share/doc/robodr
echo robodr > %{buildroot}/usr/share/doc/robodr/README
%files
/usr/share/doc/robodr/README
EOF
for t in x86_64 aarch64; do
    rpmbuild --quiet --define "_topdir $work/rpmbuild" --target "$t" -bb "$work/rpmbuild/SPECS/robodr.spec" >/dev/null 2>&1
done
find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$a/" \;

# Throwaway keys.
minisign -G -W -p "$work/rel.pub" -s "$work/rel.key" </dev/null >/dev/null 2>&1
minisign -G -W -p "$work/other.pub" -s "$work/other.key" </dev/null >/dev/null 2>&1
sign_all() { # dir key
    local f
    for f in "$1"/*.deb "$1"/*.rpm; do
        minisign -S -s "$2" -m "$f" -t "robodr $version $(basename "$f")" </dev/null >/dev/null 2>&1
    done
}
sign_all "$a" "$work/rel.key"
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "RoboDR test archive <archive@robodr.test>" rsa3072 sign never 2>/dev/null
fpr="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')"

run() { # out assets
    "$here/build-pkg-repo.sh" --assets "$2" --pubkey "$work/rel.pub" --version "$version" \
        --gnupghome "$GNUPGHOME" --key "$fpr" --valid-days 30 --out "$1"
}

if run "$work/out" "$a" 2>"$work/log"; then
    ok "repository built and self-verified"
else
    bad "build: $(tail -5 "$work/log")"
fi
o="$work/out"
for s in stable focal; do
    if gpgv --keyring "$o/robodr-archive-keyring.gpg" "$o/apt/dists/$s/InRelease" 2>/dev/null; then
        ok "$s/InRelease verifies with the exported keyring"
    else
        bad "$s/InRelease"
    fi
    grep -q '^Valid-Until: ' "$o/apt/dists/$s/Release" && ok "$s/Release has Valid-Until" || bad "$s Valid-Until"
done
# apt itself, with only the exported keyring (signed-by), against file://.
ar="$work/aptroot"
mkdir -p "$ar/etc/apt/sources.list.d" "$ar/etc/apt/preferences.d" "$ar/var/lib/apt/lists/partial" "$ar/var/cache/apt/archives/partial" "$ar/var/lib/dpkg"
: >"$ar/var/lib/dpkg/status"
echo "deb [arch=amd64 signed-by=$o/robodr-archive-keyring.gpg] file://$o/apt stable main" >"$ar/etc/apt/sources.list"
aptopt=(-o "Dir=$ar" -o "Dir::State::status=$ar/var/lib/dpkg/status" -o "Dir::Etc::trustedparts=$ar/etc/apt/trusted.gpg.d"
    -o "APT::Architecture=amd64" -o "Debug::NoLocking=1" -o "APT::Sandbox::User=root")
mkdir -p "$ar/etc/apt/trusted.gpg.d"
if apt-get "${aptopt[@]}" update >"$work/apt.log" 2>&1 && ! grep -qiE '^(W|E): ' "$work/apt.log" &&
    apt-cache "${aptopt[@]}" policy robodr 2>/dev/null | grep -q "$debver"; then
    ok "apt-get update accepts the stable suite (signed-by keyring only) and sees robodr $debver"
else
    bad "apt-get update: $(tail -5 "$work/apt.log")"
fi
for f in "$o"/rpm/*/*.rpm; do
    db="$work/rpmdb"
    mkdir -p "$db"
    rpm --dbpath "$db" --import "$o/robodr-archive-keyring.asc" 2>/dev/null || true
    [[ "$(rpm --dbpath "$db" -K "$f")" == *"signatures OK"* ]] && ok "rpm -K $(basename "$f")" || bad "rpm -K $(basename "$f")"
done
cmp -s "$a/robodr-$rpmver-1.x86_64.rpm" "$o/rpm/x86_64/robodr-$rpmver-1.x86_64.rpm" &&
    bad "repository RPM was not signed" || ok "repository RPM carries an rpmsign signature (other bytes than the asset)"

refuse() { # name mutate-command
    local name="$1" t="$work/t-$RANDOM"
    shift
    cp -r "$a" "$t"
    "$@" "$t"
    if run "$work/out-$RANDOM" "$t" >/dev/null 2>&1; then bad "accepted: $name"; else ok "refuses: $name"; fi
}
tamper() { printf 'x' >>"$1/robodr_${debver}_arm64.deb"; }
other_key() { minisign -S -s "$work/other.key" -m "$1/robodr-focal_${debver}_amd64.deb" -t "robodr $version robodr-focal_${debver}_amd64.deb" </dev/null >/dev/null 2>&1; }
wrong_comment() { minisign -S -s "$work/rel.key" -m "$1/robodr-$rpmver-1.aarch64.rpm" -t "robodr 9.9.9 robodr-$rpmver-1.aarch64.rpm" </dev/null >/dev/null 2>&1; }
no_sig() { rm "$1/robodr_${debver}_amd64.deb.minisig"; }
refuse "a tampered .deb" tamper
refuse "a signature by another minisign key" other_key
refuse "a wrong trusted comment (other version)" wrong_comment
refuse "a missing .minisig" no_sig
if "$here/build-pkg-repo.sh" --assets "$a" --pubkey "$work/rel.pub" --version "$version" --gnupghome "$GNUPGHOME" \
    --key "$fpr" --out "$o" >/dev/null 2>&1; then bad "wrote into a non-empty --out"; else ok "refuses a non-empty --out"; fi

[[ $fail == 0 ]] && echo "test-build-pkg-repo: all passed"
exit "$fail"
