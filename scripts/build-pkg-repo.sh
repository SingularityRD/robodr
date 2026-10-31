#!/usr/bin/env bash
# Signed apt and dnf repositories from a published RoboDR release
# (.github/workflows/pkg-repo.yml; docs/RELEASE.md "Package repositories").
#
#   scripts/build-pkg-repo.sh --assets DIR --pubkey MINISIGN.pub --version V
#       --gnupghome DIR --key FINGERPRINT [--passphrase-file FILE]
#       [--valid-days N] --out DIR
#
# Input: the release's assets (gh release download) with their .minisig
# files. NOTHING is put into a repository before its minisign signature
# verifies with the release public key (--pubkey, a FILE: the pinned key,
# never one fetched next to the assets) and carries the trusted comment
# "robodr <version> <file>" the release workflow signs with.
#
# Output (DIR):
#   apt/  dists/stable/  the robodr .deb (Ubuntu 22.04 / 24.04, Debian 12+)
#         dists/focal/   the robodr-focal .deb (Ubuntu 20.04 / JetPack 5)
#         each with main/binary-{amd64,arm64}/Packages(.gz), Release, a
#         clear-signed InRelease and a detached Release.gpg; pool/main/.
#   rpm/  {x86_64,aarch64}/: the RPMs, signed with rpmsign (the RPM header
#         signature dnf checks with gpgcheck=1) and repodata/ from
#         createrepo_c with repomd.xml.asc (repo_gpgcheck=1); robodr.repo.
#         rpmsign rewrites the package: the repository's RPMs have other
#         bytes than the release assets (whose minisign signatures stay valid
#         for the unsigned originals).
#   robodr-archive-keyring.gpg / .asc  the repository public key (OpenPGP)
#   KEY-FINGERPRINT, REPO-SHA256SUMS
# Then it VERIFIES what it wrote, with only the exported public key: gpgv of
# InRelease and Release.gpg of every suite and of every repomd.xml.asc, and
# `rpm -K` of every RPM in a throwaway rpmdb.
#
# The OpenPGP key (generated and held by the release owner, docs/RELEASE.md)
# is imported by the caller into --gnupghome; this script only uses it.
# --valid-days N adds "Valid-Until: <now + N days>" to every Release (apt
# then refuses a stale, replayed repository; the repository must be
# re-signed before it expires). Default: none.
#
# Requires: minisign, gpg, gpgv, apt-ftparchive (apt-utils), createrepo_c,
# rpmsign / rpm, dpkg-deb. Exit: 0 written and verified, 1 refused/failed,
# 2 usage.
set -euo pipefail

assets="" pubkey="" version="" gnupghome="" key="" passfile="" out="" valid_days=0
while [[ $# -gt 0 ]]; do
    case "$1" in
    --assets) assets="$2"; shift 2 ;;
    --pubkey) pubkey="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --gnupghome) gnupghome="$2"; shift 2 ;;
    --key) key="$2"; shift 2 ;;
    --passphrase-file) passfile="$2"; shift 2 ;;
    --valid-days) valid_days="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "build-pkg-repo: unknown argument $1" >&2; exit 2 ;;
    esac
done
for v in assets pubkey version gnupghome key out; do
    [[ -n "${!v}" ]] || { echo "build-pkg-repo: --${v} is required" >&2; exit 2; }
done
[[ "$key" =~ ^[0-9A-F]{40}$ ]] || { echo "build-pkg-repo: --key must be a 40-hex-digit fingerprint (upper case)" >&2; exit 2; }
[[ "$valid_days" =~ ^[0-9]{1,4}$ ]] || { echo "build-pkg-repo: --valid-days must be a number" >&2; exit 2; }
for t in minisign gpg gpgv apt-ftparchive createrepo_c rpmsign rpm dpkg-deb; do
    command -v "$t" >/dev/null || { echo "build-pkg-repo: $t not found" >&2; exit 2; }
done
[[ ! -e "$out" ]] || [[ -z "$(ls -A "$out")" ]] || { echo "build-pkg-repo: $out is not empty" >&2; exit 1; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
assets="$(cd "$assets" && pwd)"
export GNUPGHOME="$gnupghome"
gpg_sign=(gpg --batch --yes --local-user "$key!")
if [[ -n "$passfile" ]]; then
    gpg_sign+=(--pinentry-mode loopback --passphrase-file "$passfile")
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
debver="${version/-/\~}-1"
rpmver="${version/-/\~}"

# ------------------------------------------------ 1. release signatures first
verify_asset() { # file
    local f="$1" b
    b="$(basename "$f")"
    if ! minisign -V -q -p "$pubkey" -m "$f" >/dev/null 2>&1; then
        echo "build-pkg-repo: REFUSED: $b: minisign signature does not verify with $pubkey" >&2
        return 1
    fi
    if ! grep -qx "trusted comment: robodr $version $b" "$f.minisig"; then
        echo "build-pkg-repo: REFUSED: $b: trusted comment is not 'robodr $version $b'" >&2
        return 1
    fi
}
debs=() focal=() rpms=()
for a in amd64 arm64; do
    debs+=("$assets/robodr_${debver}_$a.deb")
    focal+=("$assets/robodr-focal_${debver}_$a.deb")
done
for a in x86_64 aarch64; do rpms+=("$assets/robodr-$rpmver-1.$a.rpm"); done
rc=0
for f in "${debs[@]}" "${focal[@]}" "${rpms[@]}"; do
    if [[ ! -f "$f" || ! -f "$f.minisig" ]]; then
        echo "build-pkg-repo: REFUSED: $(basename "$f") or its .minisig is missing from $assets" >&2
        rc=1
        continue
    fi
    verify_asset "$f" || rc=1
done
[[ $rc == 0 ]] || exit 1
echo "build-pkg-repo: ${#debs[@]} + ${#focal[@]} .deb and ${#rpms[@]} .rpm verified with the release key" >&2

# ------------------------------------------------ 2. apt
apt="$out/apt"
mkdir -p "$apt/pool/main"
cp "${debs[@]}" "${focal[@]}" "$apt/pool/main/"
release_conf="$work/release.conf"
# apt-ftparchive `packages` takes a directory; give it one per suite and arch.
suite_files() { # suite file...
    local suite="$1"
    shift
    local d="$apt/dists/$suite" a f
    for a in amd64 arm64; do
        mkdir -p "$d/main/binary-$a" "$work/scan/$suite-$a/pool/main"
        for f in "$@"; do
            [[ "$f" == *"_$a.deb" ]] && ln -f "$apt/pool/main/$(basename "$f")" "$work/scan/$suite-$a/pool/main/"
        done
        (cd "$work/scan/$suite-$a" && apt-ftparchive packages pool) >"$d/main/binary-$a/Packages"
        [[ "$(grep -c '^Filename: pool/main/' "$d/main/binary-$a/Packages")" == 1 ]] ||
            { echo "build-pkg-repo: FAIL: Packages for $suite/$a does not list exactly one package" >&2; return 1; }
        gzip -9n -k "$d/main/binary-$a/Packages"
    done
    cat >"$release_conf" <<CONF
APT::FTPArchive::Release::Origin "RoboDR";
APT::FTPArchive::Release::Label "RoboDR";
APT::FTPArchive::Release::Suite "$suite";
APT::FTPArchive::Release::Codename "$suite";
APT::FTPArchive::Release::Architectures "amd64 arm64";
APT::FTPArchive::Release::Components "main";
APT::FTPArchive::Release::Description "RoboDR $version (Singularity RD)";
CONF
    apt-ftparchive -c "$release_conf" release "$d" >"$work/Release"
    if [[ "$valid_days" != 0 ]]; then
        awk -v vu="$(date -u -d "+$valid_days days" '+%a, %d %b %Y %H:%M:%S UTC')" \
            '{ print } /^Date: / { print "Valid-Until: " vu }' "$work/Release" >"$d/Release"
    else
        cp "$work/Release" "$d/Release"
    fi
    "${gpg_sign[@]}" --digest-algo SHA512 --clearsign -o "$d/InRelease" "$d/Release"
    "${gpg_sign[@]}" --digest-algo SHA512 --armor --detach-sign -o "$d/Release.gpg" "$d/Release"
}
suite_files stable "${debs[@]}"
suite_files focal "${focal[@]}"

# ------------------------------------------------ 3. rpm
rpmdir="$out/rpm"
rpm_sign=(rpmsign --define "_gpg_name $key" --define "_gpg_path $GNUPGHOME"
    --define "_gpg_digest_algo sha512")
if [[ -n "$passfile" ]]; then
    rpm_sign+=(--define "_gpg_sign_cmd_extra_args --pinentry-mode loopback --passphrase-file $passfile")
fi
for f in "${rpms[@]}"; do
    case "$f" in *.x86_64.rpm) a=x86_64 ;; *.aarch64.rpm) a=aarch64 ;; esac
    mkdir -p "$rpmdir/$a"
    cp "$f" "$rpmdir/$a/"
    "${rpm_sign[@]}" --addsign "$rpmdir/$a/$(basename "$f")" >/dev/null
done
for a in x86_64 aarch64; do
    createrepo_c --quiet --unique-md-filenames --checksum sha256 "$rpmdir/$a" >/dev/null
    "${gpg_sign[@]}" --digest-algo SHA512 --armor --detach-sign -o "$rpmdir/$a/repodata/repomd.xml.asc" \
        "$rpmdir/$a/repodata/repomd.xml"
done
cat >"$rpmdir/robodr.repo" <<'REPO'
# /etc/yum.repos.d/robodr.repo  (replace BASEURL with where this directory is served)
[robodr]
name=RoboDR
baseurl=BASEURL/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-robodr
REPO

# ------------------------------------------------ 4. public key
gpg --batch --export --export-options export-minimal "$key" >"$out/robodr-archive-keyring.gpg"
gpg --batch --armor --export --export-options export-minimal "$key" >"$out/robodr-archive-keyring.asc"
[[ -s "$out/robodr-archive-keyring.gpg" ]] || { echo "build-pkg-repo: FAIL: key $key not in $GNUPGHOME" >&2; exit 1; }
printf '%s\n' "$key" >"$out/KEY-FINGERPRINT"

# ------------------------------------------------ 5. verify with the public key only
kr="$out/robodr-archive-keyring.gpg"
for s in stable focal; do
    d="$apt/dists/$s"
    gpgv --keyring "$kr" "$d/InRelease" >/dev/null 2>&1 || { echo "build-pkg-repo: FAIL: $s/InRelease does not verify" >&2; exit 1; }
    gpgv --keyring "$kr" "$d/Release.gpg" "$d/Release" >/dev/null 2>&1 || { echo "build-pkg-repo: FAIL: $s/Release.gpg does not verify" >&2; exit 1; }
    # Every index named in Release has the hash Release states.
    for a in amd64 arm64; do
        for f in Packages Packages.gz; do
            want="$(awk -v f="main/binary-$a/$f" '/^SHA256:/ { on = 1; next } /^[A-Za-z]/ { on = 0 } on && $3 == f { print $1 }' "$d/Release")"
            [[ -n "$want" && "$want" == "$(sha256sum "$d/main/binary-$a/$f" | cut -d' ' -f1)" ]] ||
                { echo "build-pkg-repo: FAIL: $s main/binary-$a/$f hash not in Release" >&2; exit 1; }
        done
    done
done
for a in x86_64 aarch64; do
    gpgv --keyring "$kr" "$rpmdir/$a/repodata/repomd.xml.asc" "$rpmdir/$a/repodata/repomd.xml" >/dev/null 2>&1 ||
        { echo "build-pkg-repo: FAIL: rpm/$a repomd.xml.asc does not verify" >&2; exit 1; }
done
rpmdb="$work/rpmdb"
mkdir -p "$rpmdb"
rpm --dbpath "$rpmdb" --import "$out/robodr-archive-keyring.asc"
for f in "$rpmdir"/*/*.rpm; do
    o="$(rpm --dbpath "$rpmdb" -K "$f" 2>&1)"
    [[ "$o" == *"signatures OK"* ]] || { echo "build-pkg-repo: FAIL: rpm -K $(basename "$f"): $o" >&2; exit 1; }
done
(cd "$out" && find . -type f -printf '%P\n' | LC_ALL=C sort | xargs -r -d '\n' sha256sum >"$work/sums" && mv "$work/sums" REPO-SHA256SUMS)
echo "build-pkg-repo: apt (stable, focal) and dnf (x86_64, aarch64) repositories written and verified in $out (key $key)" >&2
