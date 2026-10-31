#!/usr/bin/env bash
# Assemble the robodr .deb from already-built release binaries.
#
#   packaging/build-deb.sh --bin-dir target/release --arch amd64 [--out dist]
#   packaging/build-deb.sh --variant focal --bin-dir dist/static/aarch64-unknown-linux-musl --arch arm64
#   packaging/build-deb.sh --bin-dir target/release --arch amd64 --stage-only DIR
#       (only the file tree into DIR and the conffiles list into DIR.conffiles,
#       no .deb: packaging/build-rpm.sh builds the RPM from it)
#
# Variants:
#   standard (default) package "robodr": glibc binaries (libc6 floor read
#            from them, at least 2.35), systemd >= 247 units (LoadCredential=,
#            ProtectProc=), robodr-pulsard and its rules when built.
#   focal    package "robodr-focal": for systemd 245 / glibc 2.31 hosts
#            (Ubuntu 20.04, NVIDIA JetPack 5 on Unitree EDU computers). Every
#            binary must be STATIC (scripts/build-static.sh, musl): no
#            program interpreter, no shared library, hence no libc6
#            dependency. Units from packaging/systemd/focal/ (LoadCredential=
#            replaced by /usr/lib/robodr/robodr-load-credential, kept in step
#            by scripts/check-focal-units.py). No robodr-pulsard (needs a BTF
#            kernel; JetPack 5 has none) and no robodr-anchor-receiver
#            (base-station role: use the standard package there). The two
#            packages conflict with (and replace) each other.
#
# Reproducible: every file mtime is SOURCE_DATE_EPOCH (default: HEAD commit
# time), ownership is root:root (--root-owner-group), modes are normalised,
# and dpkg-deb itself honours SOURCE_DATE_EPOCH. Same inputs -> same .deb.
#
# Binaries (taken from --bin-dir when present):
#   required: robodr-commission robodr-replay robodr-ros2-watch
#   optional: robodr-pulsard (Pulsar-bound; needs the clang/eBPF toolchain)
#             robodr-agentd, robodr-blackbox, robodr-diode-pack,
#             robodr-diode-unpack, robodr-spool-export,
#             robodr-kafka-publish, robodr-uplink (pure crates; the release
#             requires them)
#             robodr-anchor-receiver (pure; base-station side of the remote
#             head anchor, installed with its unit when built)
#             robodr-firewall-gw (pure; in-path inline-bridge gateway for
#             a sensor box, installed with its two units, never enabled)
#             robodr-enroll (pure; fleet enrollment, key rotation, SOC
#             profiles; usr/sbin, root-only tool, no unit)
#             robodr-deliverd (pure; on-unit delivery agent, usr/sbin, with
#             its unit, installed disabled; robodr-safety-replay, the test
#             tool of the same crate, is never packaged)
#             robodr-seal (pure; sealing: TPM provisioning, enrolment,
#             signed PCR policies, runtime volume, crypto-erase; usr/sbin,
#             root-only tool, no unit)
#             robodr-depot (pure; the site depot, Sprint 14a: operator
#             commands and the mutual-TLS LAN server, usr/sbin, with its
#             unit (User=robodr-depot), installed disabled; for the depot
#             box, never enabled on a robot)
# A unit file is only installed together with its binary. ROBODR_DEB_REQUIRE
# (space separated) makes optional binaries mandatory; the release workflow
# sets it so a release can never silently ship without the daemon.
#
# Environment:
#   SOURCE_DATE_EPOCH   timestamp for every file
#   DEB_DEPENDS         Depends: field of the standard variant, replacing the
#                       computed one (below); for experiments only
#   DEB_SHLIBDEPS       auto (default): Depends from dpkg-shlibdeps when it is
#                       installed and --arch is the build host's dpkg
#                       architecture (the release builds in its oldest
#                       supported userland, Ubuntu 22.04, so the versions are
#                       the ones that userland's libraries declare); 0: the
#                       readelf fallback only. Either way every DT_NEEDED
#                       soname must be in the soname -> package table below
#                       (an unknown library fails the build), and the libc6
#                       floor is at least the newest GLIBC_x.y version need
#                       of any packaged binary (readelf -V) and at least 2.35
#                       (the oldest supported userland).
#   DEB_MAINTAINER      Maintainer: field (default: a robodr-maintainers@invalid
#                       placeholder, for development builds only)
#   ROBODR_RELEASE      1: a release build (release.yml sets it): DEB_MAINTAINER
#                       must be "Name <address>" with a real address (not
#                       .invalid / example.* / localhost, RFC 2606), else exit 2
#   ROBODR_DEB_REQUIRE  extra binaries that must be present
set -euo pipefail
# Files created by redirection (man pages, pulsar.toml) take their mode from
# the umask: a build under umask 000 (seen in a container) must not ship
# group/other-writable files.
umask 022

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

bin_dir=""
arch=""
out="dist"
variant="standard"
stage_only=""
while [[ $# -gt 0 ]]; do
    case "$1" in
    --variant) variant="$2"; shift 2 ;;
    --bin-dir) bin_dir="$2"; shift 2 ;;
    --arch) arch="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --stage-only) stage_only="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "build-deb: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ -n "$bin_dir" && -n "$arch" ]] || { echo "build-deb: --bin-dir and --arch are required" >&2; exit 2; }
[[ -d "$bin_dir" ]] || { echo "build-deb: $bin_dir is not a directory" >&2; exit 2; }
case "$arch" in amd64 | arm64) ;; *) echo "build-deb: unsupported arch $arch" >&2; exit 2 ;; esac
case "$variant" in
standard)
    package=robodr
    other_package=robodr-focal
    unit_src="$here/systemd"
    synopsis="RoboDR - Robot Detection \& Response (protective only)"
    ;;
focal)
    package=robodr-focal
    other_package=robodr
    unit_src="$here/systemd/focal"
    synopsis="RoboDR - Robot Detection \& Response, static build for systemd 245 (protective only)"
    for b in robodr-pulsard robodr-anchor-receiver; do
        if [[ " ${ROBODR_DEB_REQUIRE:-} " == *" $b "* ]]; then
            echo "build-deb: $b is not part of the focal variant (ROBODR_DEB_REQUIRE)" >&2
            exit 2
        fi
    done
    ;;
*) echo "build-deb: unknown variant '$variant' (standard | focal)" >&2; exit 2 ;;
esac
if [[ -z "$stage_only" ]]; then
    command -v dpkg-deb >/dev/null || { echo "build-deb: dpkg-deb not found" >&2; exit 2; }
fi

upstream="$(tr -d '[:space:]' <"$root/VERSION")"
# Debian ordering: a pre-release sorts before the release with "~".
deb_version="${upstream/-/\~}-1"
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
# The libc6 floor of the standard variant: the oldest supported userland
# (Ubuntu 22.04, glibc 2.35), raised below to the newest GLIBC_x.y version
# need of any packaged binary and to what dpkg-shlibdeps reports.
libc_floor=2.35
maintainer="${DEB_MAINTAINER:-RoboDR maintainers <robodr-maintainers@invalid>}"
# shellcheck source=packaging/release-maintainer.sh
. "$here/release-maintainer.sh"
# (--stage-only has no Maintainer field: build-rpm.sh checks its Packager.)
[[ -n "$stage_only" ]] || check_release_maintainer "$maintainer" DEB_MAINTAINER build-deb

if [[ -z "$stage_only" ]]; then
    mkdir -p "$out"
    out="$(cd "$out" && pwd)"
fi
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkg="$stage/${package}_${deb_version}_${arch}"
mkdir -p "$pkg/DEBIAN"

# ELF e_machine (little-endian u16 at offset 18) each binary must carry, so an
# amd64 build tree can never be packaged as arm64 (or the reverse), e.g. a
# cross build that passes target/release instead of target/<triple>/release.
case "$arch" in amd64) want_machine=62 ;; arm64) want_machine=183 ;; esac
elf_machine() {
    od -An -tu2 -j18 -N2 "$1" | tr -d '[:space:]'
}

install_bin() { # name dest-dir required(0/1)
    local name="$1" dest="$2" required="$3"
    if [[ -x "$bin_dir/$name" ]]; then
        if [[ "$(head -c4 "$bin_dir/$name" | od -An -tx1 | tr -d '[:space:]')" != 7f454c46 ||
            "$(elf_machine "$bin_dir/$name")" != "$want_machine" ]]; then
            echo "build-deb: $bin_dir/$name is not an ELF binary for $arch (e_machine $(elf_machine "$bin_dir/$name"), want $want_machine)" >&2
            exit 1
        fi
        install -D -m 0755 "$bin_dir/$name" "$pkg/$dest/$name"
        echo "build-deb: + $dest/$name" >&2
        return 0
    fi
    if [[ "$required" == 1 || " ${ROBODR_DEB_REQUIRE:-} " == *" $name "* ]]; then
        echo "build-deb: required binary $bin_dir/$name is missing" >&2
        exit 1
    fi
    echo "build-deb: - $name not built, skipped" >&2
    return 1
}

# A unit drop-in example, installed under the examples: the focal variant's
# own version (packaging/systemd/focal/<unit>.service.d/<file>) when there is
# one, otherwise the regular file, which scripts/check-focal-units.py then
# requires to use nothing newer than systemd 245.
install_dropin() { # <unit>.service.d/<file>
    local src="$here/systemd/$1"
    if [[ "$variant" == focal && -f "$here/systemd/focal/$1" ]]; then
        src="$here/systemd/focal/$1"
    fi
    install -D -m 0644 "$src" "$pkg/usr/share/doc/robodr/examples/$1"
}

for b in robodr-commission robodr-replay robodr-ros2-watch; do
    install_bin "$b" usr/bin 1
done
for b in robodr-blackbox robodr-diode-pack robodr-diode-unpack; do
    install_bin "$b" usr/bin 0 || true
done

units=usr/lib/systemd/system
ex=usr/share/doc/robodr/examples
# Exporters: robot side (diode), connected-site Kafka publisher and ingest
# API uplink, each with its unit, installed disabled. The units conflict
# (one consumer per spool).
if install_bin robodr-spool-export usr/bin 0; then
    install -D -m 0644 "$unit_src/robodr-spool-export.service" "$pkg/$units/robodr-spool-export.service"
    install -D -m 0644 "$here/etc/spool-export.env.example" "$pkg/$ex/spool-export.env.example"
fi
if install_bin robodr-kafka-publish usr/bin 0; then
    install -D -m 0644 "$unit_src/robodr-kafka-publish.service" "$pkg/$units/robodr-kafka-publish.service"
    install -D -m 0644 "$here/etc/kafka-publish.env.example" "$pkg/$ex/kafka-publish.env.example"
    install_dropin robodr-kafka-publish.service.d/50-brokers.conf.example
    install_dropin robodr-kafka-publish.service.d/60-tls-credentials.conf.example
fi
# Ingest API uplink (connected sites; conflicts with both units above).
if install_bin robodr-uplink usr/bin 0; then
    install -D -m 0644 "$unit_src/robodr-uplink.service" "$pkg/$units/robodr-uplink.service"
    install -D -m 0644 "$here/etc/uplink.env.example" "$pkg/$ex/uplink.env.example"
    install_dropin robodr-uplink.service.d/50-soc.conf.example
fi
if [[ "$variant" == focal ]]; then
    for b in robodr-pulsard robodr-anchor-receiver; do
        if [[ -e "$bin_dir/$b" ]]; then
            echo "build-deb: - $b is not part of the focal variant, skipped" >&2
        fi
    done
    # LoadCredential= stand-in for systemd 245 (packaging/focal/).
    install -D -m 0755 "$here/focal/robodr-load-credential" "$pkg/usr/lib/robodr/robodr-load-credential"
elif install_bin robodr-pulsard usr/sbin 0; then
    install -D -m 0644 "$here/systemd/robodr-pulsard.service" "$pkg/$units/robodr-pulsard.service"
    # External-BTF guard of the unit (kernels without BTF, docs/UNITREE.md 3.2.1).
    install -D -m 0755 "$here/btf/robodr-btf-check" "$pkg/usr/lib/robodr/robodr-btf-check"
    install_dropin robodr-pulsard.service.d/10-cap-sys-admin.conf.example
    install_dropin robodr-pulsard.service.d/30-host-threats.conf.example
    # Default config: base header + the RoboDR sensor sections (a conffile).
    install -d -m 0750 "$pkg/etc/robodr"
    cat "$here/etc/pulsar.base.toml" "$root/config/robodr.toml.example" >"$pkg/etc/robodr/pulsar.toml"
    chmod 0640 "$pkg/etc/robodr/pulsar.toml"
    # Rules: RoboDR's and Pulsar's upstream set (both CI-validated).
    install -d "$pkg/usr/share/robodr/rules/robodr" "$pkg/usr/share/robodr/rules/pulsar"
    cp -R "$root/rules/robodr/." "$pkg/usr/share/robodr/rules/robodr/"
    if [[ -d "$root/vendor/pulsar/rules" ]] && [[ -n "$(ls -A "$root/vendor/pulsar/rules")" ]]; then
        cp -R "$root/vendor/pulsar/rules/." "$pkg/usr/share/robodr/rules/pulsar/"
    else
        echo "build-deb: WARNING: vendor/pulsar/rules missing (submodule not checked out?); shipping RoboDR rules only" >&2
        rmdir "$pkg/usr/share/robodr/rules/pulsar"
    fi
    find "$pkg/usr/share/robodr/rules" -type f -exec chmod 0644 {} +
fi
if install_bin robodr-agentd usr/sbin 0; then
    install -D -m 0644 "$unit_src/robodr-agentd.service" "$pkg/$units/robodr-agentd.service"
    install_dropin robodr-agentd.service.d/20-finding-key.conf.example
    install_dropin robodr-agentd.service.d/30-control-plane.conf.example
    # Passive sensor box (tap / port mirror; docs/UNITREE.md): agentd drop-in,
    # capture-NIC networkd file and host firewall. Examples, never active.
    install_dropin robodr-agentd.service.d/40-sensor-box.conf.example
    for f in 10-robodr-capture.network.example nftables.conf.example; do
        install -D -m 0644 "$here/sensor-box/$f" "$pkg/usr/share/doc/robodr/examples/sensor-box/$f"
    done
fi
# executor v1 (off unless agentd's executor.enabled; not enabled by the
# package): with robodr-firewall-gw, the only CAP_NET_ADMIN units; plus
# agentd's key drop-in example.
if install_bin robodr-executor usr/sbin 0; then
    install -D -m 0644 "$unit_src/robodr-executor.service" "$pkg/$units/robodr-executor.service"
    install_dropin robodr-agentd.service.d/30-executor.conf.example
    install -D -m 0644 "$root/config/executor.example.json" "$pkg/$ex/executor.example.json"
    # Sprint 8 motion adapters: example configuration and unit drop-in.
    install -D -m 0644 "$root/config/executor.motion.example.json" \
        "$pkg/$ex/executor.motion.example.json"
    install_dropin robodr-executor.service.d/40-motion.conf.example
fi
# In-path Motion Firewall gateway (inline bridge on a sensor box,
# crates/robodr-firewall-gw): the gateway and its ruleset unit, installed
# disabled (enforcing must follow commissioning; OPERATIONS.md 6.6).
if install_bin robodr-firewall-gw usr/sbin 0; then
    for u in robodr-firewall-gw.service robodr-firewall-gw-rules.service; do
        install -D -m 0644 "$unit_src/$u" "$pkg/$units/$u"
    done
    install -D -m 0644 "$root/config/firewall-gw.ros2-arm.example.json" \
        "$pkg/$ex/firewall-gw.ros2-arm.example.json"
fi
# Base-station side of the remote head anchor (not enabled by the package).
if [[ "$variant" == standard ]] && install_bin robodr-anchor-receiver usr/bin 0; then
    install -D -m 0644 "$here/systemd/robodr-anchor-receiver.service" \
        "$pkg/$units/robodr-anchor-receiver.service"
fi

# On-unit delivery agent (Sprint 13b, docs/SECURE-DELIVERY.md): installed
# disabled; enabled after commissioning and enrolment (init-anchor).
if install_bin robodr-deliverd usr/sbin 0; then
    install -D -m 0644 "$unit_src/robodr-deliverd.service" "$pkg/$units/robodr-deliverd.service"
    install -D -m 0644 "$here/systemd/robodr-deliverd.service.d/50-depot-lan.conf.example" \
        "$pkg/$ex/robodr-deliverd.service.d/50-depot-lan.conf.example"
fi
# Sealing (Sprint 13c, docs/SECURE-DELIVERY.md 7.9): the operator's tool for
# the unit's TPM and runtime volume (OPERATIONS.md section 12); root-only.
install_bin robodr-seal usr/sbin 0 || true
# The site depot (Sprint 14a, docs/SECURE-DELIVERY.md 4-6, 8): installed
# disabled, for the depot box (OPERATIONS.md section 13).
# (config/depot.example.json goes to the examples with the other configs.)
if install_bin robodr-depot usr/sbin 0; then
    install -D -m 0644 "$unit_src/robodr-depot.service" "$pkg/$units/robodr-depot.service"
    install -D -m 0644 "$here/systemd/robodr-depot.service.d/50-tpm-anchor.conf.example" \
        "$pkg/$ex/robodr-depot.service.d/50-tpm-anchor.conf.example"
fi
# Fleet lifecycle (Sprint 9): robodr-enroll and its configuration example.
# (config/fleet.example.json goes to the examples with the other configs.)
install_bin robodr-enroll usr/sbin 0 || true
# A trusted copy of the bundle installer for the next upgrade: it verifies a
# new tarball's signature and installs from a private extraction
# (OPERATIONS.md section 3; never run the copy inside an unverified bundle).
install -D -m 0755 "$here/install-bundle.sh" "$pkg/usr/lib/robodr/install-bundle.sh"
# On-disk formats this release writes and reads (install-bundle.sh's
# black-box format gate on install and rollback).
install -D -m 0644 "$here/formats" "$pkg/usr/share/robodr/formats"

install -D -m 0644 "$here/tmpfiles.d/robodr.conf" "$pkg/usr/lib/tmpfiles.d/robodr.conf"
install -D -m 0644 "$here/sysusers.d/robodr.conf" "$pkg/usr/lib/sysusers.d/robodr.conf"

# Man pages, only for binaries that are in the package.
for page in "$root"/man/*.[1-8]; do
    [[ -e "$page" ]] || continue
    name="$(basename "$page")"
    cmd="${name%.*}"
    sec="${name##*.}"
    if [[ -e "$pkg/usr/bin/$cmd" || -e "$pkg/usr/sbin/$cmd" ]]; then
        install -d "$pkg/usr/share/man/man$sec"
        gzip -9 -n -c "$page" >"$pkg/usr/share/man/man$sec/$name.gz"
        chmod 0644 "$pkg/usr/share/man/man$sec/$name.gz"
    fi
done

doc="$pkg/usr/share/doc/robodr"
install -d "$doc/examples"
for f in docs/OPERATIONS.md docs/UNITREE.md docs/DECOMMISSION.md SECURITY.md CHANGELOG.md README.md packaging/README.md; do
    [[ -f "$root/$f" ]] || continue
    case "$f" in
    packaging/README.md) install -m 0644 "$root/$f" "$doc/PACKAGING.md" ;;
    *) install -m 0644 "$root/$f" "$doc/$(basename "$f")" ;;
    esac
done
# The control-plane contract (man robodr-agentd(8) points here).
install -D -m 0644 "$root/docs/contracts/robodr.control-plane.md" \
    "$doc/contracts/robodr.control-plane.md"
# The delivery design (man robodr-deliverd(8) points here), when the agent is in.
if [[ -e "$pkg/usr/sbin/robodr-deliverd" || -e "$pkg/usr/sbin/robodr-depot" ]]; then
    install -D -m 0644 "$root/docs/SECURE-DELIVERY.md" "$doc/SECURE-DELIVERY.md"
fi
# The fleet contract (man robodr-enroll(8) points here), when the tool is in.
if [[ -e "$pkg/usr/sbin/robodr-enroll" ]]; then
    install -D -m 0644 "$root/docs/contracts/robodr.fleet-api.md" \
        "$doc/contracts/robodr.fleet-api.md"
fi
install -m 0644 "$root/LICENSE" "$doc/copyright"
# Third-party notices and the Pulsar eBPF GPL-2.0 source offer: committed,
# generated by scripts/third_party_notices.py (CI job deny checks they match
# Cargo.lock and the Pulsar commit). A package without them is not shipped.
for f in THIRD_PARTY_NOTICES GPL-2.0-SOURCE-OFFER; do
    [[ -s "$root/$f" ]] || { echo "build-deb: $f missing (python3 scripts/third_party_notices.py)" >&2; exit 1; }
    install -m 0644 "$root/$f" "$doc/$f"
done
install -d "$doc/licenses"
for f in "$root"/LICENSES/*; do
    install -m 0644 "$f" "$doc/licenses/"
done
for f in "$root"/config/*.example*; do
    install -m 0644 "$f" "$doc/examples/"
done

# Maintainer scripts and metadata.
for s in postinst prerm postrm; do
    install -m 0755 "$here/deb/$s" "$pkg/DEBIAN/$s"
done
if [[ -f "$pkg/etc/robodr/pulsar.toml" ]]; then
    echo /etc/robodr/pulsar.toml >"$pkg/DEBIAN/conffiles"
fi

# Normalise: directories 0755 except /etc/robodr (0750: tmpfiles sets the
# group), regular files keep the modes set above.
find "$pkg" -type d -exec chmod 0755 {} +
[[ -d "$pkg/etc/robodr" ]] && chmod 0750 "$pkg/etc/robodr"

# --stage-only DIR (packaging/build-rpm.sh): the package's file tree, exactly
# as the .deb would carry it, plus conffiles (the list the RPM turns into
# %config(noreplace)); no Depends, no control data, no dpkg-deb.
if [[ -n "$stage_only" ]]; then
    if [[ -e "$stage_only" && -n "$(ls -A "$stage_only" 2>/dev/null)" ]]; then
        echo "build-deb: --stage-only $stage_only exists and is not empty" >&2
        exit 2
    fi
    mkdir -p "$stage_only"
    touch "$pkg/DEBIAN/conffiles"
    install -m 0644 "$pkg/DEBIAN/conffiles" "$stage_only.conffiles"
    rm -rf "$pkg/DEBIAN"
    find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    cp -a "$pkg/." "$stage_only/"
    echo "build-deb: staged $package ($variant, $arch) in $stage_only" >&2
    exit 0
fi

# soname -> Debian package, for every shared library a packaged binary may
# link (DT_NEEDED). Package names exist in Debian 12/13 and Ubuntu
# 22.04/24.04 (on the 64-bit-time_t distributions libssl3t64 provides
# libssl3). A soname missing here fails the build: add the library
# deliberately, with its RPM counterpart in packaging/build-rpm.sh's
# documentation (RPM generates its Requires from the same ELF data).
soname_package() {
    case "$1" in
    libc.so.6 | libm.so.6 | libpthread.so.0 | libdl.so.2 | librt.so.1 | libutil.so.1 | \
        ld-linux-x86-64.so.2 | ld-linux-aarch64.so.1) echo libc6 ;;
    libgcc_s.so.1) echo libgcc-s1 ;;
    libsqlite3.so.0) echo libsqlite3-0 ;;
    libssl.so.3 | libcrypto.so.3) echo libssl3 ;;
    *) return 1 ;;
    esac
}

# Depends: of the standard variant, printed on stdout: one entry per
# package the binaries' DT_NEEDED sonames map to, versioned by
# dpkg-shlibdeps where it can run (native architecture), the libc6 floor
# raised to the binaries' GLIBC_x.y needs, then systemd (>= 247) for the
# units (LoadCredential=, ProtectProc=).
standard_depends() {
    command -v readelf >/dev/null || { echo "build-deb: readelf (binutils) not found; needed for Depends (or set DEB_DEPENDS)" >&2; exit 2; }
    local bins=() f so pkgname need floor shl="" host_arch="" deps=() d
    while IFS= read -r f; do
        if [[ "$(head -c4 "$f" | od -An -tx1 | tr -d '[:space:]')" == 7f454c46 ]]; then
            bins+=("$f")
        fi
    done < <(find "$pkg/usr/bin" "$pkg/usr/sbin" -type f 2>/dev/null | LC_ALL=C sort)
    [[ ${#bins[@]} -gt 0 ]] || { echo "build-deb: no ELF binaries staged" >&2; exit 1; }
    # Packages from DT_NEEDED (sorted, unique).
    local pkgs=()
    while IFS= read -r so; do
        [[ -n "$so" ]] || continue
        if ! pkgname="$(soname_package "$so")"; then
            echo "build-deb: a packaged binary needs $so, which has no package mapping (soname_package in build-deb.sh)" >&2
            exit 1
        fi
        pkgs+=("$pkgname")
    done < <(for f in "${bins[@]}"; do readelf -dW "$f" 2>/dev/null; done |
        sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' | LC_ALL=C sort -u)
    mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | LC_ALL=C sort -u)
    # GLIBC_x.y version needs (weak references still carry a hard version
    # need: Rust std's pidfd_spawnp@GLIBC_2.39 on a 2.39 build host).
    need="$(printf '%s\0' "${bins[@]}" | xargs -0 readelf -V --wide 2>/dev/null |
        sed -n 's/.*Name: GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -uV | tail -n1)"
    floor="$libc_floor"
    [[ -z "$need" ]] || floor="$(printf '%s\n%s\n' "$floor" "$need" | sort -V | tail -n1)"
    # dpkg-shlibdeps: versions from the build userland's shlibs/symbols files.
    command -v dpkg >/dev/null && host_arch="$(dpkg --print-architecture 2>/dev/null || true)"
    if [[ "${DEB_SHLIBDEPS:-auto}" != 0 ]] && command -v dpkg-shlibdeps >/dev/null && [[ "$host_arch" == "$arch" ]]; then
        local sd
        sd="$(mktemp -d)"
        mkdir -p "$sd/debian"
        : >"$sd/debian/control"
        if ! shl="$(cd "$sd" && dpkg-shlibdeps -O "${bins[@]}" 2>"$sd/err")"; then
            cat "$sd/err" >&2
            rm -rf "$sd"
            echo "build-deb: dpkg-shlibdeps failed (DEB_SHLIBDEPS=0 to use the readelf fallback)" >&2
            exit 1
        fi
        rm -rf "$sd"
        shl="${shl#shlibs:Depends=}"
        echo "build-deb: dpkg-shlibdeps ($host_arch): $shl" >&2
    else
        echo "build-deb: dpkg-shlibdeps not used (host ${host_arch:-?}, package $arch); unversioned library dependencies, libc6 floor from readelf" >&2
    fi
    for p in "${pkgs[@]}"; do
        d="$p"
        if [[ -n "$shl" ]]; then
            # The shlibdeps entry of this package, e.g. "libssl3 (>= 3.0.0)".
            local e
            e="$(printf '%s\n' "$shl" | tr ',' '\n' | sed 's/^ *//' | grep -E "^$p( |\$)" | head -n1 || true)"
            [[ -z "$e" ]] || d="$e"
        fi
        if [[ "$p" == libc6 ]]; then
            local v="${d#libc6 (>= }"
            v="${v%)}"
            [[ "$v" == "$d" ]] && v=0
            d="libc6 (>= $(printf '%s\n%s\n' "$floor" "$v" | sort -V | tail -n1))"
        fi
        deps+=("$d")
    done
    # shlibdeps must not know a package the soname table does not.
    if [[ -n "$shl" ]]; then
        local e base
        while IFS= read -r e; do
            e="${e# }"
            base="${e%% *}"
            [[ -n "$base" ]] || continue
            if [[ " ${pkgs[*]} " != *" $base "* ]]; then
                echo "build-deb: dpkg-shlibdeps names $base, which the soname table does not map to (soname_package)" >&2
                exit 1
            fi
        done < <(printf '%s\n' "$shl" | tr ',' '\n')
    fi
    deps+=("systemd (>= 247)")
    local IFS=,
    printf '%s\n' "${deps[*]}" | sed 's/,/, /g'
}

# libc6 floor from the binaries' version needs (readelf -V reads any ELF
# arch). Rust std references e.g. pidfd_spawnp@GLIBC_2.39 when linked on a
# glibc >= 2.39 host; the reference is weak, but its version need is not, so
# ld.so refuses to start the binary on an older glibc. A hard-coded floor
# below that would let dpkg install a package that cannot run.
if [[ "$variant" == focal ]]; then
    # Static binaries only: no PT_INTERP, no DT_NEEDED, hence no libc6 (or
    # any other library) dependency. systemd >= 245 for sysusers, tmpfiles
    # and the focal units (scripts/check-focal-units.py).
    command -v readelf >/dev/null || { echo "build-deb: readelf (binutils) not found" >&2; exit 2; }
    while IFS= read -r f; do
        if readelf -lW "$f" | grep -q 'INTERP' || readelf -dW "$f" 2>/dev/null | grep -q '(NEEDED)'; then
            echo "build-deb: ${f#"$pkg"/} is dynamically linked; the focal variant takes static binaries only (scripts/build-static.sh)" >&2
            exit 1
        fi
    done < <(find "$pkg/usr/bin" "$pkg/usr/sbin" -type f 2>/dev/null | LC_ALL=C sort)
    if [[ -n "${DEB_DEPENDS:-}" ]]; then
        echo "build-deb: DEB_DEPENDS is ignored for the focal variant" >&2
    fi
    depends="systemd (>= 245)"
    echo "build-deb: static binaries, Depends: $depends" >&2
elif [[ -n "${DEB_DEPENDS:-}" ]]; then
    depends="$DEB_DEPENDS"
    echo "build-deb: Depends from DEB_DEPENDS (not computed): $depends" >&2
else
    depends="$(standard_depends)"
    echo "build-deb: Depends: $depends" >&2
fi

installed_kb="$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)"
sed -e "s|@PACKAGE@|$package|" -e "s|@OTHER_PACKAGE@|$other_package|g" \
    -e "s|@SYNOPSIS@|$synopsis|" -e "s|@VERSION@|$deb_version|" -e "s|@ARCH@|$arch|" \
    -e "s|@MAINTAINER@|$maintainer|" -e "s|@DEPENDS@|$depends|" \
    -e "s|@INSTALLED_SIZE@|$installed_kb|" "$here/deb/control.in" >"$pkg/DEBIAN/control"
if [[ "$variant" == focal ]]; then
    # Continuation of the Description (the last field of control.in).
    cat >>"$pkg/DEBIAN/control" <<'CONTROL'
 .
 This is the robodr-focal variant for hosts with systemd 245 and glibc
 2.31 (Ubuntu 20.04, NVIDIA JetPack 5, e.g. Unitree EDU computers): static
 (musl) binaries and systemd 245 units. It does not contain robodr-pulsard
 (eBPF, needs a BTF kernel) or robodr-anchor-receiver (base station). See
 /usr/share/doc/robodr/UNITREE.md, section 3.2.
CONTROL
fi

# md5sums (dpkg --verify), sorted for determinism.
(cd "$pkg" && find . -path ./DEBIAN -prune -o -type f -print | LC_ALL=C sort |
    sed 's|^\./||' | xargs -r -d '\n' md5sum >DEBIAN/md5sums)
chmod 0644 "$pkg/DEBIAN/control" "$pkg/DEBIAN/md5sums"
[[ -f "$pkg/DEBIAN/conffiles" ]] && chmod 0644 "$pkg/DEBIAN/conffiles"

find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

deb="$out/${package}_${deb_version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >&2
echo "$deb"
