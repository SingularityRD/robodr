#!/usr/bin/env bash
# Assemble the robodr .deb from already-built release binaries.
#
#   packaging/build-deb.sh --bin-dir target/release --arch amd64 [--out dist]
#   packaging/build-deb.sh --variant focal --bin-dir dist/static/aarch64-unknown-linux-musl --arch arm64
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
# A unit file is only installed together with its binary. ROBODR_DEB_REQUIRE
# (space separated) makes optional binaries mandatory; the release workflow
# sets it so a release can never silently ship without the daemon.
#
# Environment:
#   SOURCE_DATE_EPOCH   timestamp for every file
#   DEB_DEPENDS         Depends: field of the standard variant (default below; Rust binaries link
#                       glibc + libgcc_s, robodr-pulsard also libsqlite3
#                       unless built with Pulsar's sqlite3-vendored feature;
#                       the default libc6 floor is the newest GLIBC_x.y
#                       version the packaged binaries need, at least 2.35,
#                       read with readelf)
#   DEB_MAINTAINER      Maintainer: field
#   ROBODR_DEB_REQUIRE  extra binaries that must be present
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

bin_dir=""
arch=""
out="dist"
variant="standard"
while [[ $# -gt 0 ]]; do
    case "$1" in
    --variant) variant="$2"; shift 2 ;;
    --bin-dir) bin_dir="$2"; shift 2 ;;
    --arch) arch="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
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
command -v dpkg-deb >/dev/null || { echo "build-deb: dpkg-deb not found" >&2; exit 2; }

upstream="$(tr -d '[:space:]' <"$root/VERSION")"
# Debian ordering: a pre-release sorts before the release with "~".
deb_version="${upstream/-/\~}-1"
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
# Default Depends; the libc6 floor is raised below to the newest GLIBC_x.y
# symbol version any packaged binary requires.
libc_floor=2.35
depends_rest="libgcc-s1, libsqlite3-0, systemd (>= 247)"
maintainer="${DEB_MAINTAINER:-RoboDR maintainers <robodr-maintainers@invalid>}"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
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
    install -D -m 0644 "$here/systemd/robodr-kafka-publish.service.d/50-brokers.conf.example" \
        "$pkg/$ex/robodr-kafka-publish.service.d/50-brokers.conf.example"
fi
# Ingest API uplink (connected sites; conflicts with both units above).
if install_bin robodr-uplink usr/bin 0; then
    install -D -m 0644 "$unit_src/robodr-uplink.service" "$pkg/$units/robodr-uplink.service"
    install -D -m 0644 "$here/etc/uplink.env.example" "$pkg/$ex/uplink.env.example"
    install -D -m 0644 "$here/systemd/robodr-uplink.service.d/50-soc.conf.example" \
        "$pkg/$ex/robodr-uplink.service.d/50-soc.conf.example"
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
    install -D -m 0644 "$here/systemd/robodr-pulsard.service.d/10-cap-sys-admin.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-pulsard.service.d/10-cap-sys-admin.conf.example"
    install -D -m 0644 "$here/systemd/robodr-pulsard.service.d/30-host-threats.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-pulsard.service.d/30-host-threats.conf.example"
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
    install -D -m 0644 "$unit_src/robodr-agentd.service.d/20-finding-key.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-agentd.service.d/20-finding-key.conf.example"
    install -D -m 0644 "$unit_src/robodr-agentd.service.d/30-control-plane.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-agentd.service.d/30-control-plane.conf.example"
    # Passive sensor box (tap / port mirror; docs/UNITREE.md): agentd drop-in,
    # capture-NIC networkd file and host firewall. Examples, never active.
    install -D -m 0644 "$here/systemd/robodr-agentd.service.d/40-sensor-box.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-agentd.service.d/40-sensor-box.conf.example"
    for f in 10-robodr-capture.network.example nftables.conf.example; do
        install -D -m 0644 "$here/sensor-box/$f" "$pkg/usr/share/doc/robodr/examples/sensor-box/$f"
    done
fi
# executor v1 (off unless agentd's executor.enabled; not enabled by the
# package): with robodr-firewall-gw, the only CAP_NET_ADMIN units; plus
# agentd's key drop-in example.
if install_bin robodr-executor usr/sbin 0; then
    install -D -m 0644 "$unit_src/robodr-executor.service" "$pkg/$units/robodr-executor.service"
    install -D -m 0644 "$unit_src/robodr-agentd.service.d/30-executor.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-agentd.service.d/30-executor.conf.example"
    install -D -m 0644 "$root/config/executor.example.json" "$pkg/$ex/executor.example.json"
fi
# In-path Motion Firewall gateway (inline bridge on a sensor box,
# crates/robodr-firewall-gw): the gateway and its ruleset unit, installed
# disabled (enforcing must follow commissioning; OPERATIONS.md 6.6).
if install_bin robodr-firewall-gw usr/sbin 0; then
    for u in robodr-firewall-gw.service robodr-firewall-gw-rules.service; do
        install -D -m 0644 "$unit_src/$u" "$pkg/$units/$u"
    done
fi
# Base-station side of the remote head anchor (not enabled by the package).
if [[ "$variant" == standard ]] && install_bin robodr-anchor-receiver usr/bin 0; then
    install -D -m 0644 "$here/systemd/robodr-anchor-receiver.service" \
        "$pkg/$units/robodr-anchor-receiver.service"
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
    fi
done

doc="$pkg/usr/share/doc/robodr"
install -d "$doc/examples"
for f in docs/OPERATIONS.md docs/UNITREE.md SECURITY.md CHANGELOG.md README.md packaging/README.md; do
    [[ -f "$root/$f" ]] || continue
    case "$f" in
    packaging/README.md) install -m 0644 "$root/$f" "$doc/PACKAGING.md" ;;
    *) install -m 0644 "$root/$f" "$doc/$(basename "$f")" ;;
    esac
done
# The control-plane contract (man robodr-agentd(8) points here).
install -D -m 0644 "$root/docs/contracts/robodr.control-plane.md" \
    "$doc/contracts/robodr.control-plane.md"
# The fleet contract (man robodr-enroll(8) points here), when the tool is in.
if [[ -e "$pkg/usr/sbin/robodr-enroll" ]]; then
    install -D -m 0644 "$root/docs/contracts/robodr.fleet-api.md" \
        "$doc/contracts/robodr.fleet-api.md"
fi
install -m 0644 "$root/LICENSE" "$doc/copyright"
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
else
    command -v readelf >/dev/null || { echo "build-deb: readelf (binutils) not found; needed for the libc6 floor (or set DEB_DEPENDS)" >&2; exit 2; }
    need="$(find "$pkg/usr" -type f \( -path "$pkg/usr/bin/*" -o -path "$pkg/usr/sbin/*" \) | LC_ALL=C sort |
        xargs -r readelf -V --wide 2>/dev/null | sed -n 's/.*Name: GLIBC_\([0-9][0-9.]*\).*/\1/p' |
        sort -uV | tail -n1)"
    if [[ -n "$need" ]]; then
        libc_floor="$(printf '%s\n%s\n' "$libc_floor" "$need" | sort -V | tail -n1)"
    fi
    echo "build-deb: libc6 (>= $libc_floor)" >&2
    depends="libc6 (>= $libc_floor), $depends_rest"
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
