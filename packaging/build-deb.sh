#!/usr/bin/env bash
# Assemble the robodr .deb from already-built release binaries.
#
#   packaging/build-deb.sh --bin-dir target/release --arch amd64 [--out dist]
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
#             robodr-kafka-publish (pure crates; the release requires them)
#             robodr-anchor-receiver (pure; base-station side of the remote
#             head anchor, installed with its unit when built)
# A unit file is only installed together with its binary. ROBODR_DEB_REQUIRE
# (space separated) makes optional binaries mandatory; the release workflow
# sets it so a release can never silently ship without the daemon.
#
# Environment:
#   SOURCE_DATE_EPOCH   timestamp for every file
#   DEB_DEPENDS         Depends: field (default below; Rust binaries link
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
while [[ $# -gt 0 ]]; do
    case "$1" in
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
pkg="$stage/robodr_${deb_version}_${arch}"
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
for b in robodr-blackbox robodr-diode-pack robodr-diode-unpack robodr-spool-export robodr-kafka-publish; do
    install_bin "$b" usr/bin 0 || true
done

units=usr/lib/systemd/system
if install_bin robodr-pulsard usr/sbin 0; then
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
    install -D -m 0644 "$here/systemd/robodr-agentd.service" "$pkg/$units/robodr-agentd.service"
    install -D -m 0644 "$here/systemd/robodr-agentd.service.d/20-finding-key.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-agentd.service.d/20-finding-key.conf.example"
    # Passive sensor box (tap / port mirror; docs/UNITREE.md): agentd drop-in,
    # capture-NIC networkd file and host firewall. Examples, never active.
    install -D -m 0644 "$here/systemd/robodr-agentd.service.d/40-sensor-box.conf.example" \
        "$pkg/usr/share/doc/robodr/examples/robodr-agentd.service.d/40-sensor-box.conf.example"
    for f in 10-robodr-capture.network.example nftables.conf.example; do
        install -D -m 0644 "$here/sensor-box/$f" "$pkg/usr/share/doc/robodr/examples/sensor-box/$f"
    done
fi
# Base-station side of the remote head anchor (not enabled by the package).
if install_bin robodr-anchor-receiver usr/bin 0; then
    install -D -m 0644 "$here/systemd/robodr-anchor-receiver.service" \
        "$pkg/$units/robodr-anchor-receiver.service"
fi

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
if [[ -n "${DEB_DEPENDS:-}" ]]; then
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
sed -e "s|@VERSION@|$deb_version|" -e "s|@ARCH@|$arch|" \
    -e "s|@MAINTAINER@|$maintainer|" -e "s|@DEPENDS@|$depends|" \
    -e "s|@INSTALLED_SIZE@|$installed_kb|" "$here/deb/control.in" >"$pkg/DEBIAN/control"

# md5sums (dpkg --verify), sorted for determinism.
(cd "$pkg" && find . -path ./DEBIAN -prune -o -type f -print | LC_ALL=C sort |
    sed 's|^\./||' | xargs -r -d '\n' md5sum >DEBIAN/md5sums)
chmod 0644 "$pkg/DEBIAN/control" "$pkg/DEBIAN/md5sums"
[[ -f "$pkg/DEBIAN/conffiles" ]] && chmod 0644 "$pkg/DEBIAN/conffiles"

find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

deb="$out/robodr_${deb_version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >&2
echo "$deb"
