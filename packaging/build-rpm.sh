#!/usr/bin/env bash
# Build the robodr RPM (RHEL 9 / Rocky / Alma 9, Fedora) from built binaries.
#
#   packaging/build-rpm.sh --bin-dir target/release --arch amd64 [--out dist]
#
# The binaries come from the oldest supported RPM userland (Rocky Linux 9:
# glibc 2.34, OpenSSL 3, SQLite 3.34; release.yml / ci.yml build them in a
# rockylinux:9 container), so the package installs on RHEL 9 and everything
# newer. The file tree is build-deb.sh's (--stage-only): the same units,
# tmpfiles/sysusers fragments, man pages, docs, examples, rules and file
# modes as the robodr .deb, all root:root; only the binaries differ (built
# against another glibc). scripts/check-packages.py compares the two.
# The .deb's conffiles become %config(noreplace). The scriptlets
# (packaging/rpm/{post,preun,postun}) are the counterparts of the deb
# maintainer scripts. Only the standard `robodr` package exists as an RPM:
# robodr-focal is for systemd 245, which no supported RPM distribution has.
#
# Requires: systemd >= 247 plus rpm's generated ELF dependencies
# (libc.so.6(GLIBC_x.y)(64bit), libgcc_s.so.1, libsqlite3.so.0,
# libssl.so.3 / libcrypto.so.3 with their symbol versions): the RPM
# counterpart of build-deb.sh's soname table and dpkg-shlibdeps.
#
# Packager: RPM_PACKAGER, else DEB_MAINTAINER, else a development
# placeholder (robodr-maintainers@invalid); with ROBODR_RELEASE=1 (release.yml)
# a placeholder or malformed value fails the build (exit 2).
# Binaries: as build-deb.sh (same required and optional set; ROBODR_DEB_REQUIRE
# applies here too, so a release RPM cannot silently lack a daemon).
# Versions: upstream VERSION with "-" -> "~" (pre-releases sort first, as in
# the .deb), Release 1. Architectures: amd64 -> x86_64, arm64 -> aarch64.
# Reproducible: SOURCE_DATE_EPOCH (default: the HEAD commit time, as
# build-deb.sh) clamps every mtime and sets the build time; the build host
# is recorded as "reproducible".
#
# Needs rpmbuild (Fedora/RHEL: rpm-build; Ubuntu: rpm) and readelf. Prints
# the path of the .rpm on stdout.
#
# Signing: release.yml signs the .rpm with minisign like every other asset
# (docs/RELEASE.md). An OpenPGP signature inside the RPM (rpmsign --addsign,
# needed for a dnf repository with gpgcheck) is a release-key decision not
# taken yet (docs/RELEASE.md section 5).
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
    *) echo "build-rpm: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ -n "$bin_dir" && -n "$arch" ]] || { echo "build-rpm: --bin-dir and --arch are required" >&2; exit 2; }
command -v rpmbuild >/dev/null || { echo "build-rpm: rpmbuild not found" >&2; exit 2; }
case "$arch" in
amd64) rpm_arch=x86_64 ;;
arm64) rpm_arch=aarch64 ;;
*) echo "build-rpm: unsupported architecture $arch" >&2; exit 2 ;;
esac
upstream="$(tr -d '[:space:]' <"$root/VERSION")"
rpm_version="${upstream/-/\~}"
rpm_release=1
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH

# Packager: RPM_PACKAGER, else DEB_MAINTAINER (one maintainer for both
# formats), else the development placeholder; a release (ROBODR_RELEASE=1)
# refuses the placeholder (packaging/release-maintainer.sh).
packager="${RPM_PACKAGER:-${DEB_MAINTAINER:-RoboDR maintainers <robodr-maintainers@invalid>}}"
# shellcheck source=packaging/release-maintainer.sh
. "$here/release-maintainer.sh"
check_release_maintainer "$packager" "RPM_PACKAGER (or DEB_MAINTAINER)" build-rpm
case "$packager" in *%*) echo "build-rpm: the packager contains '%' (rpm macro expansion)" >&2; exit 2 ;; esac

mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
payload="$work/payload"
mkdir -p "$work/top"/{BUILD,RPMS,SPECS,SRPMS,SOURCES,BUILDROOT}
"$here/build-deb.sh" --bin-dir "$bin_dir" --arch "$arch" --stage-only "$payload"
conffiles_list="$payload.conffiles"

# rpm macro / glob characters in a path or a scriptlet would be expanded.
if (cd "$payload" && find . | grep -q '[][*?%{}" \\]'); then
    echo "build-rpm: a payload path contains a character rpm would expand" >&2
    exit 1
fi
for s in post preun postun; do
    if grep -q '%' "$here/rpm/$s"; then
        echo "build-rpm: packaging/rpm/$s contains '%' (rpm macro expansion)" >&2
        exit 1
    fi
done

# Nothing in the payload may be setuid/setgid or group/other writable; the
# .deb is built that way (build-deb.sh), this keeps it true for the RPM.
if [[ -n "$(find "$payload" \( -perm /6000 -o -perm /022 \) ! -type l -print -quit)" ]]; then
    echo "build-rpm: setuid/setgid or group/other-writable entry in the payload:" >&2
    find "$payload" \( -perm /6000 -o -perm /022 \) ! -type l >&2
    exit 1
fi

# %files: every file and link; the directories RoboDR owns (a path
# component named robodr*) with %dir. System directories (/usr/bin,
# /usr/lib/systemd/system, ...) belong to the filesystem and systemd
# packages and are not claimed. /etc/robodr keeps its 0750; tmpfiles gives
# it group robodr at install and boot, so rpm -V does not check its group.
conffiles=" $(tr '\n' ' ' <"$conffiles_list") "
files="$work/files"
: >"$files"
while IFS= read -r p; do
    path="/${p#./}"
    [[ "$path" == / ]] && continue
    mode="$(stat -c %a "$payload$path")"
    if [[ -d "$payload$path" && ! -L "$payload$path" ]]; then
        case "$path" in
        /etc/robodr) echo "%dir %attr($mode,root,root) %verify(not group) $path" >>"$files" ;;
        */robodr | */robodr/* | */robodr-*) echo "%dir %attr($mode,root,root) $path" >>"$files" ;;
        *) ;;
        esac
    elif [[ "$conffiles" == *" $path "* ]]; then
        echo "%config(noreplace) %attr($mode,root,root) $path" >>"$files"
    elif [[ "$path" == /usr/share/doc/robodr/copyright || "$path" == /usr/share/doc/robodr/licenses/* ||
        "$path" == /usr/share/doc/robodr/THIRD_PARTY_NOTICES || "$path" == /usr/share/doc/robodr/GPL-2.0-SOURCE-OFFER ]]; then
        # %license, not %doc: installed even with tsflags=nodocs.
        echo "%license %attr($mode,root,root) $path" >>"$files"
    elif [[ -L "$payload$path" ]]; then
        echo "$path" >>"$files"
    else
        echo "%attr($mode,root,root) $path" >>"$files"
    fi
done < <(cd "$payload" && find . | LC_ALL=C sort)

synopsis="RoboDR - Robot Detection & Response (protective only)"
spec="$work/top/SPECS/robodr.spec"
awk -v payload="$payload" -v version="$rpm_version" -v release="$rpm_release" \
    -v synopsis="$synopsis" -v post="$here/rpm/post" -v preun="$here/rpm/preun" \
    -v postun="$here/rpm/postun" -v files="$files" -v packager="$packager" '
    function slurp(f,   line) { while ((getline line < f) > 0) { if (line !~ /^#!/) print line } close(f) }
    /^@POST@$/ { slurp(post); next }
    /^@PREUN@$/ { slurp(preun); next }
    /^@POSTUN@$/ { slurp(postun); next }
    /^@FILES@$/ { while ((getline line < files) > 0) print line; close(files); next }
    { gsub(/@PAYLOAD@/, payload); gsub(/@VERSION@/, version); gsub(/@RELEASE@/, release)
      s = synopsis; gsub(/&/, "\\\\&", s); gsub(/@SYNOPSIS@/, s)
      k = packager; gsub(/&/, "\\\\&", k); gsub(/@PACKAGER@/, k); print }
' "$here/rpm/robodr.spec.in" >"$spec"

rpmbuild -bb --target "$rpm_arch" \
    --define "_topdir $work/top" \
    --define "_rpmdir $work/top/RPMS" \
    --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
    "$spec" >"$work/rpmbuild.log" 2>&1 || { cat "$work/rpmbuild.log" >&2; exit 1; }
grep -E '^(Requires|Provides|Wrote):' "$work/rpmbuild.log" >&2 || true
rpm_file="$work/top/RPMS/robodr-$rpm_version-$rpm_release.$rpm_arch.rpm"
[[ -f "$rpm_file" ]] || { cat "$work/rpmbuild.log" >&2; echo "build-rpm: $rpm_file not written" >&2; exit 1; }
install -m 0644 "$rpm_file" "$out/"
echo "$out/$(basename "$rpm_file")"
