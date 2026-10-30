# shellcheck shell=bash
# Pinned C toolchain of the release builds (docs/BUILD.md "C toolchain").
# Sourced by scripts/ci-repro.sh, scripts/build-static.sh,
# scripts/ci-install-clang.sh and release.yml; not executable on its own.
#
# The only C in the pure workspace is `ring` (rustls' crypto provider,
# robodr-uplink): its C and assembly objects are linked into the shipped
# binaries, so their bytes depend on the C compiler. Every release and
# reproducibility build compiles ring with this exact clang, for every
# target (glibc and musl, x86-64 and arm64). A missing or different clang
# FAILS the build; nothing falls back to `cc`.
#
# Changing a pin is a release-visible change: bump it here, in docs/BUILD.md
# and in the workflows (they call ci-install-clang.sh), in one commit.

# The pin depends on the build userland (VERSION_CODENAME of
# /etc/os-release, or ROBODR_BUILD_USERLAND): every pin is an exact apt
# version for amd64 and arm64 (jammy's from the release pocket, which the
# archive keeps for the life of the release; noble's is the -updates
# version, checked 2026-10-30). Besides the clang driver package, the LLVM
# libraries that hold the code generator are pinned to the same version
# (ROBODR_CLANG_APT_ALSO), since apt would otherwise take them from -updates.
#
#   noble (Ubuntu 24.04): the musl builds (robodr-focal), the CI jobs on
#          the runner itself, and any build host not listed here.
#   jammy (Ubuntu 22.04): the glibc builds of the robodr .deb: glibc 2.35
#          is the oldest Debian/Ubuntu userland the package supports
#          (docs/BUILD.md "Release build userlands").
#   rocky9 (Rocky Linux 9): the builds of the robodr .rpm (glibc 2.34,
#          the oldest RPM userland supported). Rocky's AppStream carries one
#          clang version at a time (older ones move to the vault with the
#          next point release), so this pin breaks the build when Rocky
#          moves on: bump it deliberately, like the Rust pin.
robodr_build_userland() {
    if [[ -n "${ROBODR_BUILD_USERLAND:-}" ]]; then
        printf '%s\n' "$ROBODR_BUILD_USERLAND"
    elif [[ -r /etc/os-release ]]; then
        # Debian/Ubuntu: the codename; RPM distributions have none: ID and
        # major version (rocky9).
        # shellcheck source=/dev/null
        (. /etc/os-release && if [[ -n "${VERSION_CODENAME:-}" ]]; then
            printf '%s\n' "$VERSION_CODENAME"
        else
            printf '%s%s\n' "${ID:-unknown}" "${VERSION_ID%%.*}"
        fi)
    else
        echo unknown
    fi
}
case "$(robodr_build_userland)" in
jammy)
    ROBODR_CLANG="clang-14"
    ROBODR_CLANG_VERSION="14.0.0"
    ROBODR_CLANG_APT_PACKAGE="clang-14"
    ROBODR_CLANG_APT_VERSION="1:14.0.0-1ubuntu1"
    ROBODR_CLANG_APT_ALSO="libllvm14 libclang-cpp14 libclang-common-14-dev libclang1-14 llvm-14-linker-tools"
    ROBODR_GCC_VERSION="11.4.0"
    ROBODR_BINUTILS_VERSION="2.38"
    ;;
rocky9)
    ROBODR_CLANG="clang"
    ROBODR_CLANG_VERSION="21.1.8"
    ROBODR_CLANG_APT_PACKAGE="clang"
    # An RPM version-release here (dnf install clang-<this>).
    ROBODR_CLANG_APT_VERSION="21.1.8-2.el9"
    ROBODR_CLANG_APT_ALSO="clang-libs llvm-libs"
    ROBODR_GCC_VERSION="11.5.0"
    ROBODR_BINUTILS_VERSION="2.35.2"
    ;;
*)
    # noble, and the default for any other host (unchanged behaviour).
    ROBODR_CLANG="clang-18"
    ROBODR_CLANG_VERSION="18.1.3"
    ROBODR_CLANG_APT_PACKAGE="clang-18"
    ROBODR_CLANG_APT_VERSION="1:18.1.3-1ubuntu1"
    ROBODR_CLANG_APT_ALSO="libllvm18 libclang-cpp18 libclang-common-18-dev libclang1-18 llvm-18-linker-tools"
    ROBODR_GCC_VERSION="13.3.0"
    ROBODR_BINUTILS_VERSION="2.42"
    ;;
esac
# Documented, recorded in TOOLCHAIN.txt, not enforced: the *-linux-gnu
# builds link through `cc` (gcc driver + GNU ld), the musl builds through
# rust-lld from the Rust toolchain. GNU ar archives ring's objects before
# rustc reads them (the archive itself is not shipped).

# robodr_clang_ok CC: true if CC's first --version line is the pinned clang.
robodr_clang_ok() {
    local first
    first="$("$1" --version 2>/dev/null | head -n1)" || return 1
    # Ubuntu prints "18.1.3 (1ubuntu1)" (noble) or "14.0.0-1ubuntu1" (jammy).
    [[ "$first" =~ clang\ version\ ${ROBODR_CLANG_VERSION//./\\.}([[:space:]]|$|\(|-) ]]
}

# robodr_pin_cc TRIPLE PREFIX: export CC_<triple> = the pinned clang (or
# check the one the caller set). Returns 1 (after a message on stderr)
# when it is missing or another version, unless ROBODR_ALLOW_UNPINNED_CC=1
# (local experiments only: the output is then not a release build).
robodr_pin_cc() {
    local triple="$1" who="$2" var cc
    var="CC_$(printf '%s' "$triple" | tr '-' '_')"
    cc="${!var:-$ROBODR_CLANG}"
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "$who: FAIL: C compiler $cc not found (ring's C/assembly for $triple; pinned: $ROBODR_CLANG $ROBODR_CLANG_VERSION, apt $ROBODR_CLANG_APT_PACKAGE=$ROBODR_CLANG_APT_VERSION; docs/BUILD.md \"C toolchain\")" >&2
        return 1
    fi
    if ! robodr_clang_ok "$cc"; then
        local got
        got="$("$cc" --version 2>/dev/null | head -n1)"
        if [[ "${ROBODR_ALLOW_UNPINNED_CC:-0}" == 1 ]]; then
            echo "$who: WARNING: $cc is \"$got\", not clang $ROBODR_CLANG_VERSION (ROBODR_ALLOW_UNPINNED_CC=1): NOT a release build" >&2
        else
            echo "$who: FAIL: $cc is \"$got\"; release builds compile ring with clang $ROBODR_CLANG_VERSION ($ROBODR_CLANG_APT_PACKAGE=$ROBODR_CLANG_APT_VERSION; docs/BUILD.md \"C toolchain\")" >&2
            return 1
        fi
    fi
    export "$var=$cc"
}

# robodr_toolchain_report: the versions that went into a build.
robodr_toolchain_report() {
    echo "rustc: $(rustc -vV 2>/dev/null | tr '\n' ' ')"
    echo "cargo: $(cargo -V 2>/dev/null)"
    local v
    for v in $(compgen -e | grep '^CC_' | LC_ALL=C sort); do
        echo "$v=${!v}: $("${!v}" --version 2>/dev/null | head -n1)"
    done
    echo "cc: $(cc --version 2>/dev/null | head -n1)"
    echo "ld: $(ld --version 2>/dev/null | head -n1)"
    echo "ar: $(ar --version 2>/dev/null | head -n1)"
    echo "userland: $(robodr_build_userland) (glibc $(ldd --version 2>/dev/null | head -n1 | sed 's/.* //'))"
    echo "pinned: $ROBODR_CLANG $ROBODR_CLANG_VERSION (apt $ROBODR_CLANG_APT_VERSION, also $ROBODR_CLANG_APT_ALSO), documented gcc $ROBODR_GCC_VERSION, binutils $ROBODR_BINUTILS_VERSION"
}
