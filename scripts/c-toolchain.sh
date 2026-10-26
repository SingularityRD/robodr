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

# Ubuntu 24.04 (noble) release pocket, amd64 and arm64.
ROBODR_CLANG="clang-18"
ROBODR_CLANG_VERSION="18.1.3"
ROBODR_CLANG_APT_PACKAGE="clang-18"
ROBODR_CLANG_APT_VERSION="1:18.1.3-1ubuntu1"
# Documented, recorded in TOOLCHAIN.txt, not enforced: the *-linux-gnu
# builds link through `cc` (gcc driver + GNU ld), the musl builds through
# rust-lld from the Rust toolchain. GNU ar archives ring's objects before
# rustc reads them (the archive itself is not shipped).
ROBODR_GCC_VERSION="13.3.0"
ROBODR_BINUTILS_VERSION="2.42"

# robodr_clang_ok CC: true if CC's first --version line is the pinned clang.
robodr_clang_ok() {
    local first
    first="$("$1" --version 2>/dev/null | head -n1)" || return 1
    [[ "$first" =~ clang\ version\ ${ROBODR_CLANG_VERSION//./\\.}([[:space:]]|$|\() ]]
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
    echo "pinned: $ROBODR_CLANG $ROBODR_CLANG_VERSION (apt $ROBODR_CLANG_APT_VERSION), documented gcc $ROBODR_GCC_VERSION, binutils $ROBODR_BINUTILS_VERSION"
}
