#!/bin/sh
# Tests of scripts/static-pie-ld (the aarch64 musl static-pie linker).
#
#   scripts/test-static-pie-ld.sh
#
# 1. Argument rewriting and fail-closed refusals, with a fake lld
#    (ROBODR_STATIC_PIE_LD_REAL) that records what it was given.
# 2. When the aarch64-unknown-linux-musl target and qemu-aarch64(-static)
#    are installed: a real link through rustc. The program must be ET_DYN
#    (static-pie), have no PT_INTERP and no DT_NEEDED, run under qemu,
#    unwind a panic, and load at a different address on two runs (ASLR of
#    the image). Without the target or qemu that part is SKIPPED, or FAILS
#    when ROBODR_REQUIRE_STATIC_PIE_TEST=1 (release.yml sets it).
#
# Exit: 0 pass, 1 fail.
# ok() never fails, so `test && ok || bad` is an if-then-else here.
# shellcheck disable=SC2015
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
ld="$here/static-pie-ld"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1" >&2; fail=1; }

sc="/sys/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained"
mkdir -p "$work$sc"
for f in rcrt1.o crtbeginS.o crtendS.o; do : >"$work$sc/$f"; done
cat >"$work/fake-lld" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$FAKE_OUT"
EOF
chmod +x "$work/fake-lld"
export ROBODR_STATIC_PIE_LD_REAL="$work/fake-lld" FAKE_OUT="$work/args"

# rustc's StaticNoPicExe link (shape taken from rustc 1.98.1).
set -- "$work$sc/crt1.o" "$work$sc/crti.o" "$work$sc/crtbegin.o" main.o \
    -Bstatic -lunwind -lc --eh-frame-hdr -o prog --gc-sections -static -z relro -z now \
    "$work$sc/crtend.o" "$work$sc/crtn.o"
if "$ld" "$@" && [ "$(tr '\n' ' ' <"$work/args")" = "$work$sc/rcrt1.o $work$sc/crti.o $work$sc/crtbeginS.o main.o -Bstatic -lunwind -lc --eh-frame-hdr -o prog --gc-sections -static -pie --no-dynamic-linker -z text -z relro -z now $work$sc/crtendS.o $work$sc/crtn.o " ]; then
    ok "rewrites crt1/crtbegin/crtend and -static, order kept"
else
    bad "rewrite: $(tr '\n' ' ' <"$work/args" 2>/dev/null || true)"
fi

refuse() { # name args...
    name="$1"
    shift
    rm -f "$work/args"
    if "$ld" "$@" 2>/dev/null || [ -e "$work/args" ]; then bad "accepted: $name"; else ok "refuses: $name"; fi
}
refuse "no crt1.o (not a static exe link)" "$work$sc/crti.o" "$work$sc/crtbegin.o" -static "$work$sc/crtend.o"
refuse "no -static" "$work$sc/crt1.o" "$work$sc/crtbegin.o" "$work$sc/crtend.o"
refuse "two crt1.o" "$work$sc/crt1.o" "$work$sc/crt1.o" "$work$sc/crtbegin.o" -static "$work$sc/crtend.o"
refuse "-shared" "$work$sc/crt1.o" "$work$sc/crtbegin.o" -static -shared "$work$sc/crtend.o"
refuse "--dynamic-linker" "$work$sc/crt1.o" "$work$sc/crtbegin.o" -static --dynamic-linker=/lib/ld "$work$sc/crtend.o"
refuse "-no-pie" "$work$sc/crt1.o" "$work$sc/crtbegin.o" -static -no-pie "$work$sc/crtend.o"
rm "$work$sc/rcrt1.o"
refuse "rcrt1.o missing from rust-std" "$work$sc/crt1.o" "$work$sc/crtbegin.o" -static "$work$sc/crtend.o"
unset ROBODR_STATIC_PIE_LD_REAL FAKE_OUT

# 2. Real link.
qemu="$(command -v qemu-aarch64-static || command -v qemu-aarch64 || true)"
if ! rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-musl &&
    [ ! -d "$(rustc --print sysroot 2>/dev/null)/lib/rustlib/aarch64-unknown-linux-musl/lib" ]; then
    missing="rust target aarch64-unknown-linux-musl"
elif [ -z "$qemu" ] && [ "$(uname -m)" != aarch64 ]; then
    missing="qemu-aarch64-static"
else
    missing=""
fi
if [ -n "$missing" ]; then
    if [ "${ROBODR_REQUIRE_STATIC_PIE_TEST:-0}" = 1 ]; then
        bad "real link: $missing not installed (ROBODR_REQUIRE_STATIC_PIE_TEST=1)"
    else
        echo "SKIPPED real link: $missing not installed"
    fi
else
    [ "$(uname -m)" = aarch64 ] && qemu=""
    cat >"$work/p.rs" <<'EOF'
static NAME: &str = "static-pie";
fn main() {
    let t = std::thread::spawn(|| 40 + 2).join().unwrap_or(0);
    println!("{} {} {:p}", NAME, t, main as fn());
    if std::env::args().count() > 1 {
        let r = std::panic::catch_unwind(|| panic!("unwind"));
        println!("caught={}", r.is_err());
    }
}
EOF
    if rustc -O --target aarch64-unknown-linux-musl -C linker="$ld" "$work/p.rs" -o "$work/p" 2>"$work/rustc.log"; then
        ok "rustc links through static-pie-ld"
        type="$(od -An -tu2 -j16 -N2 "$work/p" | tr -d '[:space:]')"
        [ "$type" = 3 ] && ok "ET_DYN (static-pie)" || bad "e_type $type, want 3 (ET_DYN)"
        if readelf -lW "$work/p" | grep -q INTERP; then bad "has PT_INTERP"; else ok "no PT_INTERP"; fi
        if readelf -dW "$work/p" 2>/dev/null | grep -q '(NEEDED)'; then bad "has DT_NEEDED"; else ok "no DT_NEEDED"; fi
        if readelf -dW "$work/p" 2>/dev/null | grep -q 'TEXTREL'; then bad "has TEXTREL"; else ok "no TEXTREL"; fi
        a="$($qemu "$work/p" || echo FAILED)"
        b="$($qemu "$work/p" || echo FAILED)"
        case "$a" in "static-pie 42 0x"*) ok "runs: $a" ;; *) bad "run: $a" ;; esac
        [ "$a" != "$b" ] && ok "image address differs between runs (ASLR)" || bad "same address twice: $a"
        c="$($qemu "$work/p" x 2>/dev/null | tail -1 || true)"
        [ "$c" = "caught=true" ] && ok "panic unwinds" || bad "unwind: $c"
        # build-static.sh's release check: static-pie passes, the default
        # (non-PIE) rust-lld link of the same program is refused.
        rustc -O --target aarch64-unknown-linux-musl -C linker=rust-lld "$work/p.rs" -o "$work/p-nopie"
        mkdir -p "$work/pie" "$work/nopie"
        cp "$work/p" "$work/pie/robodr-p"
        cp "$work/p-nopie" "$work/nopie/robodr-p"
        if ROBODR_REQUIRE_STATIC_PIE=1 "$here/build-static.sh" aarch64-unknown-linux-musl --check-dir "$work/pie" 2>/dev/null; then
            ok "build-static.sh --check-dir accepts the static-pie binary"
        else
            bad "build-static.sh --check-dir refused the static-pie binary"
        fi
        if ROBODR_REQUIRE_STATIC_PIE=1 "$here/build-static.sh" aarch64-unknown-linux-musl --check-dir "$work/nopie" 2>/dev/null; then
            bad "build-static.sh --check-dir accepted a non-PIE (ET_EXEC) binary"
        else
            ok "build-static.sh --check-dir refuses a non-PIE (ET_EXEC) binary"
        fi
        if env -u ROBODR_REQUIRE_STATIC_PIE "$here/build-static.sh" aarch64-unknown-linux-musl --check-dir "$work/nopie" 2>/dev/null; then
            bad "build-static.sh --check-dir accepted a non-PIE binary with the default linker"
        else
            ok "build-static.sh --check-dir refuses non-PIE with the default linker"
        fi
    else
        bad "rustc link failed: $(tail -5 "$work/rustc.log")"
    fi
fi
[ "$fail" = 0 ] && echo "test-static-pie-ld: all passed"
exit "$fail"
