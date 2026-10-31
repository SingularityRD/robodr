// Records the build identity for robodr_buildinfo (see src/lib.rs). Inputs
// are environment variables only, never `git`: the reproducibility builds
// copy the tree without .git (scripts/ci-repro.sh), and their binaries must
// equal the release build's. A malformed value fails the build.
#![allow(clippy::print_stdout)]

#[allow(dead_code)]
mod check {
    include!("src/check.rs");
}

fn var(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok()
}

fn main() {
    println!("cargo:rerun-if-changed=src/check.rs");
    let commit = check::select_commit(
        var("ROBODR_BUILD_COMMIT").as_deref(),
        var("GITHUB_SHA").as_deref(),
    );
    let epoch = check::select_epoch(var("SOURCE_DATE_EPOCH").as_deref());
    // TARGET is always set by cargo for build scripts.
    let target = check::select_target(std::env::var("TARGET").ok().as_deref());
    match (commit, epoch, target) {
        (Ok(c), Ok(e), Ok(t)) => {
            println!("cargo:rustc-env=ROBODR_BUILDINFO_COMMIT={c}");
            println!("cargo:rustc-env=ROBODR_BUILDINFO_EPOCH={e}");
            println!("cargo:rustc-env=ROBODR_BUILDINFO_TARGET={t}");
        }
        (c, e, t) => {
            for err in [c.err(), e.err(), t.err()].into_iter().flatten() {
                eprintln!("robodr-buildinfo: {err}");
            }
            std::process::exit(1);
        }
    }
}
