//! `robodr-depot`: the site depot (see `robodr_depot::cli::USAGE`).
#![forbid(unsafe_code)]

fn main() {
    std::process::exit(robodr_depot::cli::main_with_env());
}
