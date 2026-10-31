//! `robodr-seal`: see `robodr_seal::cli::USAGE`.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(robodr_seal::cli::main_with_env());
}
