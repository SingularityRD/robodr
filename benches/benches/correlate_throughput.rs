//! `cargo bench -p robodr-benches --bench correlate_throughput`: the
//! correlation-engine workloads of the full suite.

fn main() {
    for l in robodr_benches::suite(false).1 {
        match robodr_benches::run_correlate(&l) {
            Ok(v) => println!("{v}"),
            Err(e) => {
                eprintln!("{}: {e}", l.name());
                std::process::exit(2);
            }
        }
    }
}
