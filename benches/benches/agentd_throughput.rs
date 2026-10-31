//! `cargo bench -p robodr-benches --bench agentd_throughput`: the agentd
//! workloads of the quick suite, in this process (peak RSS is the whole
//! bench process's; `robodr-bench` isolates each workload instead).

fn main() {
    for l in robodr_benches::suite(true).0 {
        match robodr_benches::run_agentd(&l) {
            Ok(v) => println!("{v}"),
            Err(e) => {
                eprintln!("{}: {e}", l.name());
                std::process::exit(2);
            }
        }
    }
}
