//! Deterministic loopback-only endpoint assessment measurement harness.

mod endpoint_assessment_support;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    #[cfg(test)]
    endpoint_assessment_support::link_contract_test_surface();
    if let Err(error) = endpoint_assessment_support::run_from_process_arguments().await {
        eprintln!("endpoint assessment harness failed: {error}");
        std::process::exit(1);
    }
}
