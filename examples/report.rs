use tdx_workload_attestation::get_report;

fn main() {
    let report = get_report(false);
    println!("Got TEE Report : {:?}", report);
}
