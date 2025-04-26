use workload_attestation::verify_launch_endorsement;

fn main() {
    let result = verify_launch_endorsement("gcp-tdx")?;
    println!("Passed? {}", result);
}
