use tdx_workload_attestation::verify_launch_endorsement;

fn main() {
    match verify_launch_endorsement("gcp-tdx") {
	Ok(result) => println!("Passed? {}", result),
	Err(e) => println!("The following error occurred: {}", e),
    };
}
