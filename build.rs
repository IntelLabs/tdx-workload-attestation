#[cfg(feature = "host-gcp-tdx")]
use protobuf_codegen::{Codegen, Customize};
#[cfg(feature = "host-gcp-tdx")]
use std::process::Command;

#[cfg(feature = "host-gcp-tdx")]
fn generate_gcp_protos() {
    let no_mod_cfg = Customize::default();

    Codegen::new()
        .out_dir("src/gcp")
        .include("target/gcp") // this dir is created by the setup script
        .input("target/gcp/endorsement.proto")
        .customize(no_mod_cfg.gen_mod_rs(false))
        .run()
        .expect("Protobuf codegen failed");
}

#[cfg(feature = "host-gcp-tdx")]
fn setup_gcp_guest() {
    let _output = Command::new("scripts/gcp-endorsement-setup.sh")
        .output()
        .expect("failed to set up GCP guest");

    generate_gcp_protos();
}

fn main() {
    #[cfg(feature = "host-gcp-tdx")]
    setup_gcp_guest();
}
