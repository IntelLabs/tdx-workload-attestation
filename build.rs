#[cfg(feature = "host-gcp-tdx")]
use protobuf_codegen::{Codegen, Customize};
#[cfg(feature = "host-gcp-tdx")]
use reqwest;
#[cfg(feature = "host-gcp-tdx")]
use std::fs;
#[cfg(feature = "host-gcp-tdx")]
use std::io::Write;

#[cfg(feature = "host-gcp-tdx")]
fn generate_gcp_protos() {
    // Download the endorsement proto from the GCE TCB verifier repo
    fs::create_dir_all("target/gcp").unwrap();
    let endorsement_proto =
        reqwest::blocking::get("https://raw.githubusercontent.com/google/gce-tcb-verifier/refs/heads/main/proto/endorsement.proto").unwrap().text().unwrap();

    let mut file = fs::File::create("target/gcp/endorsement.proto").unwrap();
    file.write_all(endorsement_proto.as_bytes()).unwrap();

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
    generate_gcp_protos();
}

fn main() {
    #[cfg(feature = "host-gcp-tdx")]
    setup_gcp_guest();
}
