#[cfg(feature = "host-gcp-tdx")]
use protobuf_codegen::{Codegen, Customize};

#[cfg(feature = "host-gcp-tdx")]
fn generate_gcp_protos() {
    let no_mod_cfg = Customize::default();

    Codegen::new()
        .out_dir("src/gcp")
        .include(".")
        .input("endorsement.proto")
        .customize(no_mod_cfg.gen_mod_rs(false))
        .run()
        .expect("Protobuf codegen failed");
}

fn main() {
    #[cfg(feature = "host-gcp-tdx")]
    generate_gcp_protos();
}
