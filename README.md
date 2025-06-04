# TDX Workload Attestation
![GitHub License](https://img.shields.io/github/license/IntelLabs/tdx-workload-attestation)
[![Crates.io](https://img.shields.io/crates/v/tdx-workload-attestation.svg)](https://crates.io/crates/tdx-workload-attestation)
[![Documentation](https://docs.rs/tdx-workload-attestation/badge.svg)](https://docs.rs/tdx-workload-attestation)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/IntelLabs/tdx-workload-attestation/badge)](https://scorecard.dev/viewer/?uri=github.com/IntelLabs/tdx-workload-attestation)

A Rust library for generating attestations about virtual machine (VM) workloads
using [Intel Trust Domain Extensions] (Intel TDX).

## What is attestation?

The purpose of this library is to serve as a building block for supply chain
integrity of TDX workloads. Accordingly, "attestation" in this library refers
to an **authenticated claim about any component of the TDX workload**, not to be
confused with remote attestation from the trusted computing space.

For more information about software attestations, we refer you to the
[in-toto Attestation Framework](https://github.com/in-toto/attestation/blob/main/spec/README.md#in-toto-attestation-framework-spec).

## Quickstart

This guide assumes you are running within an [enlightened Ubuntu] VM on a
machine with support for Intel TDX 1.5 or above.

### Pre-requisites

Install a Rust toolchain (1.85 or later) (see https://www.rust-lang.org/tools/install)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then, install required libraries
```bash
sudo apt install libssl-dev protobuf-compiler
```

### Supported Environments

- VM guests: [enlightened Ubuntu] 24.04 LTS or later
- Hosts: Google Cloud Platform (GCP)

### Build tdx-workload-attestation

For a default build within an Ubuntu TDX guest, run:
```bash
cargo build
```

To enable support for GCP host verification, build with:
```bash
cargo build --features host-gcp-tdx
```
The necessary root certificates are downloaded during this build.

### Use the library

To import the TDX workload attestation library into your project, add it to your
`Cargo.toml`:

```toml
[dependencies]
tdx-workload-attestation = "0.1.0"
```

To disable TDX features, set `default-features = false`. To enable additional
GCP-specific VM verification, add the `host-gcp-tdx` feature.

### Test the library

To test and showcase how the library can be used, we provide a simple
`tdx-attest` CLI tool with the following commands.

#### Get TDX platform info

Print the platform's name:
```bash
tdx-attest platform name
```
If running on a TDX 1.5 guest, the output should be `tdx-linux`.

Check if TDX is available on the platform:
``` bash
tdx-attest platform is-tdx-available
```

#### Obtain TDX attestations

Print the VM's current Intel TDX attestation report:
```bash
sudo tdx-attest quote
```
To only print out the launch measurement (MRTD), run the `quote` command with
the `-m` flag.

You may also save the attestation report to a local file with the `-s` and `-o <filename>` options.

## Disclaimer

This library is experimental, and should not be used in a production environment.

[Intel Trust Domain Extensions]: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
[enlightened Ubuntu]: https://github.com/canonical/tdx
