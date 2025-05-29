# TDX Workload Attestation
![GitHub License](https://img.shields.io/github/license/IntelLabs/il-opensource-template)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/IntelLabs/il-opensource-template/badge)](https://scorecard.dev/viewer/?uri=github.com/IntelLabs/il-opensource-template)
<!-- UNCOMMENT AS NEEDED
[![Unit Tests](https://github.com/IntelLabs/ConvAssist/actions/workflows/run_unittests.yaml/badge.svg?branch=covassist-cleanup)](https://github.com/IntelLabs/ConvAssist/actions/workflows/run_unittests.yaml)
[![pytorch](https://img.shields.io/badge/PyTorch-v2.4.1-green?logo=pytorch)](https://pytorch.org/get-started/locally/)
![python-support](https://img.shields.io/badge/Python-3.12-3?logo=python)
-->

A Rust library for attesting virtual machine (VM) workloads using [Intel Trust
Domain Extensions] (Intel TDX).

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
tdx-attest quote
```
To only print out the launch measurement (MRTD), run the `quote` command with
the `-m` flag.

You may also save the attestation report to a local file with the `-s` and `-o <filename>` options.

## Disclaimer

This library is experimental, and should not be used in a production environment.

[Intel Trust Domain Extensions]: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
[enlightened Ubuntu]: https://github.com/canonical/tdx


