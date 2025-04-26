# Workload Attestation
![GitHub License](https://img.shields.io/github/license/IntelLabs/il-opensource-template)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/IntelLabs/il-opensource-template/badge)](https://scorecard.dev/viewer/?uri=github.com/IntelLabs/il-opensource-template)
<!-- UNCOMMENT AS NEEDED
[![Unit Tests](https://github.com/IntelLabs/ConvAssist/actions/workflows/run_unittests.yaml/badge.svg?branch=covassist-cleanup)](https://github.com/IntelLabs/ConvAssist/actions/workflows/run_unittests.yaml)
[![pytorch](https://img.shields.io/badge/PyTorch-v2.4.1-green?logo=pytorch)](https://pytorch.org/get-started/locally/)
![python-support](https://img.shields.io/badge/Python-3.12-3?logo=python)
-->

A Rust library for attesting virtual machine (VM) workloads using a [trusted execution
environment] (TEE), including their full host and guest software stack.

## Quickstart

### Pre-requisites

- Rust toolchain (1.58 or later)
- OpenSSL development libraries
- A compute platform with support for VM-based TEEs.

### Installation

```bash
git clone https://github.com/IntelLabs/workload-attestation
cargo build # defaults to tdx-linux
```

### Supported Environments

- Intel(R) Trust Domain eXtensions (Intel(R) TDX) 1.5 or above

## Disclaimer

This library is experimental, and should not be used in a production environment.

[trusted execution environments]: https://en.wikipedia.org/wiki/Trusted_execution_environment


