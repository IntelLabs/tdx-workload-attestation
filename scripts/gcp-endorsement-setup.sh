#!/bin/bash

echo "Downloading the latest GCP endorsement proto and root cert..."

mkdir -p target/gcp
cd target
wget -O gcp/endorsement.proto https://raw.githubusercontent.com/google/gce-tcb-verifier/refs/heads/main/proto/endorsement.proto
wget -O gcp/GCE-cc-tcb-root_1.crt https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt
