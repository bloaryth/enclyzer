#!/bin/bash
## Usage: sudo bash install-sgx-software-enable-master.bash

function cleanup {
  rm -rf sgx-software-enable
}
trap cleanup EXIT

# Download the source code
# You may need to set an https proxy. For example, $ export all_proxy="socks5://127.0.0.1:1080".
echo -n "[SGX-SOFTWARE-ENABLE] Downloading sgx-software-enable..."
git clone -q https://github.com/intel/sgx-software-enable.git sgx-software-enable --branch master --single-branch --depth 1
echo "Done!"

# Build the Intel(R) SGX Software Enabling Application
echo -n "[SGX-SOFTWARE-ENABLE] Building sgx-software-enable..."
make -s -C sgx-software-enable
echo "Done!"

# Enable the Intel(R) SGX via the Intel(R) SGX Software Enabling Application
echo -n "[SGX-SOFTWARE-ENABLE] Installing sgx-software-enable..."
sudo sgx-software-enable/sgx_enable
echo "Done!"