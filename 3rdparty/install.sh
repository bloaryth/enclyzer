#!/bin/bash 
## Usage: sudo bash install.sh

# SGX-related
sudo bash install-linux-sgx-2.13.sh
sudo bash install-linux-sgx-driver-master.sh
sudo bash install-sgx-software-enable-master.sh

# Enclyser-related
sudo bash install-criterion-v2.3.2.sh
sudo bash install-enclyser-prerequisites.sh

