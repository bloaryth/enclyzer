#!/bin/bash 
## Usage: sudo bash install.sh

# SGX-related
sudo bash install-linux-sgx-2.13.sh
sudo bash install-linux-sgx-driver-master.sh
sudo bash install-sgx-software-enable-master.sh

# enclyzer-related
sudo bash install-cjson-1.17.15.sh
sudo bash install-criterion-v2.3.2.sh
sudo bash install-enclyzer-prerequisites.sh
sudo bash install-enclyzer-settings.sh