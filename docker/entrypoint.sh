#!/bin/sh -e
## Usage: sudo bash entrypoint.sh

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

sudo bash ${SCRIPT_DIR}/../3rdparty/install-linux-sgx-driver-master.sh
sudo bash ${SCRIPT_DIR}/../3rdparty/install-sgx-software-enable-master.sh