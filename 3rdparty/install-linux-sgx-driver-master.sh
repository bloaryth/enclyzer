#!/bin/bash 
## Usage: sudo bash install-linux-sgx-driver-master.sh

function cleanup {
  rm -rf linux-sgx-driver
}
trap cleanup EXIT

# Check if matching kernel headers are installed
# echo -n "[LINUX-SGX-DRIVER] Checking prerequisites..."
# dpkg-query -s linux-headers-$(uname -r)
# echo "Done!"

# Install matching headers
echo -n "[LINUX-SGX-DRIVER] Installing prerequisites..."
sudo apt-get -qqy install linux-headers-$(uname -r)
echo "Done!"

# Download the source code
# You may need to set an https proxy. For example, $ export all_proxy="socks5://127.0.0.1:1080".
echo -n "[LINUX-SGX-DRIVER] Downloading linux-sgx-driver-master..."
git clone -q https://github.com/intel/linux-sgx-driver.git linux-sgx-driver --branch master --single-branch
echo "Done!"

# Build the Intel(R) SGX driver
echo -n "[LINUX-SGX-DRIVER] Building linux-sgx-driver-master..."
make -s -C linux-sgx-driver
echo "Done!"

# Install the Intel(R) SGX driver
echo -n "[LINUX-SGX-DRIVER] Installing linux-sgx-driver-master..."
sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sudo cp linux-sgx-driver/isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
sudo /sbin/depmod
sudo /sbin/modprobe isgx
echo "Done!"

# modprobe: ERROR: could not insert ‘isgx’: Operation not permitted
# The easiest way is to disable UEFI Secure Boot in the BIOS.

# Remember to reboot to start isgx
# Configure the system with the SGX hardware enabled option

# Additional information before exit
echo 'Reboot is required for the installation to take effect.'