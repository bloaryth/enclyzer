#!/bin/bash
## Usage: sudo bash install-linux-sgx-2.13.sh

# Remove the source code left by the last unfinished attempt
rm -rf linux-sgx

# Install the required tools to build the Intel(R) SGX SDK
echo "[LINUX-SGX] Installing prerequisites..."
sudo apt-get -y install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
sudo apt-get -y install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip

# Download the source code and prepare the submodules and prebuilt binaries
# You may need to set an https proxy. For example, $ export all_proxy="socks5://127.0.0.1:1080".
echo "[LINUX-SGX] Downloading linux-sgx-2.13..."
git clone https://github.com/intel/linux-sgx.git linux-sgx --branch sgx_2.13 --single-branch --depth 1
cd linux-sgx && make preparation

# Copy the mitigation tools corresponding to current OS distribution from external/toolset/{current_distr} to /usr/local/bin and make sure they have execute permission
# The above action is a must even if you copied the previous mitigation tools to /usr/local/bin before. It ensures the updated mitigation tools are used in the later build.
sudo cp external/toolset/ubuntu20.04/{as,ld,ld.gold,objdump} /usr/local/bin
which as ld ld.gold objdump

# (SGX-STEP) Patch Intel(R) SGX SDK to use SGX-STEP
echo "[LINUX-SGX] Modifying linux-sgx-2.13..."
if ! grep -Rq "sgx_set_aep" linux-sgx
then
    if [[ -v M32 ]]
    then
        patch -p1 < ../0000-32bit-compatibility-fixes.patch
    fi
    patch -p1 < ../0001-reconfigure-AEP-TCS-ebase.patch
fi

# Build Intel(R) SGX SDK with default configuration
# You can find the three flavors of tools and libraries generated in the build directory.
echo "[LINUX-SGX] Building linux-sgx-2.13 SDK..."
make sdk -j `nproc`

# Build the Intel(R) SGX SDK installer
# You can find the generated Intel(R) SGX SDK installer sgx_linux_x64_sdk_${version}.bin located under linux/installer/bin/, where ${version} refers to the version number.
make sdk_install_pkg

# Invoke the installer
echo "[LINUX-SGX] Installing linux-sgx-2.13 SDK..."
cd linux/installer/bin
sudo ./sgx_linux_x64_sdk_*.bin  << EOF
no
/opt/intel
EOF
cd ../../../

# You need to set up the needed environment variables before compiling your code.
# source /opt/intel/sgxsdk/environment
if [ -z $(cat ~/.bashrc | grep 'source /opt/intel/sgxsdk/environment') ]
then
    source /opt/intel/sgxsdk/environment
    echo "source /opt/intel/sgxsdk/environment" >> ~/.bashrc
fi

# Build the Intel(R) SGX PSW and the Intel(R) SGX PSW Installer
echo "[LINUX-SGX] Building linux-sgx-2.13 PSW..."
make psw -j `nproc`
make psw_install_pkg

# Install the Intel(R) SGX PSW
echo "[LINUX-SGX] Installing linux-sgx-2.13 PSW..."
cd linux/installer/bin/
sudo ./sgx_linux_x64_psw_*.bin
cd ../../../

# Remove the source code
cd ../
rm -rf linux-sgx