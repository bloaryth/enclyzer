#!/bin/sh -e
## Usage: sudo bash install-cjson-1.17.15.sh

CJSON_RELEASE_URL=https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
CJSON_FILE_NAME=cJSON-1.7.15.tar.gz
CJSON_FOLDER_PATH=cJSON-1.7.15/

function cleanup {
  sudo rm -rf $CJSON_FILE_NAME $CJSON_FOLDER_PATH
}
trap cleanup EXIT

## Download
echo -n "[CJSON] Downloading cjson-1.7.15..."
wget -q $CJSON_RELEASE_URL -O $CJSON_FILE_NAME
tar -xf $CJSON_FILE_NAME
echo "Done!"

## Install
echo -n "[CJSON] Installing cjson-1.7.15..."
sudo apt-get -y install cmake
cd $CJSON_FOLDER_PATH
mkdir build
cd build
cmake ..
make
make install
echo "Done!"