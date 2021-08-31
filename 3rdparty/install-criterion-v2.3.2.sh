#!/bin/sh -e
## Usage: sudo bash install-criterion-v2.3.2.sh

CRITERION_RELEASE_URL=https://github.com/Snaipe/Criterion/releases/download/v2.3.2/criterion-v2.3.2-linux-x86_64.tar.bz2
CRITERION_FILE_NAME=criterion-v2.3.2-linux-x86_64.tar.bz2

CRITERION_FOLDER_PATH=criterion-v2.3.2/
CRITERION_INSTALL_PATH=/usr/

function cleanup {
  rm -rf $CRITERION_FILE_NAME $CRITERION_FOLDER_PATH
}
trap cleanup EXIT

## Download
echo -n "[CRITERION] Downloading criterion-v2.3.2..."
wget -q $CRITERION_RELEASE_URL -O $CRITERION_FILE_NAME
tar -xjf $CRITERION_FILE_NAME
echo "Done!"

## Install
echo -n "[CRITERION] Installing criterion-v2.3.2..."
sudo cp -rf $FOLDER_NAME* $CRITERION_INSTALL_PATH
echo "Done!"