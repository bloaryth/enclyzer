#!/bin/bash
## Usage: sudo bash install-enclyzer-prerequisites.sh

enclyzer_SYSTEM_PACKAGES="make gcc curl cpuid msr-tools doxygen graphviz linux-tools-$(uname -r)"
enclyzer_PYTHON_LIBRARIES="numpy==1.20.3 openpyxl==3.0.7 pandas==1.2.4"

# System packages
echo -n "[enclyzer] INSTALLING SYSTEM PACKAGES..."
sudo apt -y install $enclyzer_SYSTEM_PACKAGES
echo "Done!"

# Python libraries
echo -n "[enclyzer] INSTALLING PYTHON LIBRARIES..."
sudo apt -y install python3-pip
sudo pip3 install $enclyzer_PYTHON_LIBRARIES
echo "Done!"