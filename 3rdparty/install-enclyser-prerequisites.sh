#!/bin/bash
## Usage: sudo bash install-enclyser-prerequisites.sh

ENCLYSER_SYSTEM_PACKAGES="make gcc curl cpuid msr-tools doxygen graphviz linux-tools-$(uname -r)"
ENCLYSER_PYTHON_LIBRARIES="numpy==1.20.3 openpyxl==3.0.7 pandas==1.2.4"

# System packages
echo -n "[ENCLYSER] INSTALLING SYSTEM PACKAGES..."
sudo apt -y install $ENCLYSER_SYSTEM_PACKAGES
echo "Done!"

# Python libraries
echo -n "[ENCLYSER] INSTALLING PYTHON LIBRARIES..."
sudo apt -y install python3-pip
sudo pip3 install $ENCLYSER_PYTHON_LIBRARIES
echo "Done!"