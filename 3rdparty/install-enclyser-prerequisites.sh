#!/bin/bash
## Usage: sudo bash install-enclyser-prerequisites.sh

ENCLYSER_CMDLINE_PARAMETER='mitigations=off tsx=on nox2apic iomem=relaxed no_timer_check isolcpus=1 nmi_watchdog=0 nosmap nosmep clearcpuid=514'
ENCLYSER_SYSTEM_PACKAGES="make gcc curl cpuid msr-tools linux-tools-$(uname -r)"
ENCLYSER_PYTHON_LIBRARIES="numpy==1.20.3 openpyxl==3.0.7 pandas==1.2.4"

# Grub cmdline configuration
if [ -z "$(grep "$ENCLYSER_CMDLINE_PARAMETER" /etc/default/grub)" ]
then
    echo "[ENCLYSER] UPDATE GRUB_CMDLINE_LINUX_DEFAULT..."
    sudo sed -i -E "s/(GRUB_CMDLINE_LINUX_DEFAULT=\".*)\"/\1 $ENCLYSER_CMDLINE_PARAMETER\"/g" /etc/default/grub
    sudo update-grub
    cat /etc/default/grub
fi

# WGET IPV4 over IPV6 configuration
# if [ ! -z "$(grep 'precedence ::ffff:0:0/96  100' /etc/gai.conf)" ]
# then
#     echo "UPDATE GAI_CONFIG..."
#     sudo sed -i -E 's/.*(precedence ::ffff:0:0\/96  100)/\1/g' /etc/gai.conf
# fi

# System packages
echo -n "[ENCLYSER] INSTALLING SYSTEM PACKAGES..."
sudo apt -y install $ENCLYSER_SYSTEM_PACKAGES
echo "Done!"

# Python libraries
echo -n "[ENCLYSER] INSTALLING PYTHON LIBRARIES..."
sudo apt -y install python3-pip
sudo pip3 install $ENCLYSER_PYTHON_LIBRARIES
echo "Done!"

# Additional information before exit
echo '`sudo reboot` is required for the installing to take effect.'