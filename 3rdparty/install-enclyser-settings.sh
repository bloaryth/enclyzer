#!/bin/bash
## Usage: sudo bash install-enclyser-settings.sh

ENCLYSER_ISOLCPUS=1,$((`grep 'cpu cores' /proc/cpuinfo -m 1 | awk '{print $4}'` + 1))
ENCLYSER_CMDLINE_PARAMETER="isolcpus=$ENCLYSER_ISOLCPUS mitigations=off tsx=on nox2apic iomem=relaxed no_timer_check nmi_watchdog=0 nosmap nosmep clearcpuid=514"

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

# Additional information before exit
echo '`sudo reboot` is required for the installing to take effect.'