#!/bin/bash
## Usage: sudo bash early-os-update.sh [MICROCODE]
##
## Microcode:
##   skylake=(["20180312"]="0xc2" ["20190514a"]="0xcc" ["20191113"]="0xd4" ["20200616"]="0xd6" ["20201110"]="0xe2" ["20210608"]="0xea")
##   kabylake=(["20180312"]="0x84" ["20190514a"]="0xb4" ["20191113"]="0xc6" ["20200616"]="0xd6" ["20201110"]="0xde" ["20210608"]="0xea")
##   coffeelake=(["20180312"]="0x84" ["20190514a"]="0xb4" ["20191113"]="0xc6" ["20200616"]="0xd6" ["20201110"]="0xde" ["20210608"]="0xea")

declare -A skylake=(["20180312"]="0xc2" ["20190514a"]="0xcc" ["20191113"]="0xd4" ["20200616"]="0xd6" ["20201110"]="0xe2" ["20210608"]="0xea")
declare -A kabylake=(["20180312"]="0x84" ["20190514a"]="0xb4" ["20191113"]="0xc6" ["20200616"]="0xd6" ["20201110"]="0xde" ["20210608"]="0xea")
declare -A coffeelake=(["20180312"]="0x84" ["20190514a"]="0xb4" ["20191113"]="0xc6" ["20200616"]="0xd6" ["20201110"]="0xde" ["20210608"]="0xea")

if [ ! -z "$(cpuid | grep '(uarch synth) = Intel Skylake {Skylake}, 14nm' -m 1)" ]; then
update_microcode="${skylake["$1"]}"
else if [ ! -z "$(cpuid | grep '(uarch synth) = Intel Kaby Lake {Skylake}, 14nm' -m 1)" ]; then
update_microcode="${kabylake["$1"]}"
else if [ ! -z "$(cpuid | grep '(uarch synth) = Intel Coffee Lake {Skylake}, 14nm' -m 1)" ]; then
update_microcode="${coffeelake["$1"]}"
fi fi fi
update_microcode_dir="microcode-$1/intel-ucode"

if [ ! -d $update_microcode_dir ]; then
    echo "[Error] Directory $update_microcode_dir not found!"
    exit 1
fi

echo -n "[EARLY-OS-UPDATE] Updating to $update_microcode by $update_microcode_dir ... "
sudo rm -rf /lib/firmware/intel-ucode
sudo cp -rf $update_microcode_dir /lib/firmware
/usr/sbin/iucode_tool -tb -lS /lib/firmware/intel-ucode/* > /dev/null 2>&1
sudo update-initramfs -u > /dev/null 2>&1
echo "Done!"