#!/bin/bash

declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")

if [ -z $PASSWORD ]; then
echo "[Remote-Execution] \$PASSWORD not set!"
exit 1
fi

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    echo $PASSWORD | ssh $SSH_TARGET -tt 'sudo bash enclyser/3rdparty/install-linux-sgx-driver-master.sh'
    echo $PASSWORD | ssh $SSH_TARGET -tt 'sudo reboot'
done