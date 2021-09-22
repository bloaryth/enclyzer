#!/bin/bash

declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")

# $1: $PASSWORD
# $2: $SSH_TARGET
remote_task(){
    ssh $2 'cd enclyser; git pull;'
    echo $1 | ssh $2 -tt 'sudo apt-get update'
    echo $1 | ssh $2 -tt 'sudo apt-get -f install'
    echo $1 | ssh $2 -tt 'sudo bash enclyser/3rdparty/install-linux-sgx-driver-master.sh'
    echo $1 | ssh $2 -tt 'sudo bash enclyser/3rdparty/install-enclyser-settings.sh'
    echo $1 | ssh $2 -tt 'sudo bash enclyser/3rdparty/install-enclyser-prerequisites.sh'
    echo $1 | ssh $2 -tt 'cd enclyser/scripts/microcode-update/; sudo bash early-os-update.sh 20180312'
    echo $1 | ssh $2 -tt 'sudo reboot'
}

if [ -z $PASSWORD ]; then
echo "[Remote-Execution] \$PASSWORD not set!"
exit 1
fi

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    remote_task "$PASSWORD" "$SSH_TARGET" >/dev/null 2>&1 &
done