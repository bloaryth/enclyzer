#!/bin/bash

# declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")
declare -a SSH_TARGET_ARR=("i5-6360u")
declare -a MICROCODE_ARR=("20180312" "20190514a" "20191113" "20200616" "20201110" "20210608")

# $1: $PASSWORD
# $2: $SSH_TARGET
remote_task(){
    mkdir -p ~/Documents/enclyser-results
    ssh $2 'cd enclyser; git pull;'
    for MICROCODE in "${MICROCODE_ARR[@]}"; do
        if echo $1 | ssh $2 -tt "cd enclyser/scripts/microcode-update/; sudo bash runtime-update.sh $MICROCODE" true; then
            echo $1 | ssh $2 -tt 'sudo make -C enclyser/enclyser clean all run'
            scp $2:enclyser/enclyser/sgx_app.txt ~/Documents/enclyser-results/$2+$MICROCODE.txt
        fi
    done
    echo $1 | ssh $2 -tt 'sudo reboot'
}

if [ -z $PASSWORD ]; then
echo "[Remote-Execution] \$PASSWORD not set!"
exit 1
fi

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    remote_task "$PASSWORD" "$SSH_TARGET" >/dev/null 2>&1 &
done