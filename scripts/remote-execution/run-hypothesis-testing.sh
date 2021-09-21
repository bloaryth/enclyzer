#!/bin/bash

declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")

# $1: $PASSWORD
# $2: $SSH_TARGET
remote_task(){
    mkdir -p ~/Documents/enclyser-results
    ssh $2 'cd enclyser; git pull;'
    echo $1 | ssh $2 -tt 'sudo make -C enclyser/enclyser clean all run'
    scp $2:enclyser/enclyser/sgx_app.txt ~/Documents/enclyser-results/$2.txt
}

if [ -z $PASSWORD ]; then
echo "[Remote-Execution] \$PASSWORD not set!"
exit 1
fi

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    remote_task "$PASSWORD" "$SSH_TARGET" >/dev/null 2>&1 &
done