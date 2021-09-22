#!/bin/bash

declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    if ssh -q $SSH_TARGET true; then
        MICROCODE=`ssh $SSH_TARGET cat /proc/cpuinfo | grep microcode -m 1 | awk '{print $3;}'`
        echo -e "[Remote-Execution] $SSH_TARGET\t$MICROCODE\tis alive!"
    fi
done