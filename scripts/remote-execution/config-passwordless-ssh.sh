#!/bin/bash

declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    ssh $SSH_TARGET -T ssh-keygen
    ssh-copy-id $SSH_TARGET
done