#!/bin/bash

declare -a SSH_TARGET_ARR=("i7-9850h" "i9-8950hk" "e3-1535mv5" "i5-6360u" "i5-8365u")

for SSH_TARGET in "${SSH_TARGET_ARR[@]}"; do
    ssh $SSH_TARGET "cp -r /opt/intel/sgxsdk/SampleCode/RemoteAttestation/ RemoteAttestation; cd RemoteAttestation; sed -i '/Enter a character before exit .../d' isv_app/isv_app.cpp; sed -i '/getchar();/d' isv_app/isv_app.cpp"
    if ssh $SSH_TARGET "cd RemoteAttestation; make clean all run >/dev/null 2>&1"; then
        echo -e "[Remote-Execution] $SSH_TARGET\tRemote Attestation\tpassed!"
    else
        echo -e "[Remote-Execution] $SSH_TARGET\tRemote Attestation\tfailed!"
    fi
    ssh $SSH_TARGET "rm -r RemoteAttestation"
done