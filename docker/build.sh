#!/bin/sh

set -e

docker build --target enclyzer --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t bloaryth/enclyzer -f ./Dockerfile ..
docker build --target aesmd --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -t bloaryth/aesmd -f ./Dockerfile ..

docker push bloaryth/enclyzer:latest
docker push bloaryth/aesmd:latest

