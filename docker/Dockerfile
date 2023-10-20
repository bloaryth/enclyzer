# Use official Ubuntu 20.04 as the base
FROM ubuntu:20.04

LABEL maintainer="Jiuqin Zhou <bloaryth@gmail.com>"

# Set up the timezone of the image
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Enable sudo inside the docker container
RUN apt-get update && apt-get install -yqq sudo && \
  useradd -ms /bin/bash ubuntu && usermod -aG sudo ubuntu && \
  echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Set up default user and workspace
USER ubuntu
WORKDIR /

# Install the ENCLYZER repository on github
RUN sudo apt-get install -yqq git && \
  sudo mkdir -p /home/ubuntu && cd /home/ubuntu && \
  git clone https://github.com/bloaryth/enclyzer.git

# Install SGX SDK and PSW for Linux
RUN sudo apt-get update && sudo apt-get install -yqq systemctl && \
  cd /home/ubuntu/enclyzer/3rdparty && sudo bash install-linux-sgx-2.13.sh

# Install criterion for ENCLYZER
RUN sudo apt-get update && \
  sudo apt-get install -yqq sudo wget tar && \
  cd /home/ubuntu/enclyzer/3rdparty && \
  sudo bash install-criterion-v2.3.2.sh

ENTRYPOINT [ "sudo", "bash", "/home/ubuntu/enclyzer/docker/entrypoint.sh" ]

