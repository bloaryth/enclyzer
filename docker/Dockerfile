FROM ubuntu:20.04 as builder

RUN apt-get update && apt-get install -yqq \
  install build-essential ocaml ocamlbuild automake \
  autoconf libtool wget python libssl-dev git cmake perl \
  libssl-dev libcurl4-openssl-dev protobuf-compiler \
  libprotobuf-dev debhelper cmake reprepro unzip

RUN git clone https://github.com/intel/linux-sgx.git linux-sgx && \
  --branch sgx_2.13 --single-branch --depth 1 && \
  cd linux-sgx && make preparation && \
  cp external/toolset/ubuntu20.04/{as,ld,ld.gold,objdump} /usr/local/bin && \
  make sdk -j `nproc` && make sdk_install_pkg && \
  make psw -j `nproc` && make psw_install_pkg



FROM ubuntu:20.04 as aesmd

RUN apt-get update && apt-get install -y \
    libcurl4 libprotobuf10 libssl1.1 make module-init-tools

WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw_*.bin --no-start-aesm

WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon



FROM ubuntu:20.04 as enclyzer

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install SGX SDK and PSW for Linux
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm && \
  sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'

# Install criterion for ENCLYZER
WORKDIR /
RUN wget https://github.com/Snaipe/Criterion/releases/download/v2.3.2/criterion-v2.3.2-linux-x86_64.tar.bz2 \
  -O criterion-v2.3.2-linux-x86_64.tar.bz2 && \
  tar -xjf criterion-v2.3.2-linux-x86_64.tar.bz2 && \
  rm criterion-v2.3.2-linux-x86_64.tar.bz2 && \
  cp -rf ./criterion-v2.3.2/* /usr/

# Enable sudo inside the docker container
RUN apt-get update && apt-get install -yqq sudo && \
  useradd -ms /bin/bash ubuntu && usermod -aG sudo ubuntu && \
  echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Set up default user and workspace
USER ubuntu

# Install the ENCLYZER repository on github
WORKDIR /home/ubuntu
RUN sudo apt-get install -yqq git && \
  git clone https://github.com/bloaryth/enclyzer.git

