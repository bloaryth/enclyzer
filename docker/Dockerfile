FROM ubuntu:20.04 as linux-sgx

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -yqq \
  build-essential ocaml ocamlbuild automake \
  autoconf libtool wget python libssl-dev git cmake perl \
  libssl-dev libcurl4-openssl-dev protobuf-compiler \
  libprotobuf-dev debhelper cmake reprepro unzip

RUN git clone https://github.com/intel/linux-sgx.git linux-sgx \
  --branch sgx_2.13 --single-branch --depth 1 && \
  cd linux-sgx && make preparation && \
  cp external/toolset/ubuntu20.04/* /usr/local/bin/ && \
  make sdk -j `nproc` && make sdk_install_pkg && \
  sh -c 'echo "no\n/opt/intel" | ./linux/installer/bin/sgx_linux_x64_sdk_*.bin' && \
  make psw -j `nproc` && make psw_install_pkg && \
  ./linux/installer/bin/sgx_linux_x64_psw_*.bin --no-start-aesm && \
  rm -rf /linux-sgx



FROM linux-sgx as aesmd

WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon



FROM linux-sgx as enclyzer

# ENV TZ=Asia/Shanghai
# RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Enable sudo inside the docker container
RUN apt-get update && apt-get install -yqq sudo && \
  useradd -ms /bin/bash ubuntu && usermod -aG sudo ubuntu && \
  echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Install SGX SDK and PSW for Linux
# RUN apt-get update && apt-get install -yqq \
#     libcurl4-openssl-dev libprotobuf-dev libssl-dev make kmod

# WORKDIR /opt/intel
# COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
# RUN sh -c 'echo "no\n/opt/intel" | ./sgx_linux_x64_sdk_*.bin' && \
#   ./sgx_linux_x64_psw*.bin --no-start-aesm

# Install criterion for ENCLYZER
WORKDIR /
RUN apt-get update && apt-get install -yqq wget tar && \
  wget https://github.com/Snaipe/Criterion/releases/download/v2.3.2/criterion-v2.3.2-linux-x86_64.tar.bz2 \
  -O criterion-v2.3.2-linux-x86_64.tar.bz2 && \
  tar -xjf criterion-v2.3.2-linux-x86_64.tar.bz2 && \
  rm criterion-v2.3.2-linux-x86_64.tar.bz2 && \
  cp -rf ./criterion-v2.3.2/* /usr/

# Install the ENCLYZER repository on github
RUN apt-get update && sudo apt-get install -yqq git gcc msr-tools kmod && \
  mkdir -p /home/ubuntu && cd /home/ubuntu && \
  git clone https://github.com/bloaryth/enclyzer.git

# Disable cache and update the ENCLYZER repository
ADD "https://www.random.org/cgi-bin/randbyte?nbytes=10&format=h" skipcache
RUN cd /home/ubuntu/enclyzer && git pull

# Set up user and build the application
USER ubuntu

# Disable prefechers and run tests
WORKDIR /home/ubuntu/enclyzer/enclyzer
CMD [ "sudo", "make", "all", "run", "clean" ]