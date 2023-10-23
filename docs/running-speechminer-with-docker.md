# **Running SpeechMiner with Docker**

In the following steps, we will guide you through the process of running SpeechMiner using Docker. Please follow these steps carefully to set up the environment correctly and run the application successfully.

## 1. Kernel Parameters

SpeechMiner was developed on kernel 4.x, and therefore, it is recommended that the user installs the same. Specifically, we recommend using Ubuntu 16.04 for optimum performance.

## 2. SGX-Enabled CPU

You need to ensure that your host's CPU supports SGX (Software Guard Extensions). Check if your CPU supports SGX at [Intel Product Specifications]( https://ark.intel.com/content/www/us/en/ark.html ) and if it's enabled in the BIOS. If your CPU supports SGX but there is no options in the BIOS to enable it, you can use [intel/sgx-software-enable]( https://github.com/intel/sgx-software-enable ) to enable SGX.

## 3. Install Kernel Headers

It is essential to have kernel headers installed, as they are required for compiling SpeechMiner's kernel modules. Please use the following commands to install the necessary kernel headers:

- **Ubuntu**:
    ```bash
    wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19-rc8/linux-modules-4.19.0-041900rc8-generic_4.19.0-041900rc8.201810150631_amd64.deb -O linux-modules-4.19.deb
    wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19-rc8/linux-headers-4.19.0-041900rc8_4.19.0-041900rc8.201810150631_all.deb -O linux-headers-4.19.deb
    wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19-rc8/linux-headers-4.19.0-041900rc8-generic_4.19.0-041900rc8.201810150631_amd64.deb -O linux-headers-generic-4.19.deb
    wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19-rc8/linux-image-unsigned-4.19.0-041900rc8-generic_4.19.0-041900rc8.201810150631_amd64.deb -O linux-image-4.19.deb
    dpkg --install *.deb
    ```
## 3. Install Docker and Docker-Compose
    
Use Docker and Docker-Compose to run SpeechMiner. You can find installation instructions to install Docker at [Install Docker Desktop on Linux | Docker Docs]( https://docs.docker.com/desktop/install/linux-install/ ) based on your operating system.

## 4. Build Docker Image and Run

For user convenience, a Dockerfile is provided by SpeechMiner.
```bash
wget https://raw.githubusercontent.com/pw0rld/SpeechMiner/master/Dockerfile
sudo docker build -t speechminer . 
```
After running the build using the following commands, you can use Dockerfile effectively by entering the container using the below command. Finally,
```bash
sudo docker run -it --privileged=true speechmine:latest /bin/bash
```
once inside the SpeechMiner Docker, you can execute the binary for your tests.