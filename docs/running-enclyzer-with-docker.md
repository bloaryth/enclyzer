# **Running ENCLYZER with Docker**

In the following steps, we will guide you through the process of running ENCLYZER using Docker. Please follow these steps carefully to set up the environment correctly and run the application successfully.

## 1. Kernel Parameters

To run ENCLYZER, specific kernel parameters are required. Make sure you have configured the necessary kernel parameters, such as $CMDLINE_PARAMETER, on your host. Typically, these parameters are set during boot using grub or other boot loaders.

```bash
ISOLCPUS=1,$((`grep 'cpu cores' /proc/cpuinfo -m 1 | awk '{print $4}'` + 1))
CMDLINE_PARAMETER="isolcpus=$ISOLCPUS mitigations=off tsx=on nox2apic iomem=relaxed no_timer_check nmi_watchdog=0 nosmap nosmep clearcpuid=514" 
```

## 2. SGX-Enabled CPU

You need to ensure that your host's CPU supports SGX (Software Guard Extensions). Check if your CPU supports SGX at [Intel® Product Specifications]( https://ark.intel.com/content/www/us/en/ark.html ) and if it's enabled in the BIOS. If your CPU supports SGX but there is no options in the BIOS to enable it, you can use [intel/sgx-software-enable]( https://github.com/intel/sgx-software-enable ) to enable SGX.

## 3. Install Kernel Headers

Kernel headers are essential for compiling ENCLYZER's kernel modules. Install the required kernel headers using the following commands:

- **Ubuntu**:
    ```bash
    sudo apt-get update
    sudo apt-get install linux-headers-$(uname -r)
    ```
- **CentOS**:
    ```bash
    yum install kernel-headers
    ```

## 4. Install Linux SGX Driver

To make use of SGX, you need to install the Linux SGX driver. The following commands install a prebuilt SGX driver. Alternatively, you can follow the instructions in [intel/linux-sgx-driver: Intel SGX Linux* Driver]( https://github.com/intel/linux-sgx-driver ).

```bash
curl -fsSL https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_driver_2.11.54c9c4c.bin | bash
```

## 5. Install Docker and Docker-Compose
    
Use Docker and Docker-Compose to run ENCLYZER. You can find installation instructions to install Docker at [Install Docker Desktop on Linux | Docker Docs]( https://docs.docker.com/desktop/install/linux-install/ ) based on your operating system.

## 6. Pull Docker Image and Run

ENCLYZER offers a Docker image for your convenience. You can retrieve it from Docker Hub. Execute the following commands to pull and run ENCLYZER's Docker image:

```bash
docker pull bloaryth/enclyzer:latest
docker pull bloaryth/aesmd:latest
docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=rw aesmd-socket
curl https://github.com/bloaryth/enclyzer/blob/master/docker/docker-compose.yml --output docker-compose.yml
docker-compose up
```

This will download the Docker image and launch ENCLYZER within a container.