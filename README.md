# README

### Supported Platforms

Enclyser is tested on Ubuntu 20.04 with a kernel version of 5.11. It is considered at least effective on the following tested Intel CPUs: e3-1535mv5, i5-6360u, i5-8365u, i9-8950hk, and i7-9850h.

### System Requirements 

Run `cd 3rdparty; sudo bash install.sh` to prepare. This command will automatically calls second-level scripts including `install-linux-sgx-2.13.sh`, `install-linux-sgx-driver-master.sh`, `install-sgx-software-enable-master.sh`, `install-criterion-v2.3.2.sh`, `install-enclyser-prerequisites.sh` and `install-enclyser-settings.sh`. 

| Script Name                           | Functions                                                                           |
| ------------------------------------- | ----------------------------------------------------------------------------------- |
| install-linux-sgx-2.13.sh             | Install SGX SDK of Version 2.13 compatible to SGX-STEP.                             |
| install-linux-sgx-driver-master.sh    | Install SGX Driver of up-to-date Version.                                           |
| install-sgx-software-enable-master.sh | Enable SGX in case the BIOS does not provide options to turn it on.                 |
| install-criterion-v2.3.2.sh           | Install Criterion of Version 2.3.2 that is required by Enclyser.                    |
| install-enclyser-prerequisites.sh     | Install required system packages and python libraries.                              |
| install-enclyser-settings.sh          | Add necessary command line parameter for booting. **Need a reboot to take effect.** |

### Load Kernel Modules

Run `sudo make -C kenclyser clean all unload load` to load the kernel module of Enclyser. 

### Build and Run Tests

Run `sudo make -C enclyser clean all run` to run all tests of Enclyser. By default, all tests are enabled and can be partially disabled by setting `.disabled = on`.

| Test Name                                        | Functions                                                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| same_thread_meltdown_sgx_is_10_percent_effective | Whether Meltdown from the same thread is 10 percent effective (for at least 75% offset) against SGX.   |
| cross_thread_meltdown_sgx_is_1_percent_effective | Whether Meltdown from the sibling thread is 1 percent effective (for at least 75% offset) against SGX. |
| cross_core_meltdown_sgx_is_1_percent_effective   | Whether Meltdown from another core is 1 percent effective (for at least 75% offset) against SGX.       |
| same_thread_l1tf_sgx_is_10_percent_effective     | Whether L1TF from the same thread is 10 percent effective (for at least 75% offset) against SGX.       |
| cross_thread_l1tf_sgx_is_1_percent_effective     | Whether L1TF from the sibling thread is 1 percent effective (for at least 75% offset) against SGX.     |
| cross_core_l1tf_sgx_is_1_percent_effective       | Whether L1TF from another core is 1 percent effective (for at least 75% offset) against SGX.           |
| same_thread_mds_sgx_is_10_percent_effective      | Whether MDS from the same thread is 10 percent effective (for at least 75% offset) against SGX.        |
| cross_thread_mds_sgx_is_1_percent_effective      | Whether MDS from the sibling thread is 1 percent effective (for at least 75% offset) against SGX.      |
| cross_core_mds_sgx_is_1_percent_effective        | Whether MDS from another core is 1 percent effective (for at least 75% offset) against SGX.            |
| same_thread_taa_sgx_is_10_percent_effective      | Whether TAA from the same thread is 10 percent effective (for at least 75% offset) against SGX.        |
| cross_thread_taa_sgx_is_1_percent_effective      | Whether TAA from the sibling thread is 1 percent effective (for at least 75% offset) against SGX.      |
| cross_core_taa_sgx_is_1_percent_effective        | Whether TAA from another core is 1 percent effective (for at least 75% offset) against SGX.            |

