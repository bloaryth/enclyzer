# Enclyzer: Automated Analysis of Transient Data Leaks for Intel SGX

```biblatex
@inproceedings{zhou2022enclyzer,
  title={ENCLYZER: Automated Analysis of Transient Data Leaks on Intel SGX},
  author={Zhou, Jiuqin and Xiao, Yuan and Teodorescu, Radu and Zhang, Yinqian},
  booktitle={2022 IEEE International Symposium on Secure and Private Execution Environment Design (SEED)},
  pages={145--156},
  year={2022},
  organization={IEEE}
}
```

### How tu Setup

1. Use a live usb (or other ways) to install an `Ubuntu 20.04` Linux distribution on the tested machine.

> [intel/linux-sgx: Intel SGX for Linux*](https://github.com/intel/linux-sgx):
>
> - Ensure that you have one of the following required operating systems: 
> 	- Ubuntu* 20.04 LTS Desktop 64bits
> 	- ...

2. Acquire and install the oldest BIOS image on the tested machine from its manufacturer.

> **ENCLYZER: Automated Analysis of Transient Data Leaks on
Intel SGX**
>
> According to an Intel Deep Dive [document](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/microcode-update-guidance.html), the microcode of a machine is decided by roughly four stages, in the ascending time order, namely Firmware Interface Table (FIT) microcode update, BIOS microcode update, OS microcode update, and runtime update. The newest microcode found in the four stages will take effect.

> &#x26a0;&#xfe0f; BIOS image is not included in this repository. You need to find by yourself because it is manufacturer-specific and typically not available online.

3. Clone this repository to the tested computer.

```shell
$ git clone https://github.com/bloaryth/enclyzer.git
```

4. Install third party libraries that enclyzer depends on.

```shell
$ cd 3rdparty
$ sudo bash install.sh
```

> The above commands are equivalent to the following ones:
> 
> ```shell
> $ cd 3rdparty
> $ sudo bash install-linux-sgx-2.13.sh
> $ sudo bash install-linux-sgx-driver-master.sh
> $ sudo bash install-sgx-software-enable-master.sh
> $ sudo bash install-criterion-v2.3.2.sh
> $ sudo bash install-enclyzer-prerequisites.sh
> $ sudo bash install-enclyzer-settings.sh
> ```

| Script Name                           | Functions                                                                           |
| ------------------------------------- | ----------------------------------------------------------------------------------- |
| install-linux-sgx-2.13.sh             | Install SGX SDK of version 2.13 compatible to [SGX-STEP](https://github.com/jovanbulck/sgx-step).                             |
| install-linux-sgx-driver-master.sh    | Install SGX Driver of up-to-date version.                                           |
| install-sgx-software-enable-master.sh | Enable SGX in case the BIOS does not provide options to turn it on.                 |
| install-criterion-v2.3.2.sh           | Install Criterion of version 2.3.2 that is required by Enclyzer.                    |
| install-enclyzer-prerequisites.sh     | Install required system packages and python libraries.                              |
| install-enclyzer-settings.sh          | Add necessary command line parameter for booting. <br/>**Need a reboot to take effect.** |

> &#x26a0;&#xfe0f; If the kernel version of the tested machine is automatically updated on Ubuntu, it is neccessary to rebuild the sgx driver. Run the following commands before reboot:
> ```shell
> sudo bash install-linux-sgx-driver-master.sh
> ```

5. Run the following scripts to rollback the microcode provided by OS start.

```shell
cd scripts/microcode-update
sudo bash early-os-update 20180312
```

6. Reboot the machine.

### How to Run

1. Update the microcode version to a targeted one.

```shell
cd scripts/microcode-update
sudo bash runtime-update 20200616
```

2. Load kernel modules (from the root directory)

```shell
$ sudo make -C kenclyzer clean all unload load
```

3. Build and run tests  (from the root directory)

```shell
sudo make -C enclyzer clean all run
```

> &#x26a0;&#xfe0f; By default, all tests are disabled by `.disabled = true` and need to be mannually enabled by setting `.disabled = false`. The output of tests are redirected to a file `enclyzer/sgx_app.txt`, which is configured in `enclyzer/Makefile`.

### Supported Platforms

Enclyzer is tested on Ubuntu 20.04 with a kernel version of 5.11. 

It is considered at least effective on three micro-architectures: Skylake, Kaybe Lake and Coffee, with these CPUs tested: e3-1535mv5, i5-6360u, i5-8365u, i9-8950hk, and i7-9850h.

### Example Output

```txt
[[----] Criterion v2.3.2
[====] Running 1 test from _system:
[RUN ] _system::print_system_info
cat: write error: Broken pipe
[PASS] _system::print_system_info: (0.04s)
[system.c] SSE2                            : 1
[system.c] AVX                             : 1
[system.c] HLE                             : 1
[system.c] RTM                             : 1
[system.c] AVX512DQ                        : 0
[system.c] SRBDS_CTRL                      : 0
[system.c] MD_CLEAR                        : 0
[system.c] RTM_ALWAYS_ABORT                : 0
[system.c] TSX_FORCE_ABORT                 : 0
[system.c] IBRS_IBPB                       : 1
[system.c] STIBP                           : 1
[system.c] L1D_FLUSH                       : 0
[system.c] IA32_ARCH_CAPABILITIES          : 0
[system.c] SSBD                            : 0
[system.c] IA32_SPEC_CTRL MSR
[system.c]     IBRS                        : 0
[system.c]     STIBP                       : 0
[system.c]     SSBD                        : 0
[system.c] MODEL_NAME                      : Intel(R) Core(TM) i5-6360U CPU @ 2.00GHz
[system.c] MICROCODE_VERSION               : 0xc2
[system.c] NR_LOGICAL_CORES                : 4
[system.c] NR_CORES                        : 2
[====] Running 6 tests from l1tf:
[RUN ] l1tf::l1tf_cc_nosgx
cat: write error: Broken pipe
[WARN] L1TF CC NOSGX GP_LOAD 0x81: 0.000000 %
[WARN] L1TF CC NOSGX GP_STORE 0x81: 0.000000 %
[WARN] L1TF CC NOSGX NT_LOAD 0x81: 0.000000 %
[WARN] L1TF CC NOSGX NT_STORE 0x81: 0.000000 %
[WARN] L1TF CC NOSGX STR_LOAD 0x81: 0.000000 %
[WARN] L1TF CC NOSGX STR_STORE 0x81: 0.000000 %
[PASS] l1tf::l1tf_cc_nosgx: (14.13s)
[RUN ] l1tf::l1tf_cc_sgx
[WARN] L1TF CC SGX GP_LOAD 0xa1: 0.000000 %
[WARN] L1TF CC SGX GP_STORE 0xa1: 0.000000 %
[WARN] L1TF CC SGX NT_LOAD 0xa1: 0.000000 %
[WARN] L1TF CC SGX NT_STORE 0xa1: 0.000000 %
[WARN] L1TF CC SGX STR_LOAD 0xa1: 0.000000 %
[WARN] L1TF CC SGX STR_STORE 0xa1: 0.000000 %
[PASS] l1tf::l1tf_cc_sgx: (41.00s)
[RUN ] l1tf::l1tf_ct_nosgx
[WARN] L1TF CT NOSGX GP_LOAD 0x41: 6.921875 %
[WARN] L1TF CT NOSGX GP_STORE 0x41: 27.328125 %
[WARN] L1TF CT NOSGX NT_LOAD 0x41: 6.921875 %
[WARN] L1TF CT NOSGX NT_STORE 0x41: 1.281250 %
[WARN] L1TF CT NOSGX STR_LOAD 0x41: 55.406250 %
[WARN] L1TF CT NOSGX STR_STORE 0x41: 27.531250 %
[PASS] l1tf::l1tf_ct_nosgx: (14.28s)
[RUN ] l1tf::l1tf_ct_sgx
[WARN] L1TF CT SGX GP_LOAD 0x61: 32.609375 %
[WARN] L1TF CT SGX GP_STORE 0x61: 36.859375 %
[WARN] L1TF CT SGX NT_LOAD 0x61: 36.468750 %
[WARN] L1TF CT SGX NT_STORE 0x61: 0.031250 %
[WARN] L1TF CT SGX STR_LOAD 0x61: 56.875000 %
[WARN] L1TF CT SGX STR_STORE 0x61: 51.531250 %
[PASS] l1tf::l1tf_ct_sgx: (42.33s)
[RUN ] l1tf::l1tf_st_nosgx
[WARN] L1TF ST NOSGX GP_LOAD 0x1: 99.937500 %
[WARN] L1TF ST NOSGX GP_STORE 0x1: 100.000000 %
[WARN] L1TF ST NOSGX NT_LOAD 0x1: 99.921875 %
[WARN] L1TF ST NOSGX NT_STORE 0x1: 0.000000 %
[WARN] L1TF ST NOSGX STR_LOAD 0x1: 99.875000 %
[WARN] L1TF ST NOSGX STR_STORE 0x1: 99.968750 %
[PASS] l1tf::l1tf_st_nosgx: (11.54s)
[RUN ] l1tf::l1tf_st_sgx
[WARN] L1TF ST SGX GP_LOAD 0x21: 98.906250 %
[WARN] L1TF ST SGX GP_STORE 0x21: 98.796875 %
[WARN] L1TF ST SGX NT_LOAD 0x21: 98.031250 %
[WARN] L1TF ST SGX NT_STORE 0x21: 0.000000 %
[WARN] L1TF ST SGX STR_LOAD 0x21: 98.296875 %
[WARN] L1TF ST SGX STR_STORE 0x21: 96.703125 %
[PASS] l1tf::l1tf_st_sgx: (12.15s)
[====] Running 6 tests from mds:
[RUN ] mds::mds_cc_nosgx
[WARN] MDS CC NOSGX GP_LOAD 0x81: 0.000000 %
[WARN] MDS CC NOSGX GP_STORE 0x81: 0.000000 %
[WARN] MDS CC NOSGX NT_LOAD 0x81: 0.015625 %
[WARN] MDS CC NOSGX NT_STORE 0x81: 0.015625 %
[WARN] MDS CC NOSGX STR_LOAD 0x81: 0.000000 %
[WARN] MDS CC NOSGX STR_STORE 0x81: 0.000000 %
[PASS] mds::mds_cc_nosgx: (16.84s)
[RUN ] mds::mds_cc_sgx
[WARN] MDS CC SGX GP_LOAD 0xa1: 0.062500 %
[WARN] MDS CC SGX GP_STORE 0xa1: 0.062500 %
[WARN] MDS CC SGX NT_LOAD 0xa1: 0.062500 %
[WARN] MDS CC SGX NT_STORE 0xa1: 0.046875 %
[WARN] MDS CC SGX STR_LOAD 0xa1: 0.031250 %
[WARN] MDS CC SGX STR_STORE 0xa1: 0.062500 %
[PASS] mds::mds_cc_sgx: (41.71s)
[RUN ] mds::mds_ct_nosgx
[WARN] MDS CT NOSGX GP_LOAD 0x41: 14.921875 %
[WARN] MDS CT NOSGX GP_STORE 0x41: 25.562500 %
[WARN] MDS CT NOSGX NT_LOAD 0x41: 19.265625 %
[WARN] MDS CT NOSGX NT_STORE 0x41: 57.375000 %
[WARN] MDS CT NOSGX STR_LOAD 0x41: 18.781250 %
[WARN] MDS CT NOSGX STR_STORE 0x41: 31.812500 %
[PASS] mds::mds_ct_nosgx: (17.32s)
[RUN ] mds::mds_ct_sgx
[WARN] MDS CT SGX GP_LOAD 0x61: 8.218750 %
[WARN] MDS CT SGX GP_STORE 0x61: 14.968750 %
[WARN] MDS CT SGX NT_LOAD 0x61: 13.218750 %
[WARN] MDS CT SGX NT_STORE 0x61: 31.390625 %
[WARN] MDS CT SGX STR_LOAD 0x61: 10.265625 %
[WARN] MDS CT SGX STR_STORE 0x61: 18.968750 %
[PASS] mds::mds_ct_sgx: (42.39s)
[RUN ] mds::mds_st_nosgx
[WARN] MDS ST NOSGX GP_LOAD 0x1: 86.187500 %
[WARN] MDS ST NOSGX GP_STORE 0x1: 86.968750 %
[WARN] MDS ST NOSGX NT_LOAD 0x1: 86.812500 %
[WARN] MDS ST NOSGX NT_STORE 0x1: 86.281250 %
[WARN] MDS ST NOSGX STR_LOAD 0x1: 86.968750 %
[WARN] MDS ST NOSGX STR_STORE 0x1: 86.218750 %
[PASS] mds::mds_st_nosgx: (11.49s)
[RUN ] mds::mds_st_sgx
[WARN] MDS ST SGX GP_LOAD 0x21: 0.031250 %
[WARN] MDS ST SGX GP_STORE 0x21: 77.968750 %
[WARN] MDS ST SGX NT_LOAD 0x21: 0.031250 %
[WARN] MDS ST SGX NT_STORE 0x21: 0.218750 %
[WARN] MDS ST SGX STR_LOAD 0x21: 0.031250 %
[WARN] MDS ST SGX STR_STORE 0x21: 69.328125 %
[PASS] mds::mds_st_sgx: (11.75s)
[====] Running 6 tests from meltdown:
[RUN ] meltdown::meltdown_cc_nosgx
[WARN] MELTDOWN CC NOSGX GP_LOAD 0x81: 0.000000 %
[WARN] MELTDOWN CC NOSGX GP_STORE 0x81: 0.000000 %
[WARN] MELTDOWN CC NOSGX NT_LOAD 0x81: 0.000000 %
[WARN] MELTDOWN CC NOSGX NT_STORE 0x81: 0.000000 %
[WARN] MELTDOWN CC NOSGX STR_LOAD 0x81: 0.000000 %
[WARN] MELTDOWN CC NOSGX STR_STORE 0x81: 0.000000 %
[PASS] meltdown::meltdown_cc_nosgx: (13.55s)
[RUN ] meltdown::meltdown_cc_sgx
[WARN] MELTDOWN CC SGX GP_LOAD 0xa1: 0.000000 %
[WARN] MELTDOWN CC SGX GP_STORE 0xa1: 0.000000 %
[WARN] MELTDOWN CC SGX NT_LOAD 0xa1: 0.000000 %
[WARN] MELTDOWN CC SGX NT_STORE 0xa1: 0.000000 %
[WARN] MELTDOWN CC SGX STR_LOAD 0xa1: 0.000000 %
[WARN] MELTDOWN CC SGX STR_STORE 0xa1: 0.000000 %
[PASS] meltdown::meltdown_cc_sgx: (40.74s)
[RUN ] meltdown::meltdown_ct_nosgx
[WARN] MELTDOWN CT NOSGX GP_LOAD 0x41: 10.375000 %
[WARN] MELTDOWN CT NOSGX GP_STORE 0x41: 22.703125 %
[WARN] MELTDOWN CT NOSGX NT_LOAD 0x41: 10.062500 %
[WARN] MELTDOWN CT NOSGX NT_STORE 0x41: 0.843750 %
[WARN] MELTDOWN CT NOSGX STR_LOAD 0x41: 51.031250 %
[WARN] MELTDOWN CT NOSGX STR_STORE 0x41: 24.156250 %
[PASS] meltdown::meltdown_ct_nosgx: (14.22s)
[RUN ] meltdown::meltdown_ct_sgx
[WARN] MELTDOWN CT SGX GP_LOAD 0x61: 0.000000 %
[WARN] MELTDOWN CT SGX GP_STORE 0x61: 0.000000 %
[WARN] MELTDOWN CT SGX NT_LOAD 0x61: 0.000000 %
[WARN] MELTDOWN CT SGX NT_STORE 0x61: 0.000000 %
[WARN] MELTDOWN CT SGX STR_LOAD 0x61: 0.000000 %
[WARN] MELTDOWN CT SGX STR_STORE 0x61: 0.000000 %
[PASS] meltdown::meltdown_ct_sgx: (42.78s)
[RUN ] meltdown::meltdown_st_nosgx
[WARN] MELTDOWN ST NOSGX GP_LOAD 0x1: 99.765625 %
[WARN] MELTDOWN ST NOSGX GP_STORE 0x1: 99.812500 %
[WARN] MELTDOWN ST NOSGX NT_LOAD 0x1: 99.890625 %
[WARN] MELTDOWN ST NOSGX NT_STORE 0x1: 0.000000 %
[WARN] MELTDOWN ST NOSGX STR_LOAD 0x1: 99.812500 %
[WARN] MELTDOWN ST NOSGX STR_STORE 0x1: 99.359375 %
[PASS] meltdown::meltdown_st_nosgx: (11.71s)
[RUN ] meltdown::meltdown_st_sgx
[WARN] MELTDOWN ST SGX GP_LOAD 0x21: 0.000000 %
[WARN] MELTDOWN ST SGX GP_STORE 0x21: 0.000000 %
[WARN] MELTDOWN ST SGX NT_LOAD 0x21: 0.000000 %
[WARN] MELTDOWN ST SGX NT_STORE 0x21: 0.000000 %
[WARN] MELTDOWN ST SGX STR_LOAD 0x21: 0.000000 %
[WARN] MELTDOWN ST SGX STR_STORE 0x21: 0.000000 %
[PASS] meltdown::meltdown_st_sgx: (11.76s)
[====] Running 6 tests from taa:
[RUN ] taa::taa_cc_nosgx
[WARN] TAA CC NOSGX GP_LOAD 0x81: 0.000000 %
[WARN] TAA CC NOSGX GP_STORE 0x81: 0.000000 %
[WARN] TAA CC NOSGX NT_LOAD 0x81: 0.000000 %
[WARN] TAA CC NOSGX NT_STORE 0x81: 0.015625 %
[WARN] TAA CC NOSGX STR_LOAD 0x81: 0.015625 %
[WARN] TAA CC NOSGX STR_STORE 0x81: 0.000000 %
[PASS] taa::taa_cc_nosgx: (16.77s)
[RUN ] taa::taa_cc_sgx
[WARN] TAA CC SGX GP_LOAD 0xa1: 0.031250 %
[WARN] TAA CC SGX GP_STORE 0xa1: 0.000000 %
[WARN] TAA CC SGX NT_LOAD 0xa1: 0.015625 %
[WARN] TAA CC SGX NT_STORE 0xa1: 0.078125 %
[WARN] TAA CC SGX STR_LOAD 0xa1: 0.062500 %
[WARN] TAA CC SGX STR_STORE 0xa1: 0.015625 %
[PASS] taa::taa_cc_sgx: (40.75s)
[RUN ] taa::taa_ct_nosgx
[WARN] TAA CT NOSGX GP_LOAD 0x41: 3.015625 %
[WARN] TAA CT NOSGX GP_STORE 0x41: 5.968750 %
[WARN] TAA CT NOSGX NT_LOAD 0x41: 4.156250 %
[WARN] TAA CT NOSGX NT_STORE 0x41: 6.593750 %
[WARN] TAA CT NOSGX STR_LOAD 0x41: 3.312500 %
[WARN] TAA CT NOSGX STR_STORE 0x41: 5.250000 %
[PASS] taa::taa_ct_nosgx: (17.41s)
[RUN ] taa::taa_ct_sgx
[WARN] TAA CT SGX GP_LOAD 0x61: 5.703125 %
[WARN] TAA CT SGX GP_STORE 0x61: 10.703125 %
[WARN] TAA CT SGX NT_LOAD 0x61: 6.468750 %
[WARN] TAA CT SGX NT_STORE 0x61: 16.562500 %
[WARN] TAA CT SGX STR_LOAD 0x61: 5.203125 %
[WARN] TAA CT SGX STR_STORE 0x61: 9.671875 %
[PASS] taa::taa_ct_sgx: (42.43s)
[RUN ] taa::taa_st_nosgx
[WARN] TAA ST NOSGX GP_LOAD 0x1: 91.453125 %
[WARN] TAA ST NOSGX GP_STORE 0x1: 91.625000 %
[WARN] TAA ST NOSGX NT_LOAD 0x1: 90.718750 %
[WARN] TAA ST NOSGX NT_STORE 0x1: 90.328125 %
[WARN] TAA ST NOSGX STR_LOAD 0x1: 91.015625 %
[WARN] TAA ST NOSGX STR_STORE 0x1: 92.625000 %
[PASS] taa::taa_st_nosgx: (11.51s)
[RUN ] taa::taa_st_sgx
[WARN] TAA ST SGX GP_LOAD 0x21: 57.234375 %
[WARN] TAA ST SGX GP_STORE 0x21: 63.140625 %
[WARN] TAA ST SGX NT_LOAD 0x21: 57.609375 %
[WARN] TAA ST SGX NT_STORE 0x21: 25.187500 %
[WARN] TAA ST SGX STR_LOAD 0x21: 53.609375 %
[WARN] TAA ST SGX STR_STORE 0x21: 59.656250 %
[PASS] taa::taa_st_sgx: (11.76s)
[====] Synthesis: Tested: 25 | Passing: 25 | Failing: 0 | Crashing: 0 
```

