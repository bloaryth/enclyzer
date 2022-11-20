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

### Supported Platforms

Enclyzer is tested on Ubuntu 20.04 with a kernel version of 5.11. It is considered at least effective on three micro-architectures: Skylake, Kaybe Lake and Coffee, with these CPUs tested: e3-1535mv5, i5-6360u, i5-8365u, i9-8950hk, and i7-9850h.

### System Requirements 

Run `cd 3rdparty; sudo bash install.sh` to install third-party packages required by Enclyzer. This command will automatically call second-level scripts including `install-linux-sgx-2.13.sh`, `install-linux-sgx-driver-master.sh`, `install-sgx-software-enable-master.sh`, `install-criterion-v2.3.2.sh`, `install-enclyser-prerequisites.sh` and `install-enclyser-settings.sh`. 

| Script Name                           | Functions                                                                           |
| ------------------------------------- | ----------------------------------------------------------------------------------- |
| install-linux-sgx-2.13.sh             | Install SGX SDK of Version 2.13 compatible to [SGX-STEP](https://github.com/jovanbulck/sgx-step).                             |
| install-linux-sgx-driver-master.sh    | Install SGX Driver of up-to-date Version.                                           |
| install-sgx-software-enable-master.sh | Enable SGX in case the BIOS does not provide options to turn it on.                 |
| install-criterion-v2.3.2.sh           | Install Criterion of Version 2.3.2 that is required by Enclyzer.                    |
| install-enclyser-prerequisites.sh     | Install required system packages and python libraries.                              |
| install-enclyser-settings.sh          | Add necessary command line parameter for booting. **Need a reboot to take effect.** |

### Load Kernel Modules

Run `sudo make -C kenclyser clean all unload load` to load the kernel module of Enclyzer. 

### Build and Run Tests

Run `sudo make -C enclyser clean all run` to build and run all tests of Enclyzer. By default, all tests are enabled and can be partially disabled by setting `.disabled = on`. Print out content of `enclyser/sgx_app.txt` to see the execution results. For example, `cat enclyser/sgx_app.txt`

### TODO

- [ ] Code Refactoring
	- [ ] Rename files and functions: lfb -> micro
	- [ ] Rename files and macros: enclyser -> enclyzer
- [ ] Docs Update
	- [ ] README, README_ZH
	- [ ] Doxygen Docs, Host Documentation Website
	- [ ] Post slides and videos for SEED22
- [ ] Usability Update
	- [ ] Instant Notification Configuration
	- [ ] Code Fingerprint in reports
	- [ ] Consistent .stignore among machines