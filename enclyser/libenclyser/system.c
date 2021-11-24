#include "enclyser/libenclyser/system.h"

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_YES

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_NO

int fd_enclyser = FD_UNINITIALIZED;
int fd_mem = FD_UNINITIALIZED;

void open_system_file()
{
    if (fd_mem == FD_UNINITIALIZED)
        ASSERT((fd_mem = open("/dev/mem", O_RDWR)) >= 0); /** /dev/mem is opened. */
    if (fd_enclyser == FD_UNINITIALIZED)
        ASSERT((fd_enclyser = open("/dev/kenclyser", O_RDWR)) >= 0); /** /dev/enclyser is opened. */
}

void close_system_file()
{
    if (fd_mem >= 0)
        close(fd_mem);
    if (fd_enclyser >= 0)
        close(fd_enclyser);
}

void native_cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    /** ecx is often an input as well as an output. */
    asm volatile(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "0"(*eax), "2"(*ecx));
}

/** FIXME Check the validation of input value. */
void native_rdmsr(uint32_t *eax, uint32_t *ecx, uint32_t *edx)
{
    msr_t msr = {.eax = *eax, .ecx = *ecx, .edx = *edx};

    ASSERT(fd_enclyser >= 0);                                     /** /dev/enclyser is opened. */
    ASSERT(ioctl(fd_enclyser, KENCLYSER_IOCTL_RDMSR, &msr) >= 0); /** ioctl returns successfully. */

    *eax = msr.eax;
    *ecx = msr.ecx;
    *edx = msr.edx;
}

void execute_command(char *command)
{
    FILE *fp;

    command_output[0] = '\0';   /** clear the command_output */

    fp = popen(command, "r");
    ASSERT(fp != NULL); /* open the command for reading. */

    while (fgets(command_output, sizeof(command_output), fp) != NULL)
        ; /* read the output a line at a time - output it. */

    command_output[strcspn(command_output, "\n")] = 0;

    pclose(fp); /* close */
}

void get_system_info(enclyser_sysinfo_t *sysinfo)
{
    uint32_t eax, ebx, ecx, edx;

    /** CPUID */
    eax = 1;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    sysinfo->sse2 = (edx >> 26) & 0x1;
    sysinfo->avx = (ecx >> 28) & 0x1;

    eax = 7;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    sysinfo->hle = (ebx >> 4) & 0x1;
    sysinfo->rtm = (ebx >> 11) & 0x1;
    sysinfo->avx512dq = (ebx >> 17) & 0x1;

    sysinfo->srbds_ctrl = (edx >> 9) & 0x1;
    sysinfo->md_clear = (edx >> 10) & 0x1;
    sysinfo->rtm_always_abort = (edx >> 11) & 0x1;
    sysinfo->tsx_force_abort = (edx >> 13) & 0x1;
    sysinfo->ibrs_ibpb = (edx >> 26) & 0x1;
    sysinfo->stibp = (edx >> 27) & 0x1;
    sysinfo->l1d_flush = (edx >> 28) & 0x1;
    sysinfo->ia32_arch_capabilities = (edx >> 29) & 0x1;
    sysinfo->ssbd = (edx >> 31) & 0x1;

    /** RDMSR */
    if (sysinfo->ibrs_ibpb | sysinfo->stibp | sysinfo->ssbd)
    {
        ecx = 0x48;

        native_rdmsr(&eax, &ecx, &edx);

        sysinfo->ia32_spec_ctrl_msr.ibrs = (eax >> 0) & 0x1;
        sysinfo->ia32_spec_ctrl_msr.stibp = (eax >> 1) & 0x1;
        sysinfo->ia32_spec_ctrl_msr.ssbd = (eax >> 2) & 0x1;
    }

    if (sysinfo->ia32_arch_capabilities)
    {
        ecx = 0x10a;

        native_rdmsr(&eax, &ecx, &edx);

        sysinfo->ia32_arch_capabilities_msr.rdcl_no = (eax >> 0) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.ibrs_all = (eax >> 1) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.rsba = (eax >> 2) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.skip_l1dfl_vmentry = (eax >> 3) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.ssb_no = (eax >> 4) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.mds_no = (eax >> 5) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.if_pschange_mc_no = (eax >> 6) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.tsx_ctrl = (eax >> 7) & 0x1;
        sysinfo->ia32_arch_capabilities_msr.taa_no = (eax >> 8) & 0x1;
    }

    if (sysinfo->tsx_force_abort)
    {
        ecx = 0x10f;

        native_rdmsr(&eax, &ecx, &edx);

        sysinfo->tsx_force_abort_msr.rtm_force_abort = (eax >> 0) & 0x1;
        sysinfo->tsx_force_abort_msr.tsx_cpuid_clear = (eax >> 1) & 0x1;
        sysinfo->tsx_force_abort_msr.sdv_enable_rtm = (eax >> 2) & 0x1;
    }

    if (sysinfo->ia32_arch_capabilities_msr.tsx_ctrl)
    {
        ecx = 0x122;

        native_rdmsr(&eax, &ecx, &edx);

        sysinfo->ia32_tsx_ctrl_msr.rtm_disable = (eax >> 0) & 0x1;
        sysinfo->ia32_tsx_ctrl_msr.tsx_cpuid_clear = (eax >> 1) & 0x1;
    }

    if (sysinfo->srbds_ctrl)
    {
        ecx = 0x123;

        native_rdmsr(&eax, &ecx, &edx);

        sysinfo->ia32_mcu_opt_ctrl_msr.rngds_mitg_dis = (eax >> 0) & 0x1;
    }

    /** COMMAND */
    execute_command("cat /proc/cpuinfo | grep 'model name' -m 1 | sed 's/model name\t: //'");
    strcpy(sysinfo->model_name, command_output);

    execute_command("cat /proc/cpuinfo | grep microcode -m 1 | awk '{print $3;}'");
    strcpy(sysinfo->microcode_version, command_output);

    execute_command("grep -c ^processor /proc/cpuinfo");
    sysinfo->nr_logical_cores = (int) strtoul(command_output, NULL, 10);

    execute_command("grep 'cpu cores' /proc/cpuinfo -m 1 | awk '{print $4}'");
    sysinfo->nr_cores = (int) strtoul(command_output, NULL, 10);
}

void print_system_info(enclyser_sysinfo_t *sysinfo)
{
    INFO("%-32s: %d", "SSE2", sysinfo->sse2);
    INFO("%-32s: %d", "AVX", sysinfo->avx);

    INFO("%-32s: %d", "HLE", sysinfo->hle);
    INFO("%-32s: %d", "RTM", sysinfo->rtm);
    INFO("%-32s: %d", "AVX512DQ", sysinfo->avx512dq);

    INFO("%-32s: %d", "SRBDS_CTRL", sysinfo->srbds_ctrl);
    INFO("%-32s: %d", "MD_CLEAR", sysinfo->md_clear);
    INFO("%-32s: %d", "RTM_ALWAYS_ABORT", sysinfo->rtm_always_abort);
    INFO("%-32s: %d", "TSX_FORCE_ABORT", sysinfo->tsx_force_abort);
    INFO("%-32s: %d", "IBRS_IBPB", sysinfo->ibrs_ibpb);
    INFO("%-32s: %d", "STIBP", sysinfo->stibp);
    INFO("%-32s: %d", "L1D_FLUSH", sysinfo->l1d_flush);
    INFO("%-32s: %d", "IA32_ARCH_CAPABILITIES", sysinfo->ia32_arch_capabilities);
    INFO("%-32s: %d", "SSBD", sysinfo->ssbd);

    if (sysinfo->ibrs_ibpb | sysinfo->stibp | sysinfo->ssbd)
    {
        INFO("IA32_SPEC_CTRL MSR");
        INFO("%-32s: %d", "    IBRS", sysinfo->ia32_spec_ctrl_msr.ibrs);
        INFO("%-32s: %d", "    STIBP", sysinfo->ia32_spec_ctrl_msr.stibp);
        INFO("%-32s: %d", "    SSBD", sysinfo->ia32_spec_ctrl_msr.ssbd);
    }

    if (sysinfo->ia32_arch_capabilities)
    {
        INFO("IA32_ARCH_CAPABILITIES MSR");
        INFO("%-32s: %d", "    RDCL_NO", sysinfo->ia32_arch_capabilities_msr.rdcl_no);
        INFO("%-32s: %d", "    IBRS_ALL", sysinfo->ia32_arch_capabilities_msr.ibrs_all);
        INFO("%-32s: %d", "    RSBA", sysinfo->ia32_arch_capabilities_msr.rsba);
        INFO("%-32s: %d", "    SKIP_L1DFL_VMENTRY", sysinfo->ia32_arch_capabilities_msr.skip_l1dfl_vmentry);
        INFO("%-32s: %d", "    SSB_NO", sysinfo->ia32_arch_capabilities_msr.ssb_no);
        INFO("%-32s: %d", "    MDS_NO", sysinfo->ia32_arch_capabilities_msr.mds_no);
        INFO("%-32s: %d", "    IF_PSCHANGE_MC_NO", sysinfo->ia32_arch_capabilities_msr.if_pschange_mc_no);
        INFO("%-32s: %d", "    TSX_CTRL", sysinfo->ia32_arch_capabilities_msr.tsx_ctrl);
        INFO("%-32s: %d", "    TAA_NO", sysinfo->ia32_arch_capabilities_msr.taa_no);
    }

    if (sysinfo->tsx_force_abort)
    {
        INFO("TSX_FORCE_ABORT MSR");
        INFO("%-32s: %d", "    RTM_FORCE_ABORT", sysinfo->tsx_force_abort_msr.rtm_force_abort);
        INFO("%-32s: %d", "    TSX_CPUID_CLEAR", sysinfo->tsx_force_abort_msr.tsx_cpuid_clear);
        INFO("%-32s: %d", "    SDV_ENABLE_RTM", sysinfo->tsx_force_abort_msr.sdv_enable_rtm);
    }

    if (sysinfo->ia32_arch_capabilities_msr.tsx_ctrl)
    {
        INFO("IA32_TSX_CTRL MSR");
        INFO("%-32s: %d", "    RTM_DISABLE", sysinfo->ia32_tsx_ctrl_msr.rtm_disable);
        INFO("%-32s: %d", "    TSX_CPUID_CLEAR", sysinfo->ia32_tsx_ctrl_msr.tsx_cpuid_clear);
    }

    if (sysinfo->srbds_ctrl)
    {
        INFO("IA32_MCU_OPT_CTRL MSR");
        INFO("%-32s: %d", "    RNGDS_MITG_DIS", sysinfo->ia32_mcu_opt_ctrl_msr.rngds_mitg_dis);
    }

    INFO("%-32s: %s", "MODEL_NAME", sysinfo->model_name);
    INFO("%-32s: %s", "MICROCODE_VERSION", sysinfo->microcode_version);
    INFO("%-32s: %d", "NR_LOGICAL_CORES", sysinfo->nr_logical_cores);
    INFO("%-32s: %d", "NR_CORES", sysinfo->nr_cores);
}

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

#endif