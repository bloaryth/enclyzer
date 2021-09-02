#include "enclyser/libenclyser/system.h"

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

#endif

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
    ASSERT((fd_mem = open("/dev/mem", O_RDWR)) >= 0);           /** /dev/mem is opened. */
    ASSERT((fd_enclyser = open("/dev/enclyser", O_RDWR)) >= 0); /** /dev/enclyser is opened. */
}

void close_system_file()
{
    ASSERT(fd_mem >= 0);    /** /dev/mem is opened. */
    ASSERT(fd_enclyser >= 0);   /** /dev/enclyser is opened. */
    close(fd_mem);
    close(fd_enclyser);
}

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
    /** ecx is often an input as well as an output. */
    asm volatile(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "0"(*eax), "2"(*ecx));
}

/** FIXME Check the validation of input value. */
static inline void native_rdmsr(unsigned int *eax, unsigned int *ecx, unsigned int *edx)
{
    msr_t msr = {.eax = *eax, .ecx = *ecx, .edx = *edx};

    ASSERT(fd_enclyser >= 0);   /** /dev/enclyser is opened. */
    ASSERT(ioctl(fd_enclyser, KENCLYSER_IOCTL_RDMSR, &msr) >= 0);   /** ioctl returns successfully. */

    *eax = msr.eax;
    *ecx = msr.ecx;
    *edx = msr.edx;
}

void print_system_info()
{
    unsigned int eax, ebx, ecx, edx;
    eax = 7;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    INFO("HLE: %d\n", (ebx >> 4) & 0x1);
    INFO("RTM: %d\n", (ebx >> 11) & 0x1);
    INFO("RTM_ALWAYS_ABORT: %d\n", (edx >> 11) & 0x1);
    INFO("TSX_FORCE_ABORT: %d\n", (edx >> 13) & 0x1);

    if ((edx >> 13) & 0x1)  /** TSX_FORCE_ABORT MSR */
    {
        unsigned int eax, ecx, edx;
        ecx = 0x10f;

        native_rdmsr(&eax, &ecx, &edx);

        INFO("TSX_FORCE_ABORT MSR\n");
        INFO("\tRTM_FORCE_ABORT: %d\n", (eax >> 0) & 0x1);
        INFO("\tTSX_CPUID_CLEAR: %d\n", (eax >> 1) & 0x1);
        INFO("\tSDV_ENABLE_RTM: %d\n", (eax >> 2) & 0x1);
    }

    INFO("SRBDS_CTRL: %d\n", (edx >> 9) & 0x1);
    INFO("MD_CLEAR: %d\n", (edx >> 10) & 0x1);
    INFO("IBRS & IBPB: %d\n", (edx >> 26) & 0x1);
    INFO("STIBP: %d\n", (edx >> 27) & 0x1);
    INFO("L1D_FLUSH: %d\n", (edx >> 28) & 0x1);
    INFO("IA32_ARCH_CAPABILITIES: %d\n", (edx >> 29) & 0x1);
    INFO("SSBD: %d\n", (edx >> 31) & 0x1);
    
    if ((edx >> 29) & 0x1)  /** IA32_ARCH_CAPABILITIES MSR */
    {
        unsigned int eax, ecx, edx;
        ecx = 0x10a;

        native_rdmsr(&eax, &ecx, &edx);

        INFO("IA32_ARCH_CAPABILITIES MSR\n");
        INFO("\tRDCL_NO: %d\n", (eax >> 0) & 0x1);
        INFO("\tIBRS_ALL: %d\n", (eax >> 1) & 0x1);
        INFO("\tRSBA: %d\n", (eax >> 2) & 0x1);
        INFO("\tSKIP_L1DFL_VMENTRY: %d\n", (eax >> 3) & 0x1);
        INFO("\tSSB_NO: %d\n", (eax >> 4) & 0x1);
        INFO("\tMDS_NO: %d\n", (eax >> 5) & 0x1);
        INFO("\tIF_PSCHANGE_MC_NO: %d\n", (eax >> 6) & 0x1);
        INFO("\tTSX_CTRL: %d\n", (eax >> 7) & 0x1);
        INFO("\tTAA_NO: %d\n", (eax >> 8) & 0x1);

        if ((eax >> 7) & 0x1)   /** IA32_TSX_CTRL MSR */
        {
            unsigned int eax, ecx, edx;
            ecx = 0x10a;

            native_rdmsr(&eax, &ecx, &edx);

            INFO("IA32_TSX_CTRL MSR\n");
            INFO("\tRTM_DISABLE: %d\n", (eax >> 0) & 0x1);
            INFO("\tTSX_CPUID_CLEAR: %d\n", (eax >> 1) & 0x1);
        }
    }
    if (((edx >> 26) & 0x1) | ((edx >> 27) & 0x1) | ((edx >> 31) & 0x1))    /** IA32_SPEC_CTRL MSR */
    {
        unsigned int eax, ecx, edx;
        ecx = 0x48;

        native_rdmsr(&eax, &ecx, &edx);

        INFO("IA32_SPEC_CTRL MSR\n");
        INFO("\tIBRS: %d\n", (eax >> 0) & 0x1);
        INFO("\tSTIBP: %d\n", (eax >> 1) & 0x1);
        INFO("\tSSBD: %d\n", (eax >> 2) & 0x1);
    }

    // if ((edx >> 26) & 0x1)  /** IA32_PRED_CMD MSR */
    // {
    //     unsigned int eax, ecx, edx;
    //     ecx = 0x49;
    
    //     native_rdmsr(&eax, &ecx, &edx);
    
    //     INFO("IA32_PRED_CMD MSR\n");
    //     if ((edx >> 26) & 0x1)
    //         INFO("\tIBPB: %d\n", (eax >> 0) & 0x1);
    // }

    if ((edx >> 9) & 0x1)   /** IA32_MCU_OPT_CTRL MSR */
    {
        unsigned int eax, ecx, edx;
        ecx = 0x123;

        native_rdmsr(&eax, &ecx, &edx);

        INFO("IA32_MCU_OPT_CTRL MSR\n");
        if ((edx >> 9) & 0x1)
            INFO("\tRNGDS_MITG_DIS: %d\n", (eax >> 0) & 0x1);
    }

    eax = 1;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    INFO("SSE2: %d\n", (edx >> 26) & 0x1);
    INFO("AVX: %d\n", (ecx >> 28) & 0x1);

    eax = 7;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    INFO("AVX512DQ: %d\n", (ebx >> 17) & 0x1);
}

#endif