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

    pclose(fp); /* close */
}

#endif