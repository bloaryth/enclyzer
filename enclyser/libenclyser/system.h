#ifndef ENCLYSER_LIBENCLYSER_SYSTEM

#define ENCLYSER_LIBENCLYSER_SYSTEM

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"

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

#include "kenclyser/kenclyser_ioctl.h"

/**
 * @brief the file descriptors used by the project
 *
 */
extern int fd_enclyser;
extern int fd_mem;

/**
 * @brief the enum defines for file descriptors.
 *
 */
#define FD_UNINITIALIZED -1

char command_output[1024];

/**
 * @brief Open the file required by the project.
 *
 */
void open_system_file(void);

/**
 * @brief Close the file required by the project.
 *
 */
void close_system_file(void);

/**
 * @brief a function of the cpuid instruction
 *
 * @param eax the eax register
 * @param ebx the ebx register
 * @param ecx the ecx register
 * @param edx the edx register
 */
void native_cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

/**
 * @brief a function of the rdmsr instruction
 *
 * @param eax the eax register
 * @param ecx the ecx register
 * @param edx the edx register
 */
void native_rdmsr(uint32_t *eax, uint32_t *ecx, uint32_t *edx);

/**
 * @brief Execute shell command and store output to \p command_output.
 *
 * @param command the command string to execute
 */
void execute_command(char *command);

/**
 * @brief Get the system info of the current platform.
 *
 * @param sysinfo a struct that describes the system
 */
void get_system_info(enclyser_sysinfo_t *sysinfo);

/**
 * @brief Print the system information that is related to the project.
 *
 * @param sysinfo a struct that describes the system
 */
void print_system_info(enclyser_sysinfo_t *sysinfo);

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

#endif

#endif