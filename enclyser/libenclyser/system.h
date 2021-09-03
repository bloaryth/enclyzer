#ifndef ENCLYSER_LIBENCLYSER_SYSTEM

#define ENCLYSER_LIBENCLYSER_SYSTEM

#ifdef __cplusplus
extern "C" {
#endif

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"

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

#include <fcntl.h> // open function
#include <unistd.h> // close function
#include <sys/ioctl.h>

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
#define FD_UNINITIALIZED    -1

/**
 * @brief Open the file required by the project.
 * 
 */
void open_system_file();

/**
 * @brief Close the file required by the project.
 * 
 */
void close_system_file();

/**
 * @brief Print the system information that is related to the project.
 * 
 */
void print_system_info();

#endif

#ifdef __cplusplus
}
#endif

#endif