#ifndef ENCLYSER_LIBENCLYSER_INFO

#define ENCLYSER_LIBENCLYSER_INFO

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)

#define info(msg, ...)                                                  \
    do {                                                                \
        printf("[" __FILE__ "] " msg "\n", ##__VA_ARGS__);              \
        fflush(stdout);                                                 \
    } while(0)

#if LIBENCLYSER_SILENT
    #define INFO(msg, ...) 
#else
    #define INFO(msg, ...) info(msg, ##__VA_ARGS__)
#endif

#endif

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_YES

/**
 * @brief the define that limit the maximun length of an print string
 * 
 */
#define PRINTF_BUF_SIZE 256

#include <stdarg.h>
#include <string.h>

/**
 * @brief Invokes OCALL to display the enclave buffer to the terminal.
 * 
 * @param fmt the format string to written to stdout
 * @param ... a list of values to be used to replace a format specifier in the format string
 * @return int On success, the total number of characters written is returned.
 */
int printf(const char* fmt, ...);

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_NO

/**
 * @brief Print a string in a ocall function.
 * 
 * @param str a string to be printed
 */
void ocall_print_string(const char *str);

#endif

#ifdef __cplusplus
}
#endif

#endif