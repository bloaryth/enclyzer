#ifndef ENCLYSER_LIBENCLYSER_INFO

#define ENCLYSER_LIBENCLYSER_INFO

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 *
 */
#ifdef NAMESPACE_SGX_YES

#include "enclyser/libenclyser/info_t.h"

/**
 * @brief Invokes OCALL to display the enclave buffer to the terminal.
 *
 * @param fmt the format string to written to stdout
 * @param ... a list of values to be used to replace a format specifier in the format string
 * @return int On success, the total number of characters written is returned.
 */
int printf(const char *fmt, ...);

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_NO

#include "enclyser/libenclyser/info_u.h"

/**
 * @brief Print a string in a ocall function.
 *
 * @param str a string to be printed
 */
void ocall_print_string(const char *str);

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ASSERT(cond)                                               \
    do                                                             \
    {                                                              \
        if (!(cond))                                               \
        {                                                          \
            perror("[" __FILE__ "] assertion '" #cond "' failed"); \
            abort();                                               \
        }                                                          \
    } while (0)

#define EXPECT(cond)                                               \
    do                                                             \
    {                                                              \
        if (!(cond))                                               \
        {                                                          \
            perror("[" __FILE__ "] assertion '" #cond "' failed"); \
        }                                                          \
    } while (0)

#define INFO(msg, ...)                                     \
    do                                                     \
    {                                                      \
        printf("[" __FILE__ "] " msg "\n", ##__VA_ARGS__); \
        fflush(stdout);                                    \
    } while (0)

#endif

#endif