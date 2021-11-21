#ifndef ENCLYSER_LIBENCLYSER_INFO

#define ENCLYSER_LIBENCLYSER_INFO

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

#endif