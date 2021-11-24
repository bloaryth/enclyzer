#include "enclyser/libenclyser/info.h"

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_YES

#include <stdarg.h>
#include <string.h>

/**
 * @brief the define that limit the maximun length of an print string
 * 
 */
#define PRINTF_BUF_SIZE 256

int printf(const char* fmt, ...)
{
    char buf[PRINTF_BUF_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, PRINTF_BUF_SIZE, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, PRINTF_BUF_SIZE - 1) + 1;
}

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_NO

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

#endif