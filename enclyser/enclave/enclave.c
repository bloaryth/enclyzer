#include "enclyser/enclave/enclave.h"
#include "enclyser/enclave/enclave_t.h"

void ecall_grooming(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer)
{
    fill_lfb(filling_sequence, filling_buffer);
    clear_lfb(clearing_sequence, clearing_buffer);
    faulting_buffer->buffer[0] = DEFAULT_BUFFER_VALUE;
}

void ecall_rep_fill_lfb(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i;

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(filling_sequence, filling_buffer);
    }
}

void ecall_empty()
{
    return;
}

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