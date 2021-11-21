#include "enclyser/enclave/enclave.h"
#include "enclyser/enclave/enclave_t.h"

uint8_t __attribute__ ((aligned(0x1000))) secret[DEFAULT_SECRET_BUFFER_SIZE];

void ecall_grooming(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer)
{
    fill_lfb(filling_sequence, filling_buffer);
    clear_lfb(clearing_sequence, clearing_buffer);
    // faulting_buffer->buffer[0] = DEFAULT_BUFFER_VALUE;
}

void ecall_rep_fill_lfb(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i;

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(filling_sequence, filling_buffer);
    }
}

uint8_t *ecall_get_secret()
{
    return secret;
}

void ecall_assign_secret(enclyser_buffer_t *enclyser_buffer)
{
    assign_enclyser_buffer(enclyser_buffer);
}

void ecall_reload_secret(enclyser_buffer_t *enclyser_buffer)
{
    // enclyser_buffer->buffer[0] = 1;
    asm volatile(
        "movq (%0), %%rax\n"
        :
        : "r" (enclyser_buffer->buffer)
    );
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