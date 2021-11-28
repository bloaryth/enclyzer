#include "enclyser/enclave/enclave.h"

#include "enclyser/enclave/enclave_t.h"

uint8_t __attribute__((aligned(0x1000))) secret[DEFAULT_SECRET_BUFFER_SIZE];

/**
 * @brief [ECALL] First fill lfb and then clear lfb by repestive \p filling_sequence and \p clearing_sequence.
 *
 * @param filling_sequence the filling sequence selector
 * @param filling_buffer the buffer that a filling sequence operates on
 * @param clearing_sequence the clearing sequence selector
 * @param clearing_buffer the buffer that a clearing sequence operates on
 * @param faulting_buffer the buffer that raises SIGSEGV if accessed
 */
void ecall_grooming(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer)
{
    fill_lfb(filling_sequence, filling_buffer);
    clear_lfb(clearing_sequence, clearing_buffer);
    // faulting_buffer->buffer[0] = DEFAULT_BUFFER_VALUE;
    (void)faulting_buffer; /** bypass the warning about unsed parameter */
}

/**
 * @brief [ECALL] Repeated calls to fill_lfb.
 *
 * @param filling_sequence the filling sequence selector
 * @param filling_buffer the buffer that a filling sequence operates on
 */
void ecall_rep_fill_lfb(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i;

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(filling_sequence, filling_buffer);
    }
}

uint8_t *ecall_get_secret(void)
{
    return secret;
}

void ecall_assign_secret(enclyser_buffer_t *enclyser_buffer)
{
    assign_enclyser_buffer(enclyser_buffer);
}

void ecall_reload_secret(enclyser_buffer_t *enclyser_buffer)
{
    // // enclyser_buffer->buffer[0] = 1;
    asm volatile(
        "movq (%0), %%rax\n"
        :
        : "r"(enclyser_buffer->buffer));
}

/**
 * @brief [ECALL] Just an empty ECALL.
 *
 */
void ecall_empty(void)
{
    return;
}