#include "enclyzer/libenclyzer/lfb.h"

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_YES

#include "enclyzer/libenclyzer/lfb_t.h"

/**
 * @brief [ECALL] Fill the internal buffer LFB via different sequences.
 *
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
void ecall_fill_lfb(int filling_sequence, buffer_t *filling_buffer)
{
    fill_lfb(filling_sequence, filling_buffer);
}

/**
 * @brief [ECALL] Clear the internal buffer LFB via different sequences.
 *
 * @param clearing_sequence a number to choose which sequence will be used
 * @param clearing_buffer the buffer which the function operates on
 */
void ecall_clear_lfb(int clearing_sequence, buffer_t *clearing_buffer)
{
    clear_lfb(clearing_sequence, clearing_buffer);
}

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_NO

#include "enclyzer/libenclyzer/lfb_u.h"

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

/**
 * @brief Fill the internal buffer LFB via different gp_load sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_gp_load(int filling_sequence, buffer_t *filling_buffer)
{
    int i = 0;

    for (i = 0; i < filling_buffer->size; i += CACHELINE_SIZE) /** movq is preferred than movb */
    {
        asm volatile(
            "movq (%0), %%rax\n"
            :
            : "r"(filling_buffer->buffer + i)
            : "rax");
    }
}

/**
 * @brief Fill the internal buffer LFB via different gp_store sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_gp_store(int filling_sequence, buffer_t *filling_buffer)
{
    uint64_t rdi, rsi, rdx, rcx;

    if (filling_buffer->size % 8 != 0)
    {
        // INFO("filling_buffer->size must be 8 byte aligned");
        return;
    }

    rdi = (uint64_t)filling_buffer->buffer; /** incremented during the process */
    rsi = (uint64_t)filling_buffer->value;  /** consistent during the process */
    rdx = (uint64_t)filling_buffer->size;   /** consistent during the process */
    rcx = (uint64_t)(CACHELINE_SIZE - 1);   /** consistent during the process, the cacheline mask */

    switch (filling_buffer->order) /** movq is preferred than movb */
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        asm volatile(
            "movq %%rdx, %%r10\n" /** r10 = rdx */
            "2:cmp $0, %%r10\n"
            "je 1f\n"
            "subq $8, %%r10\n"
            "movq %%rsi, %%rax\n" /** rax = rsi */
            "movq $0x0101010101010101, %%r11\n"
            "imul %%r11, %%rax\n" /** rax = rax * 0x0101010101010101 */
            "movq %%rax, (%%rdi)\n"
            "addq $8, %%rdi\n"
            "jmp 2b\n"
            "1:"
            : "+D"(rdi)
            : "S"(rsi), "d"(rdx), "c"(rcx)
            : "r10", "r11", "rax", "cc");
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        asm volatile(
            "movq %%rdx, %%r10\n" /** r10 = rdx */
            "2:cmp $0, %%r10\n"
            "je 1f\n"
            "subq $8, %%r10\n"
            "movq %%rdi, %%rax\n"
            "andq %%rcx, %%rax\n"
            "addq %%rsi, %%rax\n" /** rax = rsi + rdi & rcx */
            "movq $0x0101010101010101, %%r11\n"
            "imul %%r11, %%rax\n" /** rax = rax * 0x0101010101010101 */
            "movq $0x0706050403020100, %%r11\n"
            "addq %%r11, %%rax\n" /** rax = rax + 0x0706050403020100 */
            "movq %%rax, (%%rdi)\n"
            "addq $8, %%rdi\n"
            "jmp 2b\n"
            "1:"
            : "+D"(rdi)
            : "S"(rsi), "d"(rdx), "c"(rcx)
            : "r10", "r11", "rax", "cc");
        break;
    default:
        break;
    }
}

/**
 * @brief Fill the internal buffer LFB via different nt_load sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_nt_load(int filling_sequence, buffer_t *filling_buffer)
{
    int i;

    for (i = 0; i < filling_buffer->size; i += CACHELINE_SIZE)
    {
        asm volatile(
            "movntdqa (%0), %%xmm0\n"
            :
            : "r"(filling_buffer->buffer + i)
            : "xmm0");
    }
}

/**
 * @brief Fill the internal buffer LFB via different nt_store sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_nt_store(int filling_sequence, buffer_t *filling_buffer)
{
    uint64_t rdi, rsi, rdx, rcx;

    if (filling_buffer->size % 8 != 0)
    {
        // INFO("filling_buffer->size must be 8 byte aligned");
        return;
    }

    rdi = (uint64_t)filling_buffer->buffer; /** incremented during the process */
    rsi = (uint64_t)filling_buffer->value;  /** consistent during the process */
    rdx = (uint64_t)filling_buffer->size;   /** consistent during the process */
    rcx = (uint64_t)(CACHELINE_SIZE - 1);   /** consistent during the process, the cacheline mask */

    switch (filling_buffer->order)
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        asm volatile(
            "movq %%rdx, %%r10\n" /** r10 = rdx */
            "2:cmp $0, %%r10\n"
            "je 1f\n"
            "subq $8, %%r10\n"
            "movq %%rsi, %%rax\n" /** rax = rsi */
            "movq $0x0101010101010101, %%r11\n"
            "imul %%r11, %%rax\n" /** rax = rax * 0x0101010101010101 */
            "movnti %%rax, (%%rdi)\n"
            "addq $8, %%rdi\n"
            "jmp 2b\n"
            "1:"
            : "+D"(rdi)
            : "S"(rsi), "d"(rdx), "c"(rcx)
            : "r10", "r11", "rax", "cc");
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        asm volatile(
            "movq %%rdx, %%r10\n" /** r10 = rdx */
            "2:cmp $0, %%r10\n"
            "je 1f\n"
            "subq $8, %%r10\n"
            "movq %%rdi, %%rax\n"
            "andq %%rcx, %%rax\n"
            "addq %%rsi, %%rax\n" /** rax = rsi + rdi & rcx */
            "movq $0x0101010101010101, %%r11\n"
            "imul %%r11, %%rax\n" /** rax = rax * 0x0101010101010101 */
            "movq $0x0706050403020100, %%r11\n"
            "addq %%r11, %%rax\n" /** rax = rax + 0x0706050403020100 */
            "movnti %%rax, (%%rdi)\n"
            "addq $8, %%rdi\n"
            "jmp 2b\n"
            "1:"
            : "+D"(rdi)
            : "S"(rsi), "d"(rdx), "c"(rcx)
            : "r10", "r11", "rax", "cc");
        break;
    default:
        break;
    }
}

/**
 * @brief Fill the internal buffer LFB via different str_load sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_str_load(int filling_sequence, buffer_t *filling_buffer)
{
    uint64_t rsi;

    rsi = (uint64_t)filling_buffer->buffer; /** lodsq is preferred than lodsb */
    asm volatile(
        "rep lodsq\n"
        "mfence\n"
        : "+S"(rsi)
        : "c"(filling_buffer->size / 8)
        : "rax", "cc");
}

/**
 * @brief Fill the internal buffer LFB via different str_store sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_str_store(int filling_sequence, buffer_t *filling_buffer) /** TODO return int to indicate success */
{
    uint64_t rdi, rsi, rdx, rcx;

    if (filling_buffer->size % 8 != 0)
    {
        // INFO("filling_buffer->size must be 8 byte aligned");
        return;
    }

    rdi = (uint64_t)filling_buffer->buffer; /** incremented during the process */
    rsi = (uint64_t)filling_buffer->value;  /** consistent during the process */
    rdx = (uint64_t)filling_buffer->size;   /** consistent during the process */
    rcx = (uint64_t)(CACHELINE_SIZE - 1);   /** consistent during the process, the cacheline mask */

    switch (filling_buffer->order) /** stosq is preffered than stosb */
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        asm volatile(
            "movq %%rdx, %%r10\n" /** r10 = rdx */
            "2:cmp $0, %%r10\n"
            "je 1f\n"
            "subq $8, %%r10\n"
            "movq %%rsi, %%rax\n" /** rax = rsi */
            "movq $0x0101010101010101, %%r11\n"
            "imul %%r11, %%rax\n" /** rax = rax * 0x0101010101010101 */
            "stosq\n"
            "jmp 2b\n"
            "1:"
            : "+D"(rdi)
            : "S"(rsi), "d"(rdx), "c"(rcx)
            : "r10", "r11", "rax", "cc");
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        asm volatile(
            "movq %%rdx, %%r10\n" /** r10 = rdx */
            "2:cmp $0, %%r10\n"
            "je 1f\n"
            "subq $8, %%r10\n"
            "movq %%rdi, %%rax\n"
            "andq %%rcx, %%rax\n"
            "addq %%rsi, %%rax\n" /** rax = rsi + rdi & rcx */
            "movq $0x0101010101010101, %%r11\n"
            "imul %%r11, %%rax\n" /** rax = rax * 0x0101010101010101 */
            "movq $0x0706050403020100, %%r11\n"
            "addq %%r11, %%rax\n" /** rax = rax + 0x0706050403020100 */
            "stosq\n"
            "jmp 2b\n"
            "1:"
            : "+D"(rdi)
            : "S"(rsi), "d"(rdx), "c"(rcx)
            : "r10", "r11", "rax", "cc");
        break;
    default:
        break;
    }
}

void fill_lfb(int filling_sequence, buffer_t *filling_buffer)
{
    flush_buffer(filling_buffer);   // FIXME why should this line be commented out for same_thread_l1tf_sgx_is_10_percent_effective

    switch (filling_sequence)
    {
    case FILLING_SEQUENCE_NONE:
        break;
    case FILLING_SEQUENCE_GP_LOAD:
        fill_lfb_gp_load(filling_sequence, filling_buffer);
        break;
    case FILLING_SEQUENCE_GP_STORE:
        fill_lfb_gp_store(filling_sequence, filling_buffer);
        break;
    case FILLING_SEQUENCE_NT_LOAD:
        fill_lfb_nt_load(filling_sequence, filling_buffer);
        break;
    case FILLING_SEQUENCE_NT_STORE:
        fill_lfb_nt_store(filling_sequence, filling_buffer);
        break;
    case FILLING_SEQUENCE_STR_LOAD:
        fill_lfb_str_load(filling_sequence, filling_buffer);
        break;
    case FILLING_SEQUENCE_STR_STORE:
        fill_lfb_str_store(filling_sequence, filling_buffer);
    default:
        break;
    }

    asm volatile("mfence\n");
}

void clear_lfb(int clearing_sequence, buffer_t *clearing_buffer)
{
    flush_buffer(clearing_buffer);

    switch (clearing_sequence)
    {
    case CLEARING_SEQUENCE_NONE:
        break;
    case CLEARING_SEQUENCE_VERW:
        asm volatile(
            "subq $8, %rsp\n"
            "mov %ds, (%rsp)\n"
            "verw (%rsp)\n"
            "add $8, %rsp");
        break;
    case CLEARING_SEQUENCE_ORPD:
        /** TODO orpd according to avx support */
        // asm volatile(
        //     "orpd (%0), %%xmm0\n"
        //     "orpd (%0), %%xmm0\n"
        //     "mfence\n"
        //     :
        //     : "r"(clearing_buffer->buffer)
        //     : "xmm0");
        break;
    default:
        break;
    }

    asm volatile("mfence\n");
}

#endif