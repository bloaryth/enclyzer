#include "enclyser/libenclyser/lfb.h"

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
static void fill_lfb_gp_load(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i = 0;

    for (i = 0; i < filling_buffer->size; i += CACHELINE_SIZE)
    {
        asm volatile(
            "movzbq (%0), %%rax\n"
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
static void fill_lfb_gp_store(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i;

    switch (filling_buffer->order)
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        for (i = 0; i < filling_buffer->size; i++)
        {
            asm volatile(
                "movb %%al, (%0)\n"
                :
                : "r"(filling_buffer->buffer + i), "a"(filling_buffer->value)
                :);
        }
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        for (i = 0; i < filling_buffer->size; i++)
        {
            asm volatile(
                "movb %%al, (%0)\n"
                :
                : "r"(filling_buffer->buffer + i), "a"((i + filling_buffer->value) % 0x40)
                :);
        }
        break;
    case BUFFER_ORDER_LINE_NUM:
        for (i = 0; i < filling_buffer->size; i++)
        {
            asm volatile(
                "movb %%al, (%0)\n"
                :
                : "r"(filling_buffer->buffer + i), "a"((i + filling_buffer->value) / 0x40)
                :);
        }
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
static void fill_lfb_nt_load(int filling_sequence, enclyser_buffer_t *filling_buffer)
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
static void fill_lfb_nt_store(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i, j;
    uint64_t r64;

    switch (filling_buffer->order)
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        for (i = 0; i < filling_buffer->size; i += 8)
        {
            r64 = 0;
            for (j = 0; j < 8; j++)
            {
                r64 += filling_buffer->value << (4 * j);
            }
            asm volatile(
                "movnti %%rax, (%0)\n"
                :
                : "r"(filling_buffer->buffer + i), "a"(r64)
                :);
        }
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        for (i = 0; i < filling_buffer->size; i += 8)
        {
            r64 = 0;
            for (j = 0; j < 8; j++)
            {
                r64 += ((i + j + filling_buffer->value) % 0x40) << (4 * j);
            }
            asm volatile(
                "movnti %%rax, (%0)\n"
                :
                : "r"(filling_buffer->buffer + i), "a"(r64)
                :);
        }
        break;
    case BUFFER_ORDER_LINE_NUM:
        for (i = 0; i < filling_buffer->size; i += 8)
        {
            r64 = 0;
            for (j = 0; j < 8; j++)
            {
                r64 += ((i + j + filling_buffer->value) / 0x40) << (4 * j);
            }
            asm volatile(
                "movnti %%rax, (%0)\n"
                :
                : "r"(filling_buffer->buffer + i), "a"((i + filling_buffer->value) / 0x40)
                :);
        }
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
static void fill_lfb_str_load(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    asm volatile(
        "rep lodsb\n"
        "mfence\n"
        : 
        : "S"(filling_buffer->buffer), "c"(filling_buffer->size)    /** FIXME may contain bug for not including "+" */
        : "rax", "cc");
}

/**
 * @brief Fill the internal buffer LFB via different str_store sequences.
 * 
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
static void fill_lfb_str_store(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    int i;

    switch (filling_buffer->order)
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        for (i = 0; i < filling_buffer->size; i++)
        {
            asm volatile(
                "stosb %%al, (%0)\n"
                :
                : "D"(filling_buffer->buffer + i), "a"(filling_buffer->value)   /** FIXME may contain bug for not including "+" */
                : "cc");
        }
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        for (i = 0; i < filling_buffer->size; i++)
        {
            asm volatile(
                "stosb %%al, (%0)\n"
                :
                : "D"(filling_buffer->buffer + i), "a"((i + filling_buffer->value) % 0x40)  /** FIXME may contain bug for not including "+" */
                : "cc");
        }
        break;
    case BUFFER_ORDER_LINE_NUM:
        for (i = 0; i < filling_buffer->size; i++)
        {
            asm volatile(
                "stosb %%al, (%0)\n"
                :
                : "D"(filling_buffer->buffer + i), "a"((i + filling_buffer->value) / 0x40)  /** FIXME may contain bug for not including "+" */
                : "cc");
        }
        break;
    default:
        break;
    }
}

void fill_lfb(int filling_sequence, enclyser_buffer_t *filling_buffer)
{
    flush_enclyser_buffer(filling_buffer);

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

void clear_lfb(int clearing_sequence, enclyser_buffer_t *clearing_buffer)
{
    // flush_enclyser_buffer(clearing_buffer);

    switch (clearing_sequence)
    {
    case CLEARING_SEQUENCE_NONE:
        break;
    case CLEARING_SEQUENCE_VERW:
        asm volatile(
            "sub $8, %rsp\n"
            "mov %ds, (%rsp)\n"
            "verw (%rsp)\n"
            "add $8, %rsp"
        );
        break;
    case CLEARING_SEQUENCE_ORPD:
        asm volatile(
            "orpd (%0), %%xmm0\n"
            "orpd (%0), %%xmm0\n"
            "mfence\n"
            :
            : "r"(clearing_buffer->buffer)
            : "xmm0");
        /** TODO orpd according to avx support */
        break;
    default:
        break;
    }

    asm volatile("mfence\n");
}

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

#endif