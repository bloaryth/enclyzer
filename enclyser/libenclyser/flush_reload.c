#include "enclyser/libenclyser/flush_reload.h"

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

void flush(enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer)
{
    int i;

    for (i = 0; i < encoding_buffer->size; i += ENCODING_BUFFER_SLOT_SHIFT)
    {
        asm volatile("clflush (%0)\n" ::"r"(encoding_buffer->buffer + i));
    }

    asm volatile("mfence\n");
}

/**
 * @brief Get the time used to access the memory address, which indicates its location 
 * in the memory hierarchy.
 * 
 * @param address the memory address to be accessed.
 * @return the time used to access the memory address.
 * 
 * @see How to Benchmark Code Execution Times on Intel® IA-32 and IA-64 
 *     Instruction Set Architectures
 */
static uint32_t access_time(uint64_t address)
{
    uint32_t cycles;

    asm volatile(
        "cpuid\n"
        "rdtsc\n"
        "movl %%eax, %0\n"
        "movq (%1), %%rax\n"
        "rdtscp\n"
        "subl %0, %%eax\n"
        "movl %%eax, %0\n"
        "cpuid\n"
        : "=r"(cycles), "+r"(address)
        :
        : "rax", "rbx", "rcx", "rdx");

    return cycles;
}

void reload(enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer)
{
    int i;
    uint64_t dt;

    asm volatile("mfence\n");

    for (i = 0; i < encoding_buffer->size; i += ENCODING_BUFFER_SLOT_SIZE)
    {
        dt = access_time((uint64_t)(encoding_buffer->buffer + i));
        if (dt < TIME_LIMIT)
        {
            printing_buffer->buffer[i / ENCODING_BUFFER_SLOT_SIZE]++;
        }
        // INFO("i: %x, dt: %lu, %d", i, dt, i / ENCODING_BUFFER_SLOT_SIZE);
    }
}

/**
 * @brief Reset all of the accumulated data to zero.
 * 
 * @param printing_buffer the buffer that accumulates persistent data
 */
static void reset_printing_buffer(enclyser_buffer_t *printing_buffer)
{
    int i;

    for (i = 0; i < printing_buffer->size; i++)
    {
        printing_buffer->buffer[i] = 0;
    }
}

void print(enclyser_buffer_t *printing_buffer)
{
    int i;

    printf("{--------------------\n");
    for (i = 0; i < printing_buffer->size; i++)
    {
        if (printing_buffer->buffer[i] > 0)
        // if (printing_buffer->buffer[i] * RECOVERY_DINOMINATOR >  RECOVERY_NUMERATOR * REPETITION_TIME)
        {
            printf("%08u: %02x (%c)\n", printing_buffer->buffer[i], (uint32_t)i,
                   isprint(i) ? (uint32_t)i : '?');
        }
    }
    printf("--------------------}\n\n");

    reset_printing_buffer(printing_buffer);
}

#endif