#include <criterion/criterion.h>
#include "enclyser/libenclyser/flush_reload.h"

#define TIME_LIMIT 120

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

/**
 * @brief test_flush_reload
 * 
 */
enclyser_buffer_t encoding_buffer;
enclyser_buffer_t printing_buffer;

void test_flush_reload_init()
{
    open_system_file();

    encoding_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_ENCODING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    printing_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_PRINTING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    malloc_enclyser_buffer(&encoding_buffer);
    malloc_enclyser_buffer(&printing_buffer);
}

void test_flush_reload_fini()
{
    free_enclyser_buffer(&encoding_buffer);
    free_enclyser_buffer(&printing_buffer);

    close_system_file();
}

TestSuite(suite_flush_reload, .init = test_flush_reload_init, .fini = test_flush_reload_fini);

Test(suite_flush_reload, test_flush, .disabled = false)
{
    int i;

    flush(&encoding_buffer, &printing_buffer);
    for (i = 0; i < encoding_buffer.size; i += CACHELINE_SIZE)
    {
        cr_expect(access_time((uint64_t)(encoding_buffer.buffer + i)) > TIME_LIMIT);
    }
}

Test(suite_flush_reload, test_reload, .disabled = false)
{
    int i, allowance;

    flush(&encoding_buffer, &printing_buffer);
    for (i = 0; i < encoding_buffer.size; i += ENCODING_BUFFER_SLOT_SIZE)
    {
        encoding_buffer.buffer[i] = 0x0;
    }
    reload(&encoding_buffer, &printing_buffer);

    flush(&encoding_buffer, &printing_buffer);
    for (i = 0; i < encoding_buffer.size; i += ENCODING_BUFFER_SLOT_SIZE)
    {
        if (i % (ENCODING_BUFFER_SLOT_SIZE * 2) == 0)
            encoding_buffer.buffer[i] = 0x0;
    }
    reload(&encoding_buffer, &printing_buffer);

    flush(&encoding_buffer, &printing_buffer);
    for (i = 0; i < encoding_buffer.size; i += ENCODING_BUFFER_SLOT_SIZE)
    {
        if (i % (ENCODING_BUFFER_SLOT_SIZE * 4) == 0)
            encoding_buffer.buffer[i] = 0x0;
    }
    reload(&encoding_buffer, &printing_buffer);

    allowance = 64;
    for (i = 0; i < encoding_buffer.size; i += ENCODING_BUFFER_SLOT_SIZE)
    {
        if (i % (ENCODING_BUFFER_SLOT_SIZE * 4) == 0)
            cr_expect(printing_buffer.buffer[i / ENCODING_BUFFER_SLOT_SIZE] == 3 || allowance--);
        else if (i % (ENCODING_BUFFER_SLOT_SIZE * 2) == 0)
            cr_expect(printing_buffer.buffer[i / ENCODING_BUFFER_SLOT_SIZE] == 2 || allowance--);
        else
            cr_expect(printing_buffer.buffer[i / ENCODING_BUFFER_SLOT_SIZE] == 1 || allowance--);
    }
}