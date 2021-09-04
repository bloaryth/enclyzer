#include <criterion/criterion.h>
#include "enclyser/libenclyser/lfb.h"

#define TIME_LIMIT 140

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
 * @brief suite_lfb::test_fill_lfb
 * 
 */
enclyser_buffer_t filling_buffer;

void test_fill_lfb_init()
{
    open_system_file();

    filling_buffer = (enclyser_buffer_t) {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    malloc_enclyser_buffer(&filling_buffer);
}

void test_fill_lfb_fini()
{
    free_enclyser_buffer(&filling_buffer);

    close_system_file();
}

Test(suite_lfb, test_fill_lfb, .init=test_fill_lfb_init, .fini=test_fill_lfb_fini)
{
    int i;
    int filling_sequence;

    /**
     * @brief FILLING_SEQUENCE_GP_LOAD
     * 
     */
    flush_enclyser_buffer(&filling_buffer);
    filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i += CACHELINE_SIZE)
    {
        cr_expect(access_time((uint64_t)(filling_buffer.buffer + i)) < TIME_LIMIT);
    }

    /**
     * @brief FILLING_SEQUENCE_GP_STORE
     * 
     */
    filling_sequence = FILLING_SEQUENCE_GP_STORE;
    filling_buffer.value = 0x10;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == (filling_buffer.value + i) % 0x40);
    }
    filling_buffer.order = BUFFER_ORDER_LINE_NUM;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i / 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_NT_LOAD
     * 
     */
    flush_enclyser_buffer(&filling_buffer);
    filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i += CACHELINE_SIZE)
    {
        cr_expect(access_time((uint64_t)(filling_buffer.buffer + i)) < TIME_LIMIT);
    }

    /**
     * @brief FILLING_SEQUENCE_NT_STORE
     * 
     */
    filling_sequence = FILLING_SEQUENCE_NT_STORE;
    filling_buffer.value = 0x20;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == (filling_buffer.value + i) % 0x40);
    }
    filling_buffer.order = BUFFER_ORDER_LINE_NUM;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i / 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_STR_LOAD
     * 
     */
    flush_enclyser_buffer(&filling_buffer);
    filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i += CACHELINE_SIZE)
    {
        // cr_expect(access_time((uint64_t)(filling_buffer.buffer + i)) < TIME_LIMIT);  // FIXME
    }

    /**
     * @brief FILLING_SEQUENCE_STR_STORE
     * 
     */
    filling_sequence = FILLING_SEQUENCE_STR_STORE;
    filling_buffer.value = 0x30;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == (filling_buffer.value + i) % 0x40);
    }
    filling_buffer.order = BUFFER_ORDER_LINE_NUM;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i / 0x40);
    }
}

/**
 * @brief suite_lfb::test_clear_lfb
 * 
 */
enclyser_buffer_t clearing_buffer;

void test_clear_lfb_init()
{
    open_system_file();

    clearing_buffer = (enclyser_buffer_t) {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_CLEARING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    malloc_enclyser_buffer(&clearing_buffer);
}

void test_clear_lfb_fini()
{
    free_enclyser_buffer(&clearing_buffer);

    close_system_file();
}


Test(suite_lfb, test_clear_lfb, .init=test_fill_lfb_init, .fini=test_fill_lfb_fini)
{
    cr_expect(false && "TODO: test_clear_lfb");
}