#include <criterion/criterion.h>
#include <signal.h>
#include "enclyser/libenclyser/memory.h"

void init(void)
{
    open_system_file();
}

void fini(void)
{
    close_system_file();
}

TestSuite(suite_memory, .init = init, .fini = fini);

Test(suite_memory, test_malloc_buffer, .disabled = false)
{
    buffer_t buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    /**
     * @brief Test if \p buffer is malloced, and other variables are not changed.
     *
     */
    malloc_buffer(&buffer);

    cr_expect(buffer.size == DEFAULT_FILLING_BUFFER_SIZE);
    cr_expect(buffer.value == DEFAULT_BUFFER_VALUE);
    cr_expect(buffer.order == DEFAULT_BUFFER_ORDER);
    cr_expect(buffer.mem_type == DEFAULT_BUFFER_MEM_TYPE);
    cr_expect(buffer.access_ctrl == DEFAULT_BUFFER_ACCESS_CTRL);

    cr_assert(buffer.buffer != NULL);
    cr_assert(buffer.shadow != NULL);

    /**
     * @brief Test if \p shadow is a copy of \p buffer.
     *
     */
    buffer.buffer[buffer.size * 1 / 4] = 1;
    buffer.buffer[buffer.size * 2 / 4] = 2;
    buffer.buffer[buffer.size * 3 / 4] = 3;

    cr_expect(buffer.shadow[buffer.size * 1 / 4] == 1);
    cr_expect(buffer.shadow[buffer.size * 2 / 4] == 2);
    cr_expect(buffer.shadow[buffer.size * 3 / 4] == 3);

    buffer.shadow[buffer.size * 1 / 4] = 4;
    buffer.shadow[buffer.size * 2 / 4] = 5;
    buffer.shadow[buffer.size * 3 / 4] = 6;

    cr_expect(buffer.buffer[buffer.size * 1 / 4] == 4);
    cr_expect(buffer.buffer[buffer.size * 2 / 4] == 5);
    cr_expect(buffer.buffer[buffer.size * 3 / 4] == 6);

    /**
     * @brief Test if \p buffer and \p shadow is 4 KB aligned.
     *
     */
    cr_expect(((uint64_t)buffer.buffer & 0xfff) == 0);
    cr_expect(((uint64_t)buffer.shadow & 0xfff) == 0);

    free_buffer(&buffer);
}

Test(suite_memory, test_free_buffer, .signal = SIGSEGV, .disabled = false)
{
    buffer_t buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    /**
     * @brief Test if \p buffer is malloced and then freed, and other variables are not changed.
     *
     */
    malloc_buffer(&buffer);
    free_buffer(&buffer);

    cr_expect(buffer.size == DEFAULT_FILLING_BUFFER_SIZE);
    cr_expect(buffer.value == DEFAULT_BUFFER_VALUE);
    cr_expect(buffer.order == DEFAULT_BUFFER_ORDER);
    cr_expect(buffer.mem_type == DEFAULT_BUFFER_MEM_TYPE);
    cr_expect(buffer.access_ctrl == DEFAULT_BUFFER_ACCESS_CTRL);

    /**
     * @brief Test if the freed \p buffer could be accessed.
     *
     */
    buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 1 / 4] = 1;
    buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 2 / 4] = 2;
    buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 3 / 4] = 3;
}

Test(suite_memory, test_cripple_buffer, .disabled = false)
{
    buffer_t buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    uint64_t *pte;
    int i;

    malloc_buffer(&buffer);

    /**
     * @brief BUFFER_ACCESS_CTRL
     *
     */
    buffer.mem_type = BUFFER_MEM_TYPE_WB;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(PAT(*pte) == 0);
        cr_expect(PCD(*pte) == 0);
        cr_expect(PWT(*pte) == 0);
    }

    buffer.mem_type = BUFFER_MEM_TYPE_WC;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(PAT(*pte) == 0);
        cr_expect(PCD(*pte) == 0);
        cr_expect(PWT(*pte) == 1);
    }

    /**
     * @brief Test setting BUFFER_ACCESS_CTRL.
     *
     */
    buffer.access_ctrl = BUFFER_ACCESS_CTRL_ACCESSED;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(ACCESSED(*pte) == 1);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_ACCESSED;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(ACCESSED(*pte) == 0);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_USER;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(USER(*pte) == 1);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(USER(*pte) == 0);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_PRESENT;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(PRESENT(*pte) == 1);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(PRESENT(*pte) == 0);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_RSVD;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(RSVD(*pte) == 1);
    }

    buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_RSVD;
    cripple_buffer(&buffer);
    for (i = 0; i < buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table((uintptr_t)(buffer.shadow + i), PTE);
        cr_expect(RSVD(*pte) == 0);
    }

    free_buffer(&buffer);
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

Test(suite_memory, test_flush_buffer, .disabled = false) // TODO fix remapping
{
    buffer_t buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    int i;

    malloc_buffer(&buffer);

    flush_buffer(&buffer);

    for (i = 0; i < buffer.size; i += CACHELINE_SIZE)
    {
        cr_expect(access_time((unsigned long)((uintptr_t)(buffer.buffer + i))) > 120);
    }
    asm volatile("mfence\n");

    free_buffer(&buffer);
}

Test(suite_memory, test_assign_buffer, .disabled = false)
{
    buffer_t buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    int i;

    malloc_buffer(&buffer);

    buffer.value = 0x10;
    buffer.order = BUFFER_ORDER_CONSTANT;
    assign_buffer(&buffer);
    for (i = 0; i < buffer.size; i++)
    {
        cr_expect(buffer.buffer[i] == buffer.value);
    }

    buffer.value = 0x20;
    buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_buffer(&buffer);
    for (i = 0; i < buffer.size; i++)
    {
        cr_expect(buffer.buffer[i] == buffer.value + i % 0x40);
    }

    // buffer.value = 0x30;
    // buffer.order = BUFFER_ORDER_LINE_NUM;
    // assign_buffer(&buffer);
    // cr_assert(buffer.value = 0x30);
    // for (i = 0; i < buffer.size; i++)
    // {
    //     cr_expect(buffer.buffer[i] == buffer.value + i / 0x40);
    // }

    free_buffer(&buffer);
}