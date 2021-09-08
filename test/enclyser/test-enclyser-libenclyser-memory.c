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

Test(suite_memory, test_malloc_enclyser_buffer)
{
    enclyser_buffer_t enclyser_buffer = {
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
    malloc_enclyser_buffer(&enclyser_buffer);

    cr_expect(enclyser_buffer.size == DEFAULT_FILLING_BUFFER_SIZE);
    cr_expect(enclyser_buffer.value == DEFAULT_BUFFER_VALUE);
    cr_expect(enclyser_buffer.order == DEFAULT_BUFFER_ORDER);
    cr_expect(enclyser_buffer.mem_type == DEFAULT_BUFFER_MEM_TYPE);
    cr_expect(enclyser_buffer.access_ctrl == DEFAULT_BUFFER_ACCESS_CTRL);

    cr_assert(enclyser_buffer.buffer != NULL);
    cr_assert(enclyser_buffer.shadow != NULL);

    /**
     * @brief Test if \p shadow is a copy of \p buffer.
     * 
     */
    enclyser_buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 1 / 4] = 1;
    enclyser_buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 2 / 4] = 2;
    // enclyser_buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 3 / 4] = 3;    // FIXME remapping multiple pages

    cr_expect(enclyser_buffer.shadow[DEFAULT_FILLING_BUFFER_SIZE * 1 / 4] == 1);
    cr_expect(enclyser_buffer.shadow[DEFAULT_FILLING_BUFFER_SIZE * 2 / 4] == 2);
    // cr_expect(enclyser_buffer.shadow[DEFAULT_FILLING_BUFFER_SIZE * 3 / 4] == 3);    // FIXME remapping multiple pages

    /**
     * @brief Test if \p buffer and \p shadow is 4 KB aligned.
     * 
     */
    cr_expect(((uint64_t)enclyser_buffer.buffer & 0xfff) == 0);
    cr_expect(((uint64_t)enclyser_buffer.shadow & 0xfff) == 0);
}

Test(suite_memory, test_free_enclyser_buffer, .signal = SIGSEGV)
{
    enclyser_buffer_t enclyser_buffer = {
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
    malloc_enclyser_buffer(&enclyser_buffer);
    free_enclyser_buffer(&enclyser_buffer);

    cr_expect(enclyser_buffer.size == DEFAULT_FILLING_BUFFER_SIZE);
    cr_expect(enclyser_buffer.value == DEFAULT_BUFFER_VALUE);
    cr_expect(enclyser_buffer.order == DEFAULT_BUFFER_ORDER);
    cr_expect(enclyser_buffer.mem_type == DEFAULT_BUFFER_MEM_TYPE);
    cr_expect(enclyser_buffer.access_ctrl == DEFAULT_BUFFER_ACCESS_CTRL);

    /**
     * @brief 
     * 
     */
    enclyser_buffer.buffer = NULL;

    enclyser_buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 1 / 4] = 1;
    enclyser_buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 2 / 4] = 2;
    enclyser_buffer.buffer[DEFAULT_FILLING_BUFFER_SIZE * 3 / 4] = 3;
}

Test(suite_memory, test_cripple_enclyser_buffer)
{
    enclyser_buffer_t enclyser_buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    uint64_t *pte;
    int i;

    malloc_enclyser_buffer(&enclyser_buffer);

    /**
     * @brief BUFFER_ACCESS_CTRL
     * 
     */
    enclyser_buffer.mem_type = BUFFER_MEM_TYPE_WB;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(PAT(*pte) == 0);
        cr_expect(PCD(*pte) == 0);
        cr_expect(PWT(*pte) == 0);
    }

    enclyser_buffer.mem_type = BUFFER_MEM_TYPE_WC;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(PAT(*pte) == 0);
        cr_expect(PCD(*pte) == 0);
        cr_expect(PWT(*pte) == 1);
    }

    /**
     * @brief Test setting BUFFER_ACCESS_CTRL.
     * 
     */
    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_ACCESSED;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(ACCESSED(*pte) == 1);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_ACCESSED;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(ACCESSED(*pte) == 0);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_USER;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(USER(*pte) == 1);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(USER(*pte) == 0);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_PRESENT;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(PRESENT(*pte) == 1);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(PRESENT(*pte) == 0);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_RSVD;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(RSVD(*pte) == 1);
    }

    enclyser_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_RSVD;
    cripple_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i += PAGE_SIZE)
    {
        pte = (unsigned long *)remap_page_table_level(enclyser_buffer.buffer + i, PTE);
        cr_expect(RSVD(*pte) == 0);
    }

    free_enclyser_buffer(&enclyser_buffer);
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

Test(suite_memory, test_flush_enclyser_buffer) // TODO fix remapping
{
    enclyser_buffer_t enclyser_buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = 128,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    int i;

    malloc_enclyser_buffer(&enclyser_buffer);

    flush_enclyser_buffer(&enclyser_buffer);

    for (i = 0; i < enclyser_buffer.size; i += CACHELINE_SIZE)
    {
        cr_expect(access_time((unsigned long)(enclyser_buffer.buffer + i)) > 120);
    }
    asm volatile("mfence\n");
}

Test(suite_memory, test_assign_enclyser_buffer)
{
    enclyser_buffer_t enclyser_buffer = {
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    int i;

    malloc_enclyser_buffer(&enclyser_buffer);

    enclyser_buffer.value = 0x10;
    enclyser_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i++)
    {
        cr_expect(enclyser_buffer.buffer[i] == enclyser_buffer.value);
    }

    enclyser_buffer.value = 0x20;
    enclyser_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&enclyser_buffer);
    for (i = 0; i < enclyser_buffer.size; i++)
    {
        cr_expect(enclyser_buffer.buffer[i] == enclyser_buffer.value + i % 0x40);
    }

    // enclyser_buffer.value = 0x30;
    // enclyser_buffer.order = BUFFER_ORDER_LINE_NUM;
    // assign_enclyser_buffer(&enclyser_buffer);
    // cr_assert(enclyser_buffer.value = 0x30);
    // for (i = 0; i < enclyser_buffer.size; i++)
    // {
    //     cr_expect(enclyser_buffer.buffer[i] == enclyser_buffer.value + i / 0x40);
    // }

    // free_enclyser_buffer(&enclyser_buffer);
}