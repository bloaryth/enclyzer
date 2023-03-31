#include "enclyzer/libenclyzer/memory.h"

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_YES

#include "enclyzer/libenclyzer/memory_t.h"

/**
 * @brief [ECALL] Flush the enclyzer buffer to ensure a later enclyzer.
 *
 * @param buffer the buffer which the function operates on
 */
void ecall_flush_buffer(buffer_t *buffer)
{
    flush_buffer(buffer);
}

/**
 * @brief [ECALL] Assign values to a enclyzer buffer according to a policy.
 *
 * @param buffer the buffer which the function operates on
 */
void ecall_assign_buffer(buffer_t *buffer)
{
    assign_buffer(buffer);
}

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_NO

#include "enclyzer/libenclyzer/memory_u.h"

#include <sys/mman.h>

void malloc_buffer(buffer_t *buffer)
{
    if (buffer->buffer == NULL)
    {
        buffer->buffer = (uint8_t *)mmap(NULL, buffer->size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, -1, 0);
        ASSERT(buffer->buffer != MAP_FAILED);
    }
    if (buffer->shadow == NULL)
    {
        buffer->shadow = (uint8_t *)remap_pages((uintptr_t)buffer->buffer, buffer->size);
    }
}

void free_buffer(buffer_t *buffer)
{
    ASSERT(!munmap(buffer->buffer, buffer->size));
    ASSERT(!munmap(buffer->shadow, buffer->size));
}

void cripple_buffer(buffer_t *buffer)
{
    uint64_t *remapped_pte;
    int i;

    for (i = 0; i < buffer->size; i += PAGE_SIZE)
    {
        switch (buffer->mem_type)
        {
        case BUFFER_MEM_TYPE_NONE:
            break;
        case BUFFER_MEM_TYPE_WB:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_PAT0(*remapped_pte);
            break;
        case BUFFER_MEM_TYPE_WC:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_PAT1(*remapped_pte);
            break;
        default:
            break;
        }

        switch (buffer->access_ctrl) // FIXME support concurrent bits set
        {
        case BUFFER_ACCESS_CTRL_NONE:
            break;
        case BUFFER_ACCESS_CTRL_ACCESSED:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_ACCESSED(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_ACCESSED:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_NOT_ACCESSED(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_USER:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_USER(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_SUPERVISOR:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_SUPERVISOR(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_PRESENT:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_PRESENT(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_PRESENT:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_NOT_PRESENT(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_RSVD:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_RSVD(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_RSVD:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(buffer->shadow + i), PTE);
            *remapped_pte = MARK_NOT_RSVD(*remapped_pte);
            break;
        default:
            break;
        }
    }
}

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

void flush_buffer(buffer_t *buffer)
{
    int i;

    for (i = 0; i < buffer->size; i += CACHELINE_SIZE)
    {
        asm volatile("clflush (%0)\n" ::"r"(buffer->buffer + i));
    }
    asm volatile("mfence\n");
}

void assign_buffer(buffer_t *buffer)
{
    int i;

    switch (buffer->order)
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        for (i = 0; i < buffer->size; i++)
        {
            buffer->buffer[i] = buffer->value;
        }
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        for (i = 0; i < buffer->size; i++)
        {
            buffer->buffer[i] = buffer->value + i % 0x40;
        }
        break;
    // case BUFFER_ORDER_LINE_NUM:
    //     for (i = 0; i < buffer->size; i++)
    //     {
    //         buffer->buffer[i] = buffer->value + i / 0x40;
    //     }
    //     break;
    default:
        break;
    }

    asm volatile("mfence\n");
}

#endif