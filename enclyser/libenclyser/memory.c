#include "enclyser/libenclyser/memory.h"

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

void flush_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    int i;

    for (i = 0; i < enclyser_buffer->size; i += CACHELINE_SIZE)
    {
        asm volatile("clflush (%0)\n" ::"r"(enclyser_buffer->buffer + i));
    }
    asm volatile("mfence\n");
}

void assign_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    int i;

    switch (enclyser_buffer->order)
    {
    case BUFFER_ORDER_NONE:
        break;
    case BUFFER_ORDER_CONSTANT:
        for (i = 0; i < enclyser_buffer->size; i++)
        {
            enclyser_buffer->buffer[i] = enclyser_buffer->value;
        }
        break;
    case BUFFER_ORDER_OFFSET_INLINE:
        for (i = 0; i < enclyser_buffer->size; i++)
        {
            enclyser_buffer->buffer[i] = enclyser_buffer->value + i % 0x40;
        }
        break;
    // case BUFFER_ORDER_LINE_NUM:
    //     for (i = 0; i < enclyser_buffer->size; i++)
    //     {
    //         enclyser_buffer->buffer[i] = enclyser_buffer->value + i / 0x40;
    //     }
    //     break;
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

void malloc_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    enclyser_buffer->buffer = (uint8_t *)mmap(NULL, enclyser_buffer->size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, -1, 0);
    ASSERT(enclyser_buffer->buffer != MAP_FAILED);
    enclyser_buffer->shadow = (uint8_t *)remap_pages((uintptr_t)enclyser_buffer->buffer, enclyser_buffer->size);
}

void free_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    ASSERT(!munmap(enclyser_buffer->buffer, enclyser_buffer->size));
    ASSERT(!munmap(enclyser_buffer->shadow, enclyser_buffer->size));
}

void cripple_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    uint64_t *remapped_pte;
    int i;

    for (i = 0; i < enclyser_buffer->size; i += PAGE_SIZE)
    {
        switch (enclyser_buffer->mem_type)
        {
        case BUFFER_MEM_TYPE_NONE:
            break;
        case BUFFER_MEM_TYPE_WB:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_PAT0(*remapped_pte);
            break;
        case BUFFER_MEM_TYPE_WC:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_PAT1(*remapped_pte);
            break;
        default:
            break;
        }

        switch (enclyser_buffer->access_ctrl) // FIXME support concurrent bits set
        {
        case BUFFER_ACCESS_CTRL_NONE:
            break;
        case BUFFER_ACCESS_CTRL_ACCESSED:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_ACCESSED(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_ACCESSED:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_NOT_ACCESSED(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_USER:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_USER(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_SUPERVISOR:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_SUPERVISOR(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_PRESENT:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_PRESENT(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_PRESENT:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_NOT_PRESENT(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_RSVD:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_RSVD(*remapped_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_RSVD:
            remapped_pte = (unsigned long *)remap_page_table((uintptr_t)(enclyser_buffer->shadow + i), PTE);
            *remapped_pte = MARK_NOT_RSVD(*remapped_pte);
            break;
        default:
            break;
        }
    }
}

#endif