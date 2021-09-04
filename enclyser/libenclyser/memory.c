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
        asm volatile("clflush (%0)\n" ::"r"(enclyser_buffer->buffer + i));  // FIXME shadow -> buffer, incompatible with ACCESS_CTRL
    }
    asm volatile("mfence\n");
}

void assign_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    int i;

    for (i = 0; i < enclyser_buffer->size; i++)
    {
        switch (enclyser_buffer->order)
        {
        case BUFFER_ORDER_NONE:
            break;
        case BUFFER_ORDER_CONSTANT:
            enclyser_buffer->buffer[i] = enclyser_buffer->value;
            break;
        case BUFFER_ORDER_OFFSET_INLINE:
            enclyser_buffer->buffer[i] = (enclyser_buffer->value + i) % 0x40;
            break;
        case BUFFER_ORDER_LINE_NUM:
            enclyser_buffer->buffer[i] = enclyser_buffer->value + i / 0x40;
            break;
        default:
            break;
        }
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
    enclyser_buffer->buffer = (uint8_t *)mmap(NULL, enclyser_buffer->size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    enclyser_buffer->shadow = (uint8_t *)remap_page_table_level(enclyser_buffer->buffer, PAGE);
    ASSERT(enclyser_buffer->buffer != MAP_FAILED);
}

void free_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    ASSERT(!munmap(enclyser_buffer->buffer, enclyser_buffer->size));
}

void cripple_enclyser_buffer(enclyser_buffer_t *enclyser_buffer)
{
    uint64_t *tmp_pte;
    int i;

    for (i = 0; i < enclyser_buffer->size; i += PAGE_SIZE)
    {
        switch (enclyser_buffer->mem_type)
        {
        case BUFFER_MEM_TYPE_NONE:
            break;
        case BUFFER_MEM_TYPE_WB:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_PAT0(*tmp_pte);
            break;
        case BUFFER_MEM_TYPE_WC:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_PAT1(*tmp_pte);
            break;
        default:
            break;
        }

        switch (enclyser_buffer->access_ctrl)   // FIXME bit seperation
        {
        case BUFFER_ACCESS_CTRL_NONE:
            break;
        case BUFFER_ACCESS_CTRL_ACCESSED:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_ACCESSED(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_ACCESSED:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_NOT_ACCESSED(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_USER:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_USER(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_SUPERVISOR:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_SUPERVISOR(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_PRESENT:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_PRESENT(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_PRESENT:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_NOT_PRESENT(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_RSVD:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_RSVD(*tmp_pte);
            break;
        case BUFFER_ACCESS_CTRL_NOT_RSVD:
            tmp_pte = (unsigned long *)remap_page_table_level(enclyser_buffer->buffer + i, PTE);
            *tmp_pte = MARK_NOT_RSVD(*tmp_pte);
            break;
        default:
            break;
        }
    }
}

#endif