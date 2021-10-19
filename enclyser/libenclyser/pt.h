#ifndef ENCLYSER_LIBENCLYSER_PT

#define ENCLYSER_LIBENCLYSER_PT

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"
#include "enclyser/libenclyser/system.h"

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

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>

#include "enclyser/libenclyser/system.h"
#include "kenclyser/kenclyser_ioctl.h"

/**
 * @brief the shifts, marks and sizes of PGD, PUD, PMD, PTE, and PAGE
 *
 */
#define PGD_SHIFT 39
#define PGD_MASK (0x1ffUL << PGD_SHIFT)

#define PUD_SHIFT 30
#define PUD_MASK (0x1ffUL << PUD_SHIFT)

#define PMD_SHIFT 21
#define PMD_MASK (0x1ffUL << PMD_SHIFT)

#define PTE_SHIFT 12
#define PTE_MASK (0x1ffUL << PTE_SHIFT)

#define PAGE_SHIFT 0
#define PAGE_MASK (0xfffUL << PAGE_SHIFT)

#define PFN_MASK (~PAGE_MASK)

// #define PAGE_SIZE 0x1000c

/**
 * @brief the bit shifting of a Page Upper Directory (PUD)
 */
#define PUD_PS_SHIFT 7

/**
 * @brief the bit masking of a Page Upper Directory (PUD)
 */
#define PUD_PS_MASK (0x1UL << PUD_PS_SHIFT)

/**
 * @brief the bit shifting of a Page Mid-level Directory (PMD)
 */
#define PMD_PS_SHIFT 7

/**
 * @brief the bit masking of a Page Mid-level Directory (PMD)
 */
#define PMD_PS_MASK (0x1UL << PMD_PS_SHIFT)

/**
 * @brief the bit shifting of a Page-Table Entry (PTE)
 */
#define P_SHIFT 0
#define W_SHIFT 1
#define US_SHIFT 2
#define PWT_SHIFT 3
#define PCD_SHIFT 4
#define A_SHIFT 5
#define D_SHIFT 6
#define PAT_SHIFT 7
#define RSVD_SHIFT 51

/**
 * @brief the bit masking of a Page-Table Entry (PTE)
 */
#define P_MASK (0x1UL << P_SHIFT)
#define W_MASK (0x1UL << W_SHIFT)
#define US_MASK (0x1UL << US_SHIFT)
#define PWT_MASK (0x1UL << PWT_SHIFT)
#define PCD_MASK (0x1UL << PCD_SHIFT)
#define A_MASK (0x1UL << A_SHIFT)
#define D_MASK (0x1UL << D_SHIFT)
#define PAT_MASK (0x1UL << PAT_SHIFT)
#define RSVD_MASK (0x1UL << RSVD_SHIFT)

/**
 * @brief test bits on a Page Upper Directory (PUD)
 */
#define PUD_PS(entry) (((entry)&PUD_PS_MASK) >> PUD_PS_SHIFT)

/**
 * @brief test bits on a Page Mid-level Directory (PMD)
 */
#define PMD_PS(entry) (((entry)&PMD_PS_MASK) >> PMD_PS_SHIFT)

/**
 * @brief test and modify bits on a Page-Table Entry (PTE)
 */
#define PRESENT(entry) (((entry)&P_MASK) >> P_SHIFT)
#define MARK_PRESENT(entry) ((entry) | P_MASK)
#define MARK_NOT_PRESENT(entry) ((entry) & ~P_MASK)

#define WRITABLE(entry) (((entry)&W_MASK) >> W_SHIFT)
#define MARK_WRITABLE(entry) ((entry) | W_MASK)
#define MARK_NON_WRITABLE(entry) ((entry) & ~W_MASK)

#define USER(entry) (((entry)&US_MASK) >> US_SHIFT)
#define MARK_USER(entry) ((entry) | US_MASK)
#define MARK_SUPERVISOR(entry) ((entry) & ~US_MASK)

#define PWT(entry) (((entry)&PWT_MASK) >> PWT_SHIFT)
#define MARK_PWT(entry) ((entry) | PWT_MASK)
#define MARK_NOT_PWT(entry) ((entry) & ~PWT_MASK)

#define PCD(entry) (((entry)&PCD_MASK) >> PCD_SHIFT)
#define MARK_PCD(entry) ((entry) | PCD_MASK)
#define MARK_NOT_PCD(entry) ((entry) & ~PCD_MASK)

#define ACCESSED(entry) (((entry)&A_MASK) >> A_SHIFT)
#define MARK_ACCESSED(entry) ((entry) | A_MASK)
#define MARK_NOT_ACCESSED(entry) ((entry) & ~A_MASK)

#define DIRTY(entry) (((entry)&D_MASK) >> D_SHIFT)
#define MARK_DIRTY(entry) ((entry) | D_MASK)
#define MARK_CLEAN(entry) ((entry) & ~D_MASK)

#define PAT(entry) (((entry)&PAT_MASK) >> PAT_SHIFT)
#define MARK_PAT(entry) ((entry) | PAT_MASK)
#define MARK_NOT_PAT(entry) ((entry) & ~PAT_MASK)

#define RSVD(entry) (((entry)&RSVD_MASK) >> RSVD_SHIFT)
#define MARK_RSVD(entry) ((entry) | RSVD_MASK)
#define MARK_NOT_RSVD(entry) ((entry) & ~RSVD_MASK)

/**
 * @brief modify the memory type of a page by its Page-Table Entry (PTE)
 */
#define MARK_PAT0(entry) (MARK_NOT_PAT((MARK_NOT_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT1(entry) (MARK_NOT_PAT((MARK_NOT_PCD(MARK_PWT(entry)))))
#define MARK_PAT2(entry) (MARK_NOT_PAT((MARK_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT3(entry) (MARK_NOT_PAT((MARK_PCD(MARK_PWT(entry)))))
#define MARK_PAT4(entry) (MARK_PAT((MARK_NOT_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT5(entry) (MARK_PAT((MARK_NOT_PCD(MARK_PWT(entry)))))
#define MARK_PAT6(entry) (MARK_PAT((MARK_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT7(entry) (MARK_PAT((MARK_PCD(MARK_PWT(entry)))))

/**
 * @brief returns a mask of such form
 * +----- n+1 -+- n --------- 0-+
 * | 0  0  0   |  1  1  1  1  1 |
 * +-----------+----------------+
 */
#define MASK_TO(m) ((0x1UL << ((m) + 1)) - 1)

/**
 * @brief returns a mask of such form
 * +----- m+1 -+- m ------ n -+--- 0-+
 * | 0  0  0   |  1  1  1  1  | 0  0 |
 * +-----------+--------------+------+
 * the ordered version requires n < m, the other CREATE_MASK checks this at runtime
 */
#define CREATE_MASK_ORDERED(n, m) (MASK_TO((m)) ^ (MASK_TO((n)) >> 1))
#define CREATE_MASK(n, m) (((n) < (m)) ? (CREATE_MASK_ORDERED((n), (m))) : (CREATE_MASK_ORDERED((m), (n))))

/**
 * @brief get phsical address base and page table index
 */
#define M (phys_addr_width())

#define PHYS_ADDR_BASE(phys_addr) ((phys_addr) & (CREATE_MASK(12, M - 1)))

#define PGD_INDEX(virt_addr) (virt_addr & PGD_MASK) >> PGD_SHIFT
#define PUD_INDEX(virt_addr) (virt_addr & PUD_MASK) >> PUD_SHIFT
#define PMD_INDEX(virt_addr) (virt_addr & PMD_MASK) >> PMD_SHIFT
#define PTE_INDEX(virt_addr) (virt_addr & PTE_MASK) >> PTE_SHIFT
#define PAGE_INDEX(virt_addr) (virt_addr & PAGE_MASK) >> PAGE_SHIFT

typedef enum
{
    PGD,
    PUD,
    PMD,
    PTE,
    PAGE
} pt_level_t;

uintptr_t remap_page_table(uintptr_t virt_addr, pt_level_t pt_level);
uintptr_t remap_pages(uintptr_t virt_addr, uint64_t length);
void uremap(uintptr_t virt_addr, uint64_t length);

uintptr_t map_phys_addr(uintptr_t phys_addr, uintptr_t virt_addr);
uint64_t phys_addr(address_mapping_t map, pt_level_t level);
address_mapping_t get_mapping(uintptr_t virt_addr);
uint64_t phys_addr_base(address_mapping_t map, pt_level_t level);
uint64_t page_table_index(address_mapping_t map, pt_level_t level);
uint64_t phys_addr_width(void);

#endif

#endif