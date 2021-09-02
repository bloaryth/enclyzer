#ifndef ENCLYSER_LIBENCLYSER_PT

#define ENCLYSER_LIBENCLYSER_PT

#ifdef __cplusplus
extern "C" {
#endif

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

#include "kenclyser/kenclyser_ioctl.h"

/**
 * @brief the base functions of generating masks
 * 
 */

// Returns a mask of the form:
// +----- n+1 -+- n --------- 0-+
// | 0  0  0   |  1  1  1  1  1 |
// +-----------+----------------+
#define MASK_TO(m)		((UINT64_C(0x1) << ((m) + 1)) - 1 )

// Returns a mask of the form:
// +----- m+1 -+- m ------ n -+--- 0-+
// | 0  0  0   |  1  1  1  1  | 0  0 |
// +-----------+--------------+------+
// The ordered version requires n < m, the other CREATE_MASK checks this at runtime
#define CREATE_MASK_ORDERED(n,m)	(MASK_TO((m)) ^ (MASK_TO((n)) >> 1))
#define CREATE_MASK(n,m)	( ((n) < (m)) ? (CREATE_MASK_ORDERED((n), (m))) : (CREATE_MASK_ORDERED((m), (n))) )

#ifdef REDEFINE_M
#define M			REDEFINE_M
#else
#define M			(physical_address_width())
#endif

#define MASK_M			((uint64_t) ((INT64_C(0x1) << physical_address_width()) - 1))

/**
 * @brief the shifts and marks of the bits of PTE
 * 
 */
#define P_SHIFT			0
#define P_MASK			UINT64_C(0x1)

#define W_SHIFT			1
#define W_MASK			(UINT64_C(0x1) << W_SHIFT)

#define US_SHIFT		2
#define US_MASK			(UINT64_C(0x1) << US_SHIFT)

#define PWT_SHIFT       3
#define PWT_MASK        (UINT64_C(0x1) << PWT_SHIFT)

#define PCD_SHIFT       4
#define PCD_MASK        (UINT64_C(0x1) << PCD_SHIFT)

#define A_SHIFT			5
#define A_MASK			(UINT64_C(0x1) << A_SHIFT)

#define D_SHIFT			6
#define D_MASK			(UINT64_C(0x1) << D_SHIFT)

#define PAT_SHIFT       7
#define PAT_MASK        (UINT64_C(0x1) << PAT_SHIFT)

#define RSVD_SHIFT      51
#define RSVD_MASK       (UINT64_C(0x1) << RSVD_SHIFT)

#define XD_SHIFT		63
#define XD_MASK			(UINT64_C(0x1) << XD_SHIFT)

#define PUD_PS_SHIFT	7
#define PUD_PS_MASK		(UINT64_C(0x1) << PUD_PS_SHIFT)

#define PMD_PS_SHIFT	7
#define PMD_PS_MASK		(UINT64_C(0x1) << PMD_PS_SHIFT)

/**
 * @brief the shifts and marks of PGD, PUD, PMD, PTE, and PAGE
 * 
 */
#define PGD_SHIFT		39
#define PGD_MASK		(INT64_C(0x1ff) << PGD_SHIFT)

#define PUD_SHIFT		30
#define PUD_MASK		(INT64_C(0x1ff) << PUD_SHIFT)

#define PMD_SHIFT		21
#define PMD_MASK		(INT64_C(0x1ff) << PMD_SHIFT)

#define PTE_SHIFT		12
#define PTE_MASK		(INT64_C(0x1ff) << PTE_SHIFT)

#define PAGE_SHIFT		0
#define PAGE_MASK		(INT64_C(0xfff) << PAGE_SHIFT)

#define PFN_MASK        0xfffULL

/**
 * @brief the shifts and marks of HUGE_PAGE
 * 
 */
#define PAGE2MiB_SHIFT		0
#define PAGE2MiB_MASK		(INT64_C(0x1FFFFF) << PAGE2MiB_SHIFT)

#define PAGE1GiB_SHIFT		0
#define PAGE1GiB_MASK		(INT64_C(0x3FFFFFFF) << PAGE1GiB_SHIFT)

/**
 * @brief the page size of PAGE, and HUGE_PAGE
 * 
 */
#define PAGE_SIZE_4KiB		0x1000
#define PAGE_SIZE_2MiB		0x200000
#define PAGE_SIZE_1GiB		0x40000000

/**
 * @brief Modify the memory type of a PAGE.
 * 
 */
#define PWT(entry)              (((entry) & PWT_MASK) >> PWT_SHIFT)
#define MARK_PWT(entry)         ((entry) | PWT_MASK)
#define MARK_NOT_PWT(entry)     ((entry) & ~PWT_MASK)

#define PCD(entry)              (((entry) & PCD_MASK) >> PCD_SHIFT)
#define MARK_PCD(entry)         ((entry) | PCD_MASK)
#define MARK_NOT_PCD(entry)     ((entry) & ~PCD_MASK)

#define PAT(entry)              (((entry) & PAT_MASK) >> PAT_SHIFT)
#define MARK_PAT(entry)         ((entry) | PAT_MASK)
#define MARK_NOT_PAT(entry)     ((entry) & ~PAT_MASK)

#define MARK_PAT0(entry)        (MARK_NOT_PAT((MARK_NOT_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT1(entry)        (MARK_NOT_PAT((MARK_NOT_PCD(MARK_PWT(entry)))))
#define MARK_PAT2(entry)        (MARK_NOT_PAT((MARK_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT3(entry)        (MARK_NOT_PAT((MARK_PCD(MARK_PWT(entry)))))
#define MARK_PAT4(entry)        (MARK_PAT((MARK_NOT_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT5(entry)        (MARK_PAT((MARK_NOT_PCD(MARK_PWT(entry)))))
#define MARK_PAT6(entry)        (MARK_PAT((MARK_PCD(MARK_NOT_PWT(entry)))))
#define MARK_PAT7(entry)        (MARK_PAT((MARK_PCD(MARK_PWT(entry)))))

/**
 * @brief Modify the access policy of a PAGE.
 * 
 */
#define ACCESSED(entry) 		(((entry) & A_MASK) >> A_SHIFT)
#define MARK_ACCESSED(entry) 		((entry) | A_MASK)
#define MARK_NOT_ACCESSED(entry) 	((entry) & ~A_MASK)

#define DIRTY(entry) 			(((entry) & D_MASK) >> D_SHIFT)
#define MARK_DIRTY(entry) 		((entry) | D_MASK)
#define MARK_CLEAN(entry) 		((entry) & ~D_MASK)

#define WRITABLE(entry) 		(((entry) & W_MASK) >> W_SHIFT)
#define MARK_WRITABLE(entry) 		((entry) | W_MASK)
#define MARK_NON_WRITABLE(entry)	((entry) & ~W_MASK)

#define USER(entry) 		    (((entry) & US_MASK) >> US_SHIFT)
#define MARK_USER(entry) 		((entry) | US_MASK)
#define MARK_SUPERVISOR(entry)	((entry) & ~US_MASK)

#define EXECUTE_DISABLE(entry)		((((entry) & XD_MASK) >> XD_SHIFT))
#define MARK_EXECUTE_DISABLE(entry)	((entry) | XD_MASK)
#define MARK_NOT_EXECUTE_DISABLE(entry)	((entry) & ~XD_MASK)

#define EXECUTABLE(entry) 		((EXECUTE_DISABLE(entry)) ? UINT64_C( 0 ) : UINT64_C( 1 ) )
#define MARK_EXECUTABLE(entry) 		MARK_NOT_EXECUTE_DISABLE(entry)
#define MARK_NON_EXECUTABLE(entry)	MARK_EXECUTE_DISABLE(entry)

#define PRESENT(entry)			(((entry) & P_MASK) >> P_SHIFT)
#define MARK_PRESENT(entry) 		((entry) | P_MASK)
#define MARK_NOT_PRESENT(entry) 	((entry) & ~P_MASK)

#define RSVD(entry)			    (((entry) & RSVD_MASK) >> RSVD_SHIFT)
#define MARK_RSVD(entry)        ((entry) | RSVD_MASK)
#define CLEAR_RSVD(entry)       ((entry) & ~RSVD_MASK)

/**
 * @brief some converting utilities
 * 
 */
#define PUD_PS(entry)			(((entry) & PUD_PS_MASK) >> PUD_PS_SHIFT)
#define PMD_PS(entry)			(((entry) & PMD_PS_MASK) >> PMD_PS_SHIFT)

#define PGD_PHYS(entry)			((entry) & (CREATE_MASK(12, M-1)))
#define PUD_PS_0_PHYS(entry)    ((entry) & (CREATE_MASK(12, M-1)))
#define PUD_PS_1_PHYS(entry)	((entry) & (CREATE_MASK(30, M-1)))
#define PMD_PS_0_PHYS(entry)	((entry) & (CREATE_MASK(12, M-1)))
#define PMD_PS_1_PHYS(entry)	((entry) & (CREATE_MASK(21, M-1)))
#define PT_PHYS(entry)			((entry) & (CREATE_MASK(12, M-1)))

#define PGD_INDEX(virt)			(virt & PGD_MASK) >> PGD_SHIFT
#define PUD_INDEX(virt)			(virt & PUD_MASK) >> PUD_SHIFT
#define PMD_INDEX(virt)			(virt & PMD_MASK) >> PMD_SHIFT
#define PTE_INDEX(virt)			(virt & PTE_MASK) >> PTE_SHIFT
#define PAGE_INDEX(virt)		(virt & PAGE_MASK) >> PAGE_SHIFT
#define PAGE1GiB_INDEX(virt)	(virt & PAGE1GiB_MASK) >> PAGE1GiB_SHIFT
#define PAGE2MiB_INDEX(virt)	(virt & PAGE2MiB_MASK) >> PAGE2MiB_SHIFT

typedef enum {PGD, PUD, PMD, PTE, PAGE} pt_level_t;

void *remap(uint64_t phys);
void free_map(void *p);
void *remap_page_table_level( void *address, pt_level_t level );
void flush_tlb(void *adrs);

address_mapping_t *get_mappings( void *address );
uint64_t phys_address( address_mapping_t *map, pt_level_t level );
uint64_t phys_base_address( address_mapping_t *map, pt_level_t level );
uint64_t virt_index( address_mapping_t *map, pt_level_t level );
uint64_t physical_address_width( void );

#endif

#ifdef __cplusplus
}
#endif

#endif