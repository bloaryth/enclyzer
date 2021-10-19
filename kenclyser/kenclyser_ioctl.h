#ifndef KENCLYSER_KENCLYSER_IOCTL

#define KENCLYSER_KENCLYSER_IOCTL

#include <linux/ioctl.h>

#define KENCLYSER_IOCTL_MAGIC 'L'
#define KENCLYSER_IOCTL_VICTIM_INFO _IOWR(KENCLYSER_IOCTL_MAGIC, 0, struct enclave_info)
#define KENCLYSER_IOCTL_GET_PT_MAPPING _IOWR(KENCLYSER_IOCTL_MAGIC, 1, address_mapping_t)
#define KENCLYSER_IOCTL_EDBGRD _IOWR(KENCLYSER_IOCTL_MAGIC, 2, edbgrd_t)
#define KENCLYSER_IOCTL_INVPG _IOWR(KENCLYSER_IOCTL_MAGIC, 3, invpg_t)
#define KENCLYSER_IOCTL_RDMSR _IOWR(KENCLYSER_IOCTL_MAGIC, 4, msr_t)
#define KENCLYSER_IOCTL_WRMSR _IOWR(KENCLYSER_IOCTL_MAGIC, 5, msr_t)

struct enclave_info
{
    uint64_t base;
    uint64_t size;
    uint64_t aep;
    uint64_t tcs;
};

typedef struct
{
    uintptr_t virt_addr; /** the virtual address */
    uintptr_t phys_addr; /** the physical address */
    uintptr_t pt_addr;   /** the physical address of the page table */
    uintptr_t pgd_addr;  /** the physical address of the Page Global Directory (PGD) */
    uintptr_t pud_addr;  /** the physical address of the Page Upper Directory (PUD) */
    uintptr_t pmd_addr;  /** the physical address of the Page Mid-level Directory (PMD) */
    uintptr_t pte_addr;  /** the physical address of the Page-Table Entry (PTE) */
    uint64_t pgd_cont;   /** the content of the Page Global Directory (PGD) */
    uint64_t pud_cont;   /** the content of the Page Upper Directory (PUD) */
    uint64_t pmd_cont;   /** the content of the Page Mid-level Directory (PMD) */
    uint64_t pte_cont;   /** the content of the Page-Table Entry (PTE) */
} address_mapping_t;

typedef struct {
    uint64_t adrs;
    uint64_t val;
    int64_t  len;
    int      write;
} edbgrd_t;

typedef struct
{
    uint64_t adrs;
} invpg_t;

typedef struct
{
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
} msr_t;

#endif