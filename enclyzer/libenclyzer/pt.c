#include "enclyzer/libenclyzer/pt.h"

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 *
 */
#ifdef NAMESPACE_SGX_YES

#include "enclyzer/libenclyzer/pt_t.h"

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_NO

#include "enclyzer/libenclyzer/pt_u.h"

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>

// void flush_tlb(void *adrs)
// {
// 	invpg_t param = {.adrs = (uint64_t)adrs};

// 	ASSERT(fd_enclyzer >= 0);										/** /dev/enclyzer is opened. */
// 	ASSERT(ioctl(fd_enclyzer, KENCLYZER_IOCTL_INVPG, &param) >= 0); /** ioctl returns successfully. */
// }

/**
 * @brief remap a page table level in the page table mapping of a virtual address
 *
 * @param virt_addr the virtual address
 * @param pt_level the pagetable level
 * @return uintptr_t the remapped virtual address
 */
uintptr_t remap_page_table(uintptr_t virt_addr, pt_level_t pt_level)
{
	return map_phys_addr(phys_addr(get_mapping(virt_addr), pt_level), 0);
}

/**
 * @brief Remap pages starting from a virtual address with a specified length
 *
 * @param virt_addr the virtual address of the first page (must be page aligned)
 * @param length the length of pages in bytes
 * @return uintptr_t the remapped virtual address
 */
uintptr_t remap_pages(uintptr_t virt_addr, uint64_t length)
{
	uintptr_t remapped_page;
	uint64_t offset;

	ASSERT(virt_addr % PAGE_SIZE == 0); /** check if virt_addr is page aligned */
	remapped_page = (uintptr_t)mmap(0, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, -1, 0);
	for (offset = 0; offset < (virt_addr & PAGE_MASK) + length; offset += PAGE_SIZE)
	{
		map_phys_addr(phys_addr(get_mapping(virt_addr + offset), PAGE), remapped_page + offset);
	}

	return remapped_page;
}

/**
 * @brief
 *
 * @param virt_addr
 * @param length
 */
void uremap(uintptr_t virt_addr, uint64_t length)
{
	ASSERT(!munmap((void *)(virt_addr & PFN_MASK), length));
}

/**
 * @brief map a physical address to a fixed or auto-decided virtual address
 *
 * @param phys_addr the phsical address to be mapped
 * @param virt_addr the fixed virtual address
 * @return uintptr_t the fixed virtual address
 */
uintptr_t map_phys_addr(uintptr_t phys_addr, uintptr_t virt_addr)
{
	uintptr_t mapped_page;

	ASSERT(fd_enclyzer >= 0); /** check if /dev/enclyzer is opened. */
	if (virt_addr == 0)
	{
		mapped_page = (uintptr_t)mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd_mem, phys_addr & PFN_MASK);
		ASSERT(mapped_page != (uintptr_t)MAP_FAILED);
	}
	else
	{
		ASSERT((phys_addr & PAGE_MASK) == (virt_addr & PAGE_MASK)); /** phys_addr has the same offset as virt_addr. */
		mapped_page = (uintptr_t)mmap((void *)(virt_addr & PFN_MASK), 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd_mem, phys_addr & PFN_MASK);
		ASSERT(mapped_page != (uintptr_t)MAP_FAILED);
	}

	return mapped_page | (phys_addr & PAGE_MASK);
}

/**
 * @brief Get the physical address of a page table level in the mapping
 *
 * @param map the page table mapping
 * @param level the page table level selector
 * @return uint64_t the physical address
 */
uint64_t phys_addr(address_mapping_t map, pt_level_t level)
{
	uint64_t base = phys_addr_base(map, level);
	uint64_t index = page_table_index(map, level);

	if (level == PAGE)
		return base + index;
	else
		return base + index * 64 / 8;
}

/**
 * @brief Get the page table mapping from a virtual address
 *
 * @param virt_addr the virtual address
 * @return address_mapping_t the page table mapping
 */
address_mapping_t get_mapping(uintptr_t virt_addr)
{
	address_mapping_t mapping;

	mapping.virt_addr = virt_addr;
	ASSERT(fd_enclyzer >= 0);												   /** /dev/enclyzer is opened. */
	ASSERT(ioctl(fd_enclyzer, KENCLYZER_IOCTL_GET_PT_MAPPING, &mapping) >= 0); /** ioctl returns successfully. */

	return mapping;
}

/**
 * @brief Get the physical base address of a page level in the page table
 *
 * @param map the page table mapping
 * @param level the page table level selector
 * @return uint64_t the phsical base address
 */
uint64_t phys_addr_base(address_mapping_t map, pt_level_t level)
{
	ASSERT(!PUD_PS(map.pud_cont) && !PMD_PS(map.pmd_cont)); /** huge_page is not supported */

	switch (level)
	{
	case PGD:
		return PHYS_ADDR_BASE(map.pgd_addr);
	case PUD:
		return PHYS_ADDR_BASE(map.pud_addr);
	case PMD:
		return PHYS_ADDR_BASE(map.pmd_addr);
	case PTE:
		return PHYS_ADDR_BASE(map.pte_addr);
	case PAGE:
	default:
		return PHYS_ADDR_BASE(map.phys_addr);
	}
}

/**
 * @brief Get the index of a page table level in the page table.
 *
 * 9 bits for PGD, PUD, PMD and PTE. 12 bits for PAGE.
 *
 * @param map the address mapping in the page table
 * @param level the page table level selector
 * @return uint64_t the index in the page table
 */
uint64_t page_table_index(address_mapping_t map, pt_level_t level)
{
	ASSERT(!PUD_PS(map.pud_cont) && !PMD_PS(map.pmd_cont)); /** huge_page is not supported */

	switch (level)
	{
	case PGD:
		return PGD_INDEX(map.virt_addr);
	case PUD:
		return PUD_INDEX(map.virt_addr);
	case PMD:
		return PMD_INDEX(map.virt_addr);
	case PTE:
		return PTE_INDEX(map.virt_addr);
	case PAGE:
	default:
		return PAGE_INDEX(map.virt_addr);
	}
}

uint64_t phys_addr_width(void)
{
	uint32_t eax, ebx, ecx, edx;
	static uint64_t width = 0;

	if (width == 0)
	{
		eax = 0x80000008;
		ebx = 0;
		ecx = 0;
		edx = 0;

		native_cpuid(&eax, &ebx, &ecx, &edx);

		width = eax & 0xff;
	}

	return width;
}

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

#endif