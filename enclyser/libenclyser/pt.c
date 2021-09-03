#include "enclyser/libenclyser/pt.h"

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

/** FIXME refactor the code. */
/** TODO add annotations for every ASSERT */

void flush_tlb(void *adrs)
{
	invpg_t param = {.adrs = (uint64_t)adrs};

	ASSERT(fd_enclyser >= 0); /** /dev/enclyser is opened. */
	ASSERT(ioctl(fd_enclyser, KENCLYSER_IOCTL_INVPG, &param) >= 0);	/** ioctl returns successfully. */
}

void *remap(uint64_t phys)
{
	void *map;
	uintptr_t virt;
	// volatile uint8_t force_mapping;

	ASSERT(fd_enclyser >= 0); /** /dev/enclyser is opened. */
	map = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd_mem, phys & ~PFN_MASK);
	ASSERT(map != MAP_FAILED);

	virt = ((uintptr_t)map) | (phys & PFN_MASK);

	//XXX dereferencing the mapping may cause illegal memory accesses for MMIO
	//regions (eg APIC)
	//force_mapping = *((uint8_t *) virt);

	return (void *)virt;
}

void free_map(void *p)
{
	ASSERT(!munmap((void *)(((uintptr_t)p) & ~PFN_MASK), 0x1000));
}

void *remap_page_table_level(void *address, pt_level_t level)
{
	address_mapping_t *map = get_mappings(address);
	void *addr_remapped;

	addr_remapped = remap(phys_address(map, level));
	free(map);

	return addr_remapped;
}

address_mapping_t *get_mappings(void *address)
{
	address_mapping_t *mapping;
	ASSERT((mapping = (address_mapping_t *)malloc(sizeof(address_mapping_t))));
	memset(mapping, 0x00, sizeof(address_mapping_t));
	mapping->virt = (uintptr_t)address;

	ASSERT(fd_enclyser >= 0); /** /dev/enclyser is opened. */
	ASSERT(ioctl(fd_enclyser, KENCLYSER_IOCTL_GET_PT_MAPPING, mapping) >= 0);	/** ioctl returns successfully. */

	return mapping;
}

uint64_t phys_address(address_mapping_t *map, pt_level_t level)
{
	uint64_t base = phys_base_address(map, level);
	uint64_t index = virt_index(map, level);

	if (level == PAGE)
		return base + index;
	else
		return base + index * 64 / 8;
}

uint64_t phys_base_address(address_mapping_t *map, pt_level_t level)
{
	ASSERT(map);

	switch (level)
	{
	case PGD:
		return map->pgd_phys_address;
	case PUD:
	{
		return PGD_PHYS(map->pgd);
	}
	case PMD:
	{
		ASSERT(!PUD_PS(map->pud));
		return PUD_PS_0_PHYS(map->pud);
	}
	case PTE:
	{
		ASSERT(!PUD_PS(map->pud) && !PMD_PS(map->pmd));
		return PMD_PS_0_PHYS(map->pmd);
	}
	case PAGE:
	default:
	{
		if (PUD_PS(map->pud))
			return PUD_PS_1_PHYS(map->pud);

		if (PMD_PS(map->pmd))
			return PMD_PS_1_PHYS(map->pmd);

		return PT_PHYS(map->pte);
	}
	}
}

uint64_t virt_index(address_mapping_t *map, pt_level_t level)
{
	uint64_t virt;
	ASSERT(map);
	virt = map->virt;

	switch (level)
	{
	case PGD:
		return PGD_INDEX(virt);
	case PUD:
		return PUD_INDEX(virt);
	case PMD:
	{
		ASSERT(!PUD_PS(map->pud));
		return PMD_INDEX(virt);
	}
	case PTE:
	{
		ASSERT(!PUD_PS(map->pud) && !PMD_PS(map->pmd));
		return PTE_INDEX(virt);
	}
	case PAGE:
	default:
	{
		if (PUD_PS(map->pud))
			return PAGE1GiB_INDEX(virt);

		if (PMD_PS(map->pmd))
			return PAGE2MiB_INDEX(virt);

		return PAGE_INDEX(virt);
	}
	}
}

void cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	asm volatile("cpuid\n"
				 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
				 : "a"(*eax), "b"(*ebx), "c"(*ecx), "d"(*edx));
}

uint64_t physical_address_width(void)
{
	uint32_t eax, ebx, ecx, edx;
	static uint64_t width = 0;

	//the result is cached to avoid VM exits due to the issuing of cpuid
	if (width == 0)
	{
		eax = 0x80000008;
		ebx = 0;
		ecx = 0;
		edx = 0;

		cpuid(&eax, &ebx, &ecx, &edx);

		width = eax & 0xff;
	}

	return width;
}

#endif