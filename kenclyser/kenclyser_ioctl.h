#ifndef KENCLYSER_KENCLYSER_IOCTL

#define KENCLYSER_KENCLYSER_IOCTL

#include <linux/ioctl.h>

#define KENCLYSER_IOCTL_MAGIC            'L'
#define KENCLYSER_IOCTL_VICTIM_INFO      _IOWR(KENCLYSER_IOCTL_MAGIC, 0, struct enclave_info)
#define KENCLYSER_IOCTL_GET_PT_MAPPING   _IOWR(KENCLYSER_IOCTL_MAGIC, 1, address_mapping_t)
#define KENCLYSER_IOCTL_EDBGRD           _IOWR(KENCLYSER_IOCTL_MAGIC, 2, edbgrd_t)
#define KENCLYSER_IOCTL_INVPG            _IOWR(KENCLYSER_IOCTL_MAGIC, 3, invpg_t)
#define KENCLYSER_IOCTL_RDMSR            _IOWR(KENCLYSER_IOCTL_MAGIC, 4, msr_t)
#define KENCLYSER_IOCTL_WRMSR            _IOWR(KENCLYSER_IOCTL_MAGIC, 5, msr_t)

struct enclave_info
{
    uint64_t base;
    uint64_t size;
    uint64_t aep;
    uint64_t tcs;
};

typedef struct {
	uint64_t virt;
	uint64_t phys;
	uint64_t pgd_phys_address;
	uint64_t pgd;
	uint64_t pud;
	uint64_t pmd;
	uint64_t pte;
} address_mapping_t;

typedef struct {
    uint64_t adrs;
    uint64_t val;
    int64_t  len;
    int      write;
} edbgrd_t;

typedef struct {
    uint64_t adrs;
} invpg_t;

typedef struct {
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
} msr_t;

#endif