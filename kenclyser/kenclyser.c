#include "kenclyser/kenclyser.h"
#include "kenclyser/kenclyser_ioctl.h"

#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/irq.h>

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>

#include <linux/kallsyms.h>
#include <linux/clockchips.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jiuqin Zhou <bloaryth@gmail.com>");
MODULE_DESCRIPTION("SGX-Analyser: A tool in sgx-analyser to control performance monitoring counters");

int target_cpu = -1;
int counter_number = 0;

int check_pat(void)
{
    unsigned int pat_low, pat_high;

    native_rdmsr(IA32_PAT, pat_low, pat_high);
    log("IA32_PAT = 0x%016lx", ((unsigned long)(pat_high) << 32) + pat_low);

    if (((pat_low >> PA1_BIT) & 0xff) != WRITE_COMBINING)
    {
        return -EINVAL;
    }

    return 0;
}

// void enable_user_rdpmc(void)
// {
//     unsigned long cr4_value;

//     asm volatile(
//         "movq %%cr4, %0\n"
//         "orq %1, %0\n"
//         "movq %0, %%cr4\n"
//         : "=a"(cr4_value)
//         : "c"(CR4_PCE_TRUE_MASK)
//         : "memory");
// }

// void disable_user_rdpmc(void)
// {
//     unsigned long cr4_value;

//     asm volatile(
//         "movq %%cr4, %0\n"
//         "andq %1, %0\n"
//         "movq %0, %%cr4\n"
//         : "=a"(cr4_value)
//         : "c"(CR4_PCE_FALSE_MASK)
//         : "memory");
// }

long kenclyser_get_pt_mapping(struct file *filep, unsigned int cmd, unsigned long arg)
{
    address_mapping_t *map = (address_mapping_t *)arg;
    pgd_t *pgd = NULL;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;
    pte_t *pte = NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0))
    p4d_t *p4d = NULL;
#endif

    map->pt_addr = __pa(current->mm->pgd);

    pgd = pgd_offset(current->mm, map->virt_addr);
    map->pgd_addr = __pa(pgd);
    map->pgd_cont = *((uint64_t *)pgd);

    if (!pgd_present(*pgd))
        return 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0))
    /* simply unfold the pgd inside the dummy p4d struct */
    p4d = p4d_offset(pgd, map->virt_addr);
    pud = pud_offset(p4d, map->virt_addr);
#else
    pud = pud_offset(pgd, map->virt_addr);
#endif
    map->pud_addr = __pa(pud);
    map->pud_cont = *((uint64_t *)pud);

    if (!pud_present(*pud))
        return 0;

    pmd = pmd_offset(pud, map->virt_addr);
    map->pmd_addr = __pa(pmd);
    map->pmd_cont = *((uint64_t *)pmd);

    if (!pmd_present(*pmd))
        return 0;

    pte = pte_offset_map(pmd, map->virt_addr);
    map->pte_addr = __pa(pte);
    map->pte_cont = *((uint64_t *)pte);

    if (!pte_present(*pte))
        return 0;

    map->phys_addr = PFN_PHYS(pte_pfn(*pte)) | (map->virt_addr & 0xfff);

    return 0;
}

long kenclyser_rdmsr(struct file *filep, unsigned int cmd, unsigned long arg)
{
    msr_t *msr = (msr_t *)arg;

    native_rdmsr(msr->ecx, msr->eax, msr->edx);

    return 0;
}

long kenclyser_wrmsr(struct file *filep, unsigned int cmd, unsigned long arg)
{
    msr_t *msr = (msr_t *)arg;

    native_wrmsr(msr->ecx, msr->eax, msr->edx);

    return 0;
}

typedef long (*ioctl_t)(struct file *filep, unsigned int cmd, unsigned long arg);

long kenclyser_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    char data[256];
    ioctl_t handler = NULL;
    long ret;

    switch (cmd)
    {
    case KENCLYSER_IOCTL_VICTIM_INFO:
        return -EINVAL;
        break;
    case KENCLYSER_IOCTL_GET_PT_MAPPING:
        handler = kenclyser_get_pt_mapping;
        break;
    case KENCLYSER_IOCTL_EDBGRD:
        return -EINVAL;
        break;
    case KENCLYSER_IOCTL_INVPG:
        return -EINVAL;
        break;
    case KENCLYSER_IOCTL_RDMSR:
        handler = kenclyser_rdmsr;
        break;
    case KENCLYSER_IOCTL_WRMSR:
        handler = kenclyser_wrmsr;
        break;
    default:
        return -EINVAL;
    }

    RET_ASSERT(handler && (_IOC_SIZE(cmd) < 256));
    if (copy_from_user(data, (void __user *)arg, _IOC_SIZE(cmd)))
        return -EFAULT;

    ret = handler(filep, cmd, (unsigned long)((void *)data));

    if (!ret && (cmd & IOC_OUT))
    {
        if (copy_to_user((void __user *)arg, data, _IOC_SIZE(cmd)))
            return -EFAULT;
    }

    return 0;
}

int pmc_open(struct inode *inode, struct file *file)
{
    return 0;
}

int pmc_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations pmc_fops = {
    .owner = THIS_MODULE,
    .compat_ioctl = kenclyser_ioctl,
    .unlocked_ioctl = kenclyser_ioctl,
    .open = pmc_open,
    .release = pmc_release};

static struct miscdevice pmc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEV,
    .fops = &pmc_fops,
    .mode = S_IRUGO | S_IWUGO};

/* Code from: <https://www.libcrack.so/2012/09/02/bypassing-devmem_is_allowed-with-kprobes/> */
static int devmem_is_allowed_handler(struct kretprobe_instance *rp, struct pt_regs *regs)
{
    if (regs->ax == 0)
    {
        regs->ax = 0x1;
    }
    return 0;
}

static struct kretprobe krp = {
    .handler = devmem_is_allowed_handler,
    .maxactive = 20 /* Probe up to 20 instances concurrently. */
};

int init_module(void)
{
    if (check_pat())
    {
        err("PAT check failed..");
        return -EINVAL;
    }

    /* Activate a kretprobe to bypass CONFIG_STRICT_DEVMEM kernel compilation option */
    krp.kp.symbol_name = "devmem_is_allowed";
    if (register_kretprobe(&krp) < 0)
    {
        err("register_kprobe failed..");
        return -EINVAL;
    }

    // enable_user_rdpmc();

    if (misc_register(&pmc_dev))
    {
        err("virtual device registration failed..");
        pmc_dev.this_device = NULL;
        return -EINVAL;
    }

    log("listening on /dev/" DEV);
    return 0;
}

void cleanup_module(void)
{
    if (pmc_dev.this_device)
        misc_deregister(&pmc_dev);

    unregister_kretprobe(&krp);

    // disable_user_rdpmc();

    log("kernel module unloaded");
}