#ifndef KENCLYSER_KENCLYSER

#define KENCLYSER_KENCLYSER

#include <linux/module.h>
#include <linux/kernel.h>

#define DEV "kenclyser"
#define log(msg, ...) printk(KERN_INFO "[" DEV "] " msg "\n", ##__VA_ARGS__)
#define err(msg, ...) printk(KERN_ALERT "[" DEV "] error: " msg "\n", ##__VA_ARGS__)

#define CR4_PCE_BIT 8
#define CR4_PCE_TRUE_MASK (1UL << CR4_PCE_BIT)
#define CR4_PCE_FALSE_MASK (~CR4_PCE_TRUE_MASK)

#define IA32_PAT 0x277

#define PA1_BIT 8
#define PA2_BIT 16

#define UNCACHEABLE     0x00
#define WRITE_COMBINING 0x01
#define WRITE_THROUGH   0x04
#define WRITE_PROTECTED 0x05
#define WRITE_BACK      0x06
#define UNCACHED        0x07

#define RET_ASSERT(cond)                          \
    do                                            \
    {                                             \
        if (!(cond))                              \
        {                                         \
            err("assertion '" #cond "' failed."); \
            return -EINVAL;                       \
        }                                         \
    } while (0)

#endif