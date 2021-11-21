#ifndef ENCLYSER_LIBENCLYSER_DEF

#define ENCLYSER_LIBENCLYSER_DEF

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

#include <stdint.h>

/**
 * the times of repetition of an attack
 */
#define REPETITION_TIME 100

/**
 * @brief the general settings of the intel architecutre
 *
 * TODO Automatically getting these data in enclyser/libenclyser/system.h
 *
 */
#define PAGE_SIZE 0x1000
#define CACHELINE_SIZE 0x40
#define L1D_CACHE_SIZE (32 * 1024)
#define L1D_CACHE_STRIDE 0x1000

/**
 * @brief the settings for \p reloading_buffer
 *
 */
#define ENCODING_BUFFER_SLOT_SHIFT 6
#define ENCODING_BUFFER_SLOT_SIZE (1 << ENCODING_BUFFER_SLOT_SHIFT)
#define ENCODING_BUFFER_SLOT_NUM 256

/**
 * @brief the struct for all the buffers in the project
 *
 */
typedef struct
{
    uint8_t *buffer; /** where the data is stored */
    uint8_t *shadow; /** has the same physical address but different virtual address to \p buffer */
    int size;        /** the allocated size of \p buffer */
    int value;       /** the initial value that is mutated and assigned to \p buffer */
    int order;       /** the policy which specifies how the initial value is mutated when assigned */
    int mem_type;    /** the memory type that is modified to the page table of \p buffer */
    int access_ctrl; /** the access control that is modified to the page table of \p buffer */
} enclyser_buffer_t;

/**
 * @brief the enum defines for \p enclyser_buffer_t->order
 *
 */
#define BUFFER_ORDER_NONE 0x0
#define BUFFER_ORDER_CONSTANT 0x1
#define BUFFER_ORDER_OFFSET_INLINE 0x2
// #define BUFFER_ORDER_LINE_NUM       0x3

/**
 * @brief the enum defines for \p enclyser_buffer_t->mem_type
 *
 */
#define BUFFER_MEM_TYPE_NONE 0x0
#define BUFFER_MEM_TYPE_WB 0x1
#define BUFFER_MEM_TYPE_WC 0x2

/**
 * @brief the enum defines for \p enclyser_buffer_t->access_ctrl
 *
 */
#define BUFFER_ACCESS_CTRL_NONE 0x0
#define BUFFER_ACCESS_CTRL_ACCESSED 0x1
#define BUFFER_ACCESS_CTRL_NOT_ACCESSED 0x2
#define BUFFER_ACCESS_CTRL_USER 0x3
#define BUFFER_ACCESS_CTRL_SUPERVISOR 0x4
#define BUFFER_ACCESS_CTRL_PRESENT 0x5
#define BUFFER_ACCESS_CTRL_NOT_PRESENT 0x6
#define BUFFER_ACCESS_CTRL_NOT_RSVD 0x7
#define BUFFER_ACCESS_CTRL_RSVD 0x8

/**
 * @brief the default settings for \p enclyser_buffer_t
 *
 */
#define DEFAULT_FILLING_BUFFER_SIZE 6144                                                    /** the default and minumun size of a filling buffer */
#define DEFAULT_CLEARING_BUFFER_SIZE 6144                                                   /** the default and minumun size of a clearing buffer */
#define DEFAULT_FAULTING_BUFFER_SIZE 4096                                                   /** the default size of a faulting buffer */
#define DEFAULT_ATTACKING_BUFFER_SIZE 4096                                                  /** the default size of an attacking buffer */
#define DEFAULT_ENCODING_BUFFER_SIZE (ENCODING_BUFFER_SLOT_NUM * ENCODING_BUFFER_SLOT_SIZE) /** the default size of a encoding buffer */
#define DEFAULT_PRINTING_BUFFER_SIZE (ENCODING_BUFFER_SLOT_NUM * sizeof(uint8_t))           /** the default size of a printing buffer */
#define DEFAULT_SECRET_BUFFER_SIZE 64                                                       /** the default size of a secret buffer */
#define DEFAULT_BUFFER_VALUE 0                                                              /** the default value of a buffer */
#define DEFAULT_BUFFER_ORDER BUFFER_ORDER_NONE                                              /** the default order of a buffer */
#define DEFAULT_BUFFER_MEM_TYPE BUFFER_MEM_TYPE_NONE                                        /** the default memory type of a buffer */
#define DEFAULT_BUFFER_ACCESS_CTRL BUFFER_ACCESS_CTRL_NONE                                  /** the default memory type of a buffer */

/**
 * @brief the struct used to select an attack in the project
 *
 */
typedef struct
{
    int major;  /** different types of attacks have different \p major */
    int minor;  /** different variants of an attack referenced by \p major have different \p minor. */
    int offset; /** an offset control argument for attacks */
} enclyser_attack_t;

/**
 * @brief the enum defines for \p enclyser_attack_t->major
 *
 */
#define ATTACK_MAJOR_NONE 0x0
#define ATTACK_MAJOR_L1DES 0x1
#define ATTACK_MAJOR_L1TF 0x2
#define ATTACK_MAJOR_LVI 0x3
#define ATTACK_MAJOR_MDS 0x4
#define ATTACK_MAJOR_RDCL 0x5
#define ATTACK_MAJOR_TAA 0x6

/**
 * @brief the enum defines for \p enclyser_attack_t->minor
 *
 */
#define ATTACK_MINOR_NONE 0x0
#define ATTACK_MINOR_NO_TSX 0x10
#define ATTACK_MINOR_TSX 0x20
#define ATTACK_MINOR_STABLE 0xff

/**
 * @brief the default settings for \p enclyser_attack_t
 *
 */
#define DEFAULT_ATTACK_MAJOR ATTACK_MAJOR_NONE
#define DEFAULT_ATTACK_MINOR ATTACK_MINOR_NONE
#define DEFAULT_ATTACK_OFFSET 0

/**
 * @brief The enum defines for different \p filling_sequence.
 *
 */
#define FILLING_SEQUENCE_NONE 0x0
#define FILLING_SEQUENCE_GP_LOAD 0x1
#define FILLING_SEQUENCE_GP_STORE 0x2
#define FILLING_SEQUENCE_NT_LOAD 0x3
#define FILLING_SEQUENCE_NT_STORE 0x4
#define FILLING_SEQUENCE_STR_LOAD 0x5
#define FILLING_SEQUENCE_STR_STORE 0x6

/**
 * @brief The enum defines for different \p clearing_sequence.
 *
 */
#define CLEARING_SEQUENCE_NONE 0x0
#define CLEARING_SEQUENCE_VERW 0x1
#define CLEARING_SEQUENCE_ORPD 0x2

#endif

/**
 * @brief The defines and functions that are exclusive to trusted libraries
 *
 */
#ifdef NAMESPACE_SGX_YES

#endif

/**
 * @brief The defines and functions that are exclusive to untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_NO

/**
 * @brief A bunch of useful msrs.
 *
 */
typedef struct
{
    int ibrs;  /** IA32_SPEC_CTRL[0] */
    int stibp; /** IA32_SPEC_CTRL[1] */
    int ssbd;  /** IA32_SPEC_CTRL[2] */
} enclyser_ia32_spec_ctrl_msr;

typedef struct
{
    int rdcl_no;            /** IA32_ARCH_CAPABILITIES[0] */
    int ibrs_all;           /** IA32_ARCH_CAPABILITIES[1] */
    int rsba;               /** IA32_ARCH_CAPABILITIES[2] */
    int skip_l1dfl_vmentry; /** IA32_ARCH_CAPABILITIES[3] */
    int ssb_no;             /** IA32_ARCH_CAPABILITIES[4] */
    int mds_no;             /** IA32_ARCH_CAPABILITIES[5] */
    int if_pschange_mc_no;  /** IA32_ARCH_CAPABILITIES[6] */
    int tsx_ctrl;           /** IA32_ARCH_CAPABILITIES[7] */
    int taa_no;             /** IA32_ARCH_CAPABILITIES[8] */
} enclyser_ia32_arch_capabilities_msr;

typedef struct
{
    int rtm_force_abort; /** TSX_FORCE_ABORT[0] */
    int tsx_cpuid_clear; /** TSX_FORCE_ABORT[1] */
    int sdv_enable_rtm;  /** TSX_FORCE_ABORT[2] */
} enclyser_tsx_force_abort_msr;

typedef struct
{
    int rtm_disable;     /** IA32_TSX_CTRL[0] */
    int tsx_cpuid_clear; /** IA32_TSX_CTRL[1] */
} enclyser_ia32_tsx_ctrl_msr;

typedef struct
{
    int rngds_mitg_dis; /** IA32_MCU_OPT_CTRL[0] */
} enclyser_ia32_mcu_opt_ctrl_msr;

/**
 * @brief the struct used to describe the system info on the current platform
 *
 */
typedef struct
{
    int sse2;                                                       /** CPUID.(EAX=01H,ECX=0H):EDX[26] */
    int avx;                                                        /** CPUID.(EAX=01H,ECX=0H):ECX[28] */
    int hle;                                                        /** CPUID.(EAX=07H,ECX=0H):EBX[4] */
    int rtm;                                                        /** CPUID.(EAX=07H,ECX=0H):EBX[11] */
    int avx512dq;                                                   /** CPUID.(EAX=07H,ECX=0H):EBX[17] */
    int srbds_ctrl;                                                 /** CPUID.(EAX=07H,ECX=0H):EDX[9] */
    int md_clear;                                                   /** CPUID.(EAX=07H,ECX=0H):EDX[10] */
    int rtm_always_abort;                                           /** CPUID.(EAX=07H,ECX=0H):EDX[11] */
    int tsx_force_abort;                                            /** CPUID.(EAX=07H,ECX=0H):EDX[13] */
    int ibrs_ibpb;                                                  /** CPUID.(EAX=07H,ECX=0H):EDX[26] */
    int stibp;                                                      /** CPUID.(EAX=07H,ECX=0H):EDX[27] */
    int l1d_flush;                                                  /** CPUID.(EAX=07H,ECX=0H):EDX[28] */
    int ia32_arch_capabilities;                                     /** CPUID.(EAX=07H,ECX=0H):EDX[29] */
    int ssbd;                                                       /** CPUID.(EAX=07H,ECX=0H):EDX[31] */
    enclyser_ia32_spec_ctrl_msr ia32_spec_ctrl_msr;                 /** RDMSR.(ECX=0x48):EAX */
    enclyser_ia32_arch_capabilities_msr ia32_arch_capabilities_msr; /** RDMSR.(ECX=0x10a):EAX */
    enclyser_tsx_force_abort_msr tsx_force_abort_msr;               /** RDMSR.(ECX=0x10f):EAX */
    enclyser_ia32_tsx_ctrl_msr ia32_tsx_ctrl_msr;                   /** RDMSR.(ECX=0x122):EAX */
    enclyser_ia32_mcu_opt_ctrl_msr ia32_mcu_opt_ctrl_msr;           /** RDMSR.(ECX=0x123):EAX */
    char model_name[64];                                            /** cat /proc/cpuinfo | grep 'model name' -m 1 | sed 's/model name\t: //' */
    char microcode_version[64];                                     /** cat /proc/cpuinfo | grep microcode -m 1 | awk '{print $3;}' */
    int nr_logical_cores;                                           /** grep -c ^processor /proc/cpuinfo */
    int nr_cores;                                                   /** grep 'cpu cores' /proc/cpuinfo -m 1 | awk '{print $4}' */
} enclyser_sysinfo_t;

#endif

#endif