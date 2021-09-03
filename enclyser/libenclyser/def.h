#ifndef ENCLYSER_LIBENCLYSER_DEF

#define ENCLYSER_LIBENCLYSER_DEF

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

#include <stdint.h>

/**
 * the times of repetition of an attack
 */
#define REPETITION_TIME     100

/**
 * @brief the general settings of the intel architecutre
 * 
 * TODO Automatically getting these data in enclyser/libenclyser/system.h
 * 
 */
#define PAGE_SIZE           0x1000  /** FIXME See enclyser/libenclyser/pt.h */
#define CACHELINE_SIZE      0x40
#define L1D_CACHE_SIZE      (32 * 1024)
#define L1D_CACHE_STRIDE    0x1000

/**
 * @brief the settings for \p reloading_buffer
 * 
 */
#define ENCODING_BUFFER_SLOT_SHIFT     6
#define ENCODING_BUFFER_SLOT_SIZE      (1 << ENCODING_BUFFER_SLOT_SHIFT)
#define ENCODING_BUFFER_SLOT_NUM       256

/**
 * @brief the struct for all the buffers in the project
 * 
 */
typedef struct {
    char *buffer;       /** where the data is stored */
    char *shadow;       /** has the same physical address but different virtual address to \p buffer */
    int size;           /** the allocated size of \p buffer */
    int value;          /** the initial value that is mutated and assigned to \p buffer */
    int order;          /** the policy which specifies how the initial value is mutated when assigned */
    int mem_type;       /** the memory type that is modified to the page table of \p buffer */
    int access_ctrl;    /** the access control that is modified to the page table of \p buffer */
} enclyser_buffer_t;

/**
 * @brief the enum defines for \p enclyser_buffer_t->order
 * 
 */
#define BUFFER_ORDER_NONE           0x0
#define BUFFER_ORDER_CONSTANT       0x1
#define BUFFER_ORDER_OFFSET_INLINE  0x2
#define BUFFER_ORDER_LINE_NUM       0x3

/**
 * @brief the enum defines for \p enclyser_buffer_t->mem_type
 * 
 */
#define BUFFER_MEM_TYPE_NONE    0x0
#define BUFFER_MEM_TYPE_WB      0x1
#define BUFFER_MEM_TYPE_WC      0x2

/**
 * @brief the enum defines for \p enclyser_buffer_t->access_ctrl
 * 
 */
#define BUFFER_ACCESS_CTRL_NONE             0x0
#define BUFFER_ACCESS_CTRL_NOT_ACCESSED     0x1
#define BUFFER_ACCESS_CTRL_SUPERVISOR       0x2
#define BUFFER_ACCESS_CTRL_NOT_PRESENT      0x3
#define BUFFER_ACCESS_CTRL_RSVD             0x4

/**
 * @brief the default settings for \p enclyser_buffer_t
 * 
 */
#define DEFAULT_FILLING_BUFFER_SIZE     6144    /** the default and minumun size of a filling buffer */
#define DEFAULT_CLEARING_BUFFER_SIZE    6144    /** the default and minumun size of a clearing buffer */
#define DEFAULT_FAULTING_BUFFER_SIZE    6144    /** the default size of a faulting buffer */
#define DEFAULT_ATTACKING_BUFFER_SIZE   6144    /** the default size of an attacking buffer */
#define DEFAULT_ENCODING_BUFFER_SIZE    (ENCODING_BUFFER_SLOT_NUM * ENCODING_BUFFER_SLOT_SIZE)  /** the default size of a encoding buffer */
#define DEFAULT_PRINTING_BUFFER_SIZE    (ENCODING_BUFFER_SLOT_NUM * sizeof(int))                /** the default size of a printing buffer */
#define DEFAULT_BUFFER_VALUE            0       /** the default value of a buffer */
#define DEFAULT_BUFFER_ORDER            BUFFER_ORDER_NONE       /** the default order of a buffer */
#define DEFAULT_BUFFER_MEM_TYPE         BUFFER_MEM_TYPE_NONE    /** the default memory type of a buffer */
#define DEFAULT_BUFFER_ACCESS_CTRL      BUFFER_ACCESS_CTRL_NONE /** the default memory type of a buffer */

/**
 * @brief the struct used to select an attack in the project
 * 
 */
typedef struct {
    int major;      /** different types of attacks have different \p major */
    int minor;      /** different variants of an attack referenced by \p major have different \p minor. */
} enclyer_attack_t;

/**
 * @brief the enum defines for \p enclyer_attack_t->major
 * 
 */
#define ATTACK_MAJOR_NONE       0x0
#define ATTACK_MAJOR_L1DES      0x1
#define ATTACK_MAJOR_L1TF       0x2
#define ATTACK_MAJOR_LVI        0x3
#define ATTACK_MAJOR_MDS        0x4
#define ATTACK_MAJOR_TAA        0x5

/**
 * @brief the enum defines for \p enclyer_attack_t->minor
 * 
 */
#define ATTACK_MINOR_NONE       0x0
#define ATTACK_MINOR_STABLE     0xff

/**
 * @brief the default settings for \p enclyer_attack_t
 * 
 */
#define DEFAULT_ATTACK_MAJOR    ATTACK_MAJOR_NONE
#define DEFAULT_ATTACK_MINOR    ATTACK_MINOR_NONE

/**
 * @brief The enum defines for different \p filling_sequence.
 * 
 */
#define FILLING_SEQUENCE_NONE      0x0
#define FILLING_SEQUENCE_GP_LOAD   0x1
#define FILLING_SEQUENCE_GP_STORE  0x2
#define FILLING_SEQUENCE_NT_LOAD   0x3
#define FILLING_SEQUENCE_NT_STORE  0x4
#define FILLING_SEQUENCE_STR_LOAD  0x5
#define FILLING_SEQUENCE_STR_STORE 0x6

/**
 * @brief The enum defines for different \p clearing_sequence.
 * 
 */
#define CLEARING_SEQUENCE_NONE     0x0
#define CLEARING_SEQUENCE_VERW     0x1
#define CLEARING_SEQUENCE_ORPD     0x2

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

#endif

#ifdef __cplusplus
}
#endif

#endif