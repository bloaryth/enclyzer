#ifndef ENCLYSER_LIBENCLYSER_ATTACK

#define ENCLYSER_LIBENCLYSER_ATTACK

#ifdef __cplusplus
extern "C" {
#endif

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"
#include "enclyser/libenclyser/memory.h"

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
static void l1des_attack(enclyer_attack_t *l1des_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

/**
 * @brief Try different variants of the l1tf attack.
 * 
 * @param l1tf_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void l1tf_attack(enclyer_attack_t *l1tf_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

/**
 * @brief Try different variants of the lvi attack.
 * 
 * @param lvi_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void lvi_attack(enclyer_attack_t *lvi_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

/**
 * @brief Try different variants of the mds attack.
 * 
 * @param mds_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void mds_attack(enclyer_attack_t *mds_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

/**
 * @brief Try different variants of the taa attack.
 * 
 * @param taa_attack the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/channel/flush_reload.h
 */
static void taa_attack(enclyer_attack_t *taa_attack, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

/**
 * @brief Try different types of attacks.
 * 
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyser/libenclyser/flush_reload.h
 */
void attack(enclyer_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

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

#ifdef __cplusplus
}
#endif

#endif