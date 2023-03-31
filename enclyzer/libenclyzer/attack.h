#ifndef enclyzer_LIBenclyzer_ATTACK

#define enclyzer_LIBenclyzer_ATTACK

#include "enclyzer/libenclyzer/def.h"
#include "enclyzer/libenclyzer/info.h"
#include "enclyzer/libenclyzer/memory.h"

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

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

/**
 * @brief Try different types of attacks.
 *
 * @param attack_spec the specified attack
 * @param attaking_buffer the buffer used by the attack
 * @param encoding_buffer the buffer used to encode data leaked
 *
 * @see FLUSH+RELOAD in enclyzer/libenclyzer/flush_reload.h
 */
void attack(attack_spec_t *attack_spec, buffer_t *attaking_buffer, buffer_t *encoding_buffer);

#endif

#endif