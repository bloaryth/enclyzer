#ifndef ENCLYSER_LIBENCLYSER_ATTACK

#define ENCLYSER_LIBENCLYSER_ATTACK

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"
#include "enclyser/libenclyser/memory.h"

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
 * @see FLUSH+RELOAD in enclyser/libenclyser/flush_reload.h
 */
void attack(enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer);

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

#endif