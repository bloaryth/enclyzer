#ifndef ENCLYSER_LIBENCLYSER_LFB

#define ENCLYSER_LIBENCLYSER_LFB

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"
#include "enclyser/libenclyser/memory.h"

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
 * @brief Fill the internal buffer LFB via different sequences.
 *
 * @param filling_sequence a number to choose which sequence will be used
 * @param filling_buffer the buffer which the function operates on
 */
void fill_lfb(int filling_sequence, buffer_t *filling_buffer);

/**
 * @brief Clear the internal buffer LFB via different sequences.
 *
 * @param clearing_sequence a number to choose which sequence will be used
 * @param clearing_buffer the buffer which the function operates on
 */
void clear_lfb(int clearing_sequence, buffer_t *clearing_buffer);

#endif

#endif