#ifndef enclyzer_LIBenclyzer_MEMORY

#define enclyzer_LIBenclyzer_MEMORY

#include "enclyzer/libenclyzer/def.h"
#include "enclyzer/libenclyzer/info.h"
#include "enclyzer/libenclyzer/pt.h"

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

/**
 * @brief Malloc a space for a enclyzer buffer.
 *
 * If \p buffer is NULL, allocating a new buffer for it, or skip this step.
 * If \p shadow is NULL, shadowing the *buffer* for it, or skip this step.
 * So the this function can be called multiple times safely, and parameter can be preset to allow
 * more flexibility if the buffer is already allocated or shadowed in other ways.
 *
 * @param buffer the buffer which the function operates on
 */
void malloc_buffer(buffer_t *buffer);

/**
 * @brief Free the space of a enclyzer buffer.
 *
 * @param buffer the buffer which the function operates on
 */
void free_buffer(buffer_t *buffer);

/**
 * @brief Modify the page table entry of a enclyzer buffer.
 *
 * @param buffer the buffer which the function operates on
 */
void cripple_buffer(buffer_t *buffer);

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

/**
 * @brief Flush the enclyzer buffer to ensure a later enclyzer.
 *
 * @param buffer the buffer which the function operates on
 */
void flush_buffer(buffer_t *buffer);

/**
 * @brief Assign values to a enclyzer buffer according to a policy.
 *
 * @param buffer the buffer which the function operates on
 */
void assign_buffer(buffer_t *buffer);

#endif

#endif