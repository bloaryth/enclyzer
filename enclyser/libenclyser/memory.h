#ifndef ENCLYSER_LIBENCLYSER_MEMORY

#define ENCLYSER_LIBENCLYSER_MEMORY

#ifdef __cplusplus
extern "C" {
#endif

#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/info.h"
#include "enclyser/libenclyser/pt.h"

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 * 
 */
#ifdef NAMESPACE_SGX_SHARED

/**
 * @brief Flush the enclyser buffer to ensure a later enclyser.
 * 
 * @param enclyser_buffer the buffer which the function operates on
 */
void flush_enclyser_buffer(enclyser_buffer_t *enclyser_buffer);

/**
 * @brief Assign values to a enclyser buffer according to a policy.
 * 
 * @param enclyser_buffer the buffer which the function operates on
 */
void assign_enclyser_buffer(enclyser_buffer_t *enclyser_buffer);

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

/**
 * @brief Malloc a space for a enclyser buffer.
 * 
 * @param enclyser_buffer the buffer which the function operates on
 */
void malloc_enclyser_buffer(enclyser_buffer_t *enclyser_buffer);

/**
 * @brief Free the space of a enclyser buffer.
 * 
 * @param enclyser_buffer the buffer which the function operates on
 */
void free_enclyser_buffer(enclyser_buffer_t *enclyser_buffer);

/**
 * @brief Modify the page table entry of a enclyser buffer.
 * 
 * @param enclyser_buffer the buffer which the function operates on
 */
void cripple_enclyser_buffer(enclyser_buffer_t *enclyser_buffer);

#endif

#ifdef __cplusplus
}
#endif

#endif