#ifndef ENCLYSER_LIBENCLYSER_FLUSH_RELOAD

#define ENCLYSER_LIBENCLYSER_FLUSH_RELOAD

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

/**
 * @brief The boundry which defines which is a succussful cache hit.
 *
 */
#define TIME_LIMIT 120

/**
 * @brief The FLUSH phase of the FLUSH+RELOAD technique.
 *
 * @param encoding_buffer the buffer that contains temporary data
 * @param printing_buffer the buffer that accumulates persistent data
 */
void flush(buffer_t *encoding_buffer, buffer_t *printing_buffer);

/**
 * @brief The RELOAD phase of the FLUSH+RELOAD technique.
 *
 * @param encoding_buffer the buffer that contains temporary data
 * @param printing_buffer the buffer that accumulates persistent data
 */
void reload(buffer_t *encoding_buffer, buffer_t *printing_buffer);

/**
 * @brief Reset all of the accumulated data to zero.
 *
 * @param printing_buffer the buffer that accumulates persistent data
 */
void reset(buffer_t *printing_buffer);

/**
 * @brief Print the printing_buffer in a clear and concise way.
 *
 * @param printing_buffer the buffer that accumulates persistent data
 * @param printing_bar it decides whether an answer should be printed
 */
void print(buffer_t *printing_buffer, uint8_t printing_bar);

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

#endif

#endif