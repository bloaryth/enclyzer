#ifndef ENCLYSER_LIBENCLYSER_FLUSH_RELOAD

#define ENCLYSER_LIBENCLYSER_FLUSH_RELOAD

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

#include <ctype.h>  // isprint function

/**
 * @brief The boundry which defines which is a succussful cache hit.
 * 
 */
#define TIME_LIMIT  120

/**
 * @brief A set of defines that collaborately defines the recovery rate.
 * 
 */
#define RECOVERY_NUMERATOR      1
#define RECOVERY_DINOMINATOR    100

/**
 * @brief The FLUSH phase of the FLUSH+RELOAD technique.
 * 
 * @param encoding_buffer the buffer that contains temporary data
 * @param printing_buffer the buffer that accumulates persistent data
 */
void flush(enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer);

/**
 * @brief The RELOAD phase of the FLUSH+RELOAD technique.
 * 
 * @param encoding_buffer the buffer that contains temporary data
 * @param printing_buffer the buffer that accumulates persistent data
 */
void reload(enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer);

/**
 * @brief Print the printing_buffer in a clear and concise way.
 * 
 * @param printing_buffer the buffer that accumulates persistent data
 */
void print(enclyser_buffer_t *printing_buffer);

#endif

#ifdef __cplusplus
}
#endif

#endif