#ifndef ENCLYSER_LIBENCLYSER_TEMPLATE

#define ENCLYSER_LIBENCLYSER_TEMPLATE

/**
 * @brief the defines and functions that are exclusive to trusted libraries
 *
 */
#ifdef NAMESPACE_SGX_YES

#include "enclyser/libenclyser/template_t.h"

#endif

/**
 * @brief the defines and functions that are exclusive to untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_NO

#include "enclyser/libenclyser/template_u.h"

#endif

/**
 * @brief the defines and functions that are shared by trusted libraries and untrusted libraries
 *
 */
#ifdef NAMESPACE_SGX_SHARED

#endif

#endif