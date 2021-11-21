#ifndef ENCLYSER_LIBENCLYSER_INCLUDE

#define ENCLYSER_LIBENCLYSER_INCLUDE

#include "enclyser/libenclyser/attack.h"
#include "enclyser/libenclyser/def.h"
#include "enclyser/libenclyser/flush_reload.h"
#include "enclyser/libenclyser/info.h"
#include "enclyser/libenclyser/lfb.h"
#include "enclyser/libenclyser/memory.h"
#include "enclyser/libenclyser/pt.h"
#include "enclyser/libenclyser/system.h"

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

#endif

#endif