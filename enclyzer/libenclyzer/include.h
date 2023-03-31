#ifndef enclyzer_LIBenclyzer_INCLUDE

#define enclyzer_LIBenclyzer_INCLUDE

#include "enclyzer/libenclyzer/attack.h"
#include "enclyzer/libenclyzer/def.h"
#include "enclyzer/libenclyzer/flush_reload.h"
#include "enclyzer/libenclyzer/info.h"
#include "enclyzer/libenclyzer/lfb.h"
#include "enclyzer/libenclyzer/memory.h"
#include "enclyzer/libenclyzer/pt.h"
#include "enclyzer/libenclyzer/system.h"

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

#endif

#endif