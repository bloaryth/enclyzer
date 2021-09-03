#ifndef ENCLYSER_ENCLAVE_ENCLAVE

#define ENCLYSER_ENCLAVE_ENCLAVE

#ifdef __cplusplus
extern "C" {
#endif

#include "enclyser/libenclyser/include.h"

/**
 * @brief First fill lfb and then clear lfb by repestive \p filling_sequence and \p clearing_sequence.
 * 
 * @param filling_sequence the filling sequence selector
 * @param filling_buffer the buffer that a filling sequence operates on
 * @param clearing_sequence the clearing sequence selector
 * @param clearing_buffer the buffer that a clearing sequence operates on
 * @param faulting_buffer the buffer that raises SIGSEGV if accessed
 */
void ecall_grooming(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer);

#ifdef __cplusplus
}
#endif

#endif