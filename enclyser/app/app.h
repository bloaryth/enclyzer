#ifndef ENCLYSER_APP_APP

#define ENCLYSER_APP_APP

#ifdef __cplusplus
extern "C"
{
#endif

#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_urts.h"  /* sgx_launch_token_t */

#include "enclyser/libenclyser/include.h"

/**
 * @brief defines and variables for enclave creation and destruction
 * 
 */
#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"

sgx_enclave_id_t global_eid;
sgx_launch_token_t token;
sgx_status_t ret;
int updated;

/**
 * @brief defines and variables for grooming and attack.
 * 
 */
int app_filling_sequence;
int app_clearing_sequence;

enclyser_buffer_t app_filling_buffer;
enclyser_buffer_t app_clearing_buffer;
enclyser_buffer_t app_faulting_buffer;

enclyser_attack_t app_attack_spec;

enclyser_buffer_t app_attaking_buffer;
enclyser_buffer_t app_encoding_buffer;
enclyser_buffer_t app_printing_buffer;

/**
 * @brief defines and variables for signal handling
 * 
 */
int sigsegv_signal;

/**
 * @brief A signal handler for SIGSEGV.
 * 
 * @param signal the signal number passed in
 */
void sigsegv_handler(int signal);

#ifdef __cplusplus
}
#endif

#endif