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
 * @brief VAB_MODEL: the enum defines for different victim-attacker-bridge models.
 * 
 */
#define USER_USER_NONE  0x1
#define SGX_USER_EEXIT  0x2
#define SGX_USER_AEX    0x3

/**
 * @brief VA_LOC: the enum defines for different locations of the victim and attacker.
 * 
 * \p CORE means physical core, not logical core.
 */
#define SAME_THREAD_SAME_CORE       0x1
#define DOUBLE_THREAD_SAME_CORE     0x2
#define DOUBLE_THREAD_DOUBLE_CORE   0x3

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

// /**
//  * @brief A helpher function that sets up the runnning environment.
//  * 
//  * The environment includes \p app_filling_buffer, \p app_clearing_buffer, 
//  * \p app_attack, \p app_attaking_buffer, \p app_encoding_buffer.
//  */
// static void construct_app_environment();

// /**
//  * @brief A helper function that clearns up the running environment.
//  * 
//  * The environment includes \p app_filling_buffer, \p app_clearing_buffer, 
//  * \p app_attack, \p app_attaking_buffer, \p app_encoding_buffer.
//  */
// static void desctruct_app_environment();

// /**
//  * @brief First fill lfb and then clear lfb by repestive \p filling_sequence and \p clearing_sequence.
//  * 
//  * @param filling_sequence the filling sequence selector
//  * @param filling_buffer the buffer that a filling sequence operates on
//  * @param clearing_sequence the clearing sequence selector
//  * @param clearing_buffer the buffer that a clearing sequence operates on
//  * @param faulting_buffer the buffer that raises SIGSEGV if accessed
//  */
// static void app_grooming(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer);

// /**
//  * @brief Execute attack select by \p attack. Step 1.
//  * 
//  * @param attack_spec the attack selector
//  * @param attaking_buffer the buffer that an attack operates on
//  * @param encoding_buffer the buffer that encodes the temporary attack output
//  * @param printing_buffer the buffer that consistently logs and accumulates attack output
//  */
// static void app_attack_1(enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer);

// /**
//  * @brief Execute attack select by \p attack. Step 2.
//  * 
//  * @param attack_spec the attack selector
//  * @param attaking_buffer the buffer that an attack operates on
//  * @param encoding_buffer the buffer that encodes the attack output
//  */
// static void app_attack_2(enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer);

// /**
//  * @brief A single test provided by this app.
//  * 
//  * @param filling_sequence the filling sequence selector
//  * @param filling_buffer the buffer that a filling sequence operates on
//  * @param clearing_sequence the clearing sequence selector
//  * @param clearing_buffer the buffer that a clearing sequence operates on
//  * @param faulting_buffer the buffer that raises SIGSEGV if accessed
//  * @param attack_spec the attack selector
//  * @param attaking_buffer the buffer that an attack operates on
//  * @param encoding_buffer the buffer that encodes the temporary attack output
//  * @param printing_buffer the buffer that consistently logs and accumulates attack output
//  */
// static void app_test(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer, enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer);

#ifdef __cplusplus
}
#endif

#endif