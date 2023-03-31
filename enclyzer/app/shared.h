#ifndef enclyzer_APP_SHARED

#define enclyzer_APP_SHARED

#define _GNU_SOURCE

#include "enclyzer/enclave/enclave_u.h"

#include "enclyzer/libenclyzer/include.h"

#include <criterion/criterion.h>

#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_urts.h"  /* sgx_launch_token_t */

#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>

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
sysinfo_t sysinfo;
attack_spec_t attack_spec;

/* ========== Virtual ========== */

int* filling_sequence;
// int* clearing_sequence;

buffer_t* filling_buffer;
// buffer_t* clearing_buffer;
// buffer_t* faulting_buffer;
buffer_t* attacking_buffer;
buffer_t* encoding_buffer;
buffer_t* printing_buffer;

/* ========== Real ========== */

int app_filling_sequence;
// int app_clearing_sequence;

buffer_t app_filling_buffer;
// buffer_t app_clearing_buffer;
// buffer_t app_faulting_buffer;
buffer_t app_attacking_buffer;
buffer_t app_encoding_buffer;
buffer_t app_printing_buffer;

int enclave_filling_sequence;
// int enclave_clearing_sequence;

buffer_t encalve_secret_buffer;


/**
 * @brief A helpher function that sets up the runnning environment.
 *
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer,
 * \p app_attack, \p app_attacking_buffer, \p app_encoding_buffer.
 */
void construct_app_environment(void);

/**
 * @brief A helper function that clearns up the running environment.
 *
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer,
 * \p app_attack, \p app_attacking_buffer, \p app_encoding_buffer.
 */
void destruct_app_environment(void);

#endif