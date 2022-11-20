#pragma region shared

#include "enclyser/app/app.h"

sgx_enclave_id_t global_eid = 0;
sgx_launch_token_t token = {};
sgx_status_t ret = 0;
int updated = 0;

sysinfo_t sysinfo = {};

attack_spec_t attack_spec = {
    .major = DEFAULT_ATTACK_MAJOR,
    .minor = DEFAULT_ATTACK_MINOR,
    .offset = DEFAULT_ATTACK_OFFSET};

/* ========== APP ========== */

int app_filling_sequence = 0;
// int app_clearing_sequence = 0;

buffer_t app_filling_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_FILLING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

// buffer_t app_clearing_buffer = {
//     .buffer = NULL,
//     .shadow = NULL,
//     .size = DEFAULT_CLEARING_BUFFER_SIZE,
//     .value = DEFAULT_BUFFER_VALUE,
//     .order = DEFAULT_BUFFER_ORDER,
//     .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//     .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

// buffer_t app_faulting_buffer = {
//     .buffer = NULL,
//     .shadow = NULL,
//     .size = DEFAULT_FAULTING_BUFFER_SIZE,
//     .value = DEFAULT_BUFFER_VALUE,
//     .order = DEFAULT_BUFFER_ORDER,
//     .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//     .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

buffer_t app_attacking_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_ATTACKING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

buffer_t app_encoding_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_ENCODING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

buffer_t app_printing_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_PRINTING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

/* ========== ENCLAVE ========== */

int enclave_filling_sequence = 0;
// int enclave_clearing_sequence = 0;

buffer_t encalve_secret_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_FILLING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

// int sigsegv_signal;

// void sigsegv_handler(int signal)
// {
//     sigsegv_signal = signal;

//     ASSERT(!mprotect(app_faulting_buffer.buffer, app_faulting_buffer.size, PROT_READ | PROT_WRITE));

//     flush_buffer(&app_encoding_buffer);
//     attack(&attack_spec, &app_attacking_buffer, &app_encoding_buffer);
//     reload(&app_encoding_buffer, &app_printing_buffer);

//     sigsegv_signal = 0;
// }

/**
 * @brief A helpher function that sets up the runnning environment.
 *
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer,
 * \p app_attack, \p app_attacking_buffer, \p app_encoding_buffer.
 */
void construct_app_environment(void)
{
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    ASSERT(ret == SGX_SUCCESS);

    open_system_file();

    get_system_info(&sysinfo);

    ecall_get_secret(global_eid, &encalve_secret_buffer.buffer);

    malloc_buffer(&app_filling_buffer);
    // malloc_buffer(&app_clearing_buffer);
    // malloc_buffer(&app_faulting_buffer);
    malloc_buffer(&app_attacking_buffer);
    malloc_buffer(&app_encoding_buffer);
    malloc_buffer(&app_printing_buffer);
    malloc_buffer(&encalve_secret_buffer);

    // ASSERT(signal(SIGSEGV, sigsegv_handler) != SIG_ERR);
}

/**
 * @brief A helper function that clearns up the running environment.
 *
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer,
 * \p app_attack, \p app_attacking_buffer, \p app_encoding_buffer.
 */
void destruct_app_environment(void)
{
    sgx_destroy_enclave(global_eid);

    free_buffer(&app_filling_buffer);
    // free_buffer(&app_clearing_buffer);
    // free_buffer(&app_faulting_buffer);
    free_buffer(&app_attacking_buffer);
    free_buffer(&app_encoding_buffer);
    free_buffer(&app_printing_buffer);

    close_system_file();

    ASSERT(signal(SIGSEGV, SIG_DFL) != SIG_ERR);
}

#pragma endregion
