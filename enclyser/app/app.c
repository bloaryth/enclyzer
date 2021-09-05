#include "enclyser/app/app.h"

#if (VAB_MODEL == SGX_USER_EEXIT) || (VAB_MODEL == SGX_USER_AEX)
#include "enclyser/app/enclave_u.h"
#endif

#include "signal.h"

sgx_enclave_id_t global_eid;
sgx_launch_token_t token;
sgx_status_t ret;
int updated;

int app_filling_sequence;
int app_clearing_sequence;

enclyser_buffer_t app_filling_buffer = {
    .size = DEFAULT_FILLING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL
};

enclyser_buffer_t app_clearing_buffer = {
    .size = DEFAULT_CLEARING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL
};

enclyser_buffer_t app_faulting_buffer = {
    .size = DEFAULT_FAULTING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL
};

enclyser_attack_t app_attack_spec = {
    .major = DEFAULT_ATTACK_MAJOR,
    .minor = DEFAULT_ATTACK_MINOR
};

enclyser_buffer_t app_attaking_buffer = {
    .size = DEFAULT_ATTACKING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL
};

enclyser_buffer_t app_encoding_buffer = {
    .size = DEFAULT_ENCODING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL
};

enclyser_buffer_t app_printing_buffer = {
    .size = DEFAULT_PRINTING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL
};

int sigsegv_signal;

void sigsegv_handler(int signal)
{
    sigsegv_signal = signal;

    // TODO check and reset access_ctrl and call cripple_enclyser_buffer()

    app_attack_2(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer, &app_printing_buffer);

    sigsegv_signal = 0;
}

static void construct_app_environment()
{
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    ASSERT(ret == SGX_SUCCESS);

    open_system_file();

    malloc_enclyser_buffer(&app_filling_buffer);
    malloc_enclyser_buffer(&app_clearing_buffer);
    malloc_enclyser_buffer(&app_faulting_buffer);

    malloc_enclyser_buffer(&app_attaking_buffer);
    malloc_enclyser_buffer(&app_encoding_buffer);
    malloc_enclyser_buffer(&app_printing_buffer);

    ASSERT(signal(SIGSEGV, sigsegv_handler) != SIG_ERR);
}

static void desctruct_app_environment()
{
    sgx_destroy_enclave(global_eid);

    free_enclyser_buffer(&app_filling_buffer);
    free_enclyser_buffer(&app_clearing_buffer);
    free_enclyser_buffer(&app_faulting_buffer);

    free_enclyser_buffer(&app_attaking_buffer);
    free_enclyser_buffer(&app_encoding_buffer);
    free_enclyser_buffer(&app_printing_buffer);

    close_system_file();

    ASSERT(signal(SIGSEGV, SIG_DFL) != SIG_ERR);
}

static void app_grooming(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer)
{
    fill_lfb(filling_sequence, filling_buffer);
    clear_lfb(clearing_sequence, clearing_buffer);
    /** a placeholder for access to \p faulting_buffer */
}

static void app_attack_1(enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer)
{
    flush_enclyser_buffer(attaking_buffer);
    flush_enclyser_buffer(encoding_buffer);
}

static void app_attack_2(enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer)
{
    attack(attack_spec, attaking_buffer, encoding_buffer);
    reload(encoding_buffer, printing_buffer);
}

static void app_test(int filling_sequence, enclyser_buffer_t *filling_buffer, int clearing_sequence, enclyser_buffer_t *clearing_buffer, enclyser_buffer_t *faulting_buffer, enclyser_attack_t *attack_spec, enclyser_buffer_t *attaking_buffer, enclyser_buffer_t *encoding_buffer, enclyser_buffer_t *printing_buffer)
{
    int i;

    for (i = 0; i < REPETITION_TIME; i++)
    {
        app_attack_1(attack_spec, attaking_buffer, encoding_buffer, printing_buffer);
#if VAB_MODEL == USER_USER_NONE
        app_grooming(filling_sequence, filling_buffer, clearing_sequence, clearing_buffer, faulting_buffer);
#elif (VAB_MODEL == SGX_USER_EEXIT) || (VAB_MODEL == SGX_USER_AEX)
        ecall_grooming(filling_sequence, filling_buffer, clearing_sequence, clearing_buffer, faulting_buffer);
#endif
        app_attack_2(attack_spec, attaking_buffer, encoding_buffer, printing_buffer);
    }
    print(printing_buffer);
}

int main(int argc, char **argv)
{
    construct_app_environment();

    /**
     * @brief TODO the interation of tests with different settings
     * 
     * app_filling_sequence
     * app_clearing_sequence
     * 
     * app_attack_spec.major
     * app_attack_spec.minor
     * 
     * app_attacking_buffer.value
     * app_attacking_buffer.order
     * app_attacking_buffer.mem_type
     * app_attacking_buffer.access_ctrl
     */
    app_test(app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer, &app_attack_spec, &app_attaking_buffer, &app_encoding_buffer, &app_printing_buffer);

    desctruct_app_environment();

    return 0;
}