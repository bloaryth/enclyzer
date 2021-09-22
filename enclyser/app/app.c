#pragma region shared

#define _GNU_SOURCE

#include "enclyser/app/app.h"
#include "enclyser/app/enclave_u.h"

#include <criterion/criterion.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>

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
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_clearing_buffer = {
    .size = DEFAULT_CLEARING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_faulting_buffer = {
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
    .size = DEFAULT_ATTACKING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_encoding_buffer = {
    .size = DEFAULT_ENCODING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_buffer_t app_printing_buffer = {
    .size = DEFAULT_PRINTING_BUFFER_SIZE,
    .value = DEFAULT_BUFFER_VALUE,
    .order = DEFAULT_BUFFER_ORDER,
    .mem_type = DEFAULT_BUFFER_MEM_TYPE,
    .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

enclyser_sysinfo_t app_sysinfo = {};

int sigsegv_signal;

void sigsegv_handler(int signal)
{
    sigsegv_signal = signal;

    ASSERT(!mprotect(app_faulting_buffer.buffer, app_faulting_buffer.size, PROT_READ | PROT_WRITE));

    attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);

    sigsegv_signal = 0;
}

/**
 * @brief A helpher function that sets up the runnning environment.
 * 
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer, 
 * \p app_attack, \p app_attaking_buffer, \p app_encoding_buffer.
 */
static void construct_app_environment()
{
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    ASSERT(ret == SGX_SUCCESS);

    open_system_file();

    get_system_info(&app_sysinfo);

    malloc_enclyser_buffer(&app_filling_buffer);
    malloc_enclyser_buffer(&app_clearing_buffer);
    malloc_enclyser_buffer(&app_faulting_buffer);

    malloc_enclyser_buffer(&app_attaking_buffer);
    malloc_enclyser_buffer(&app_encoding_buffer);
    malloc_enclyser_buffer(&app_printing_buffer);

    ASSERT(signal(SIGSEGV, sigsegv_handler) != SIG_ERR);

    sleep(5); // IMPORTANT! FIXME robust against signals */
}

/**
 * @brief A helper function that clearns up the running environment.
 * 
 * The environment includes \p app_filling_buffer, \p app_clearing_buffer, 
 * \p app_attack, \p app_attaking_buffer, \p app_encoding_buffer.
 */
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

#pragma endregion

#pragma region _system

Test(_system, print_system_info, .disabled = false)
{
    open_system_file();

    get_system_info(&app_sysinfo);
    print_system_info(&app_sysinfo);

    close_system_file();
}

#pragma endregion

#pragma region taa

TestSuite(taa, .init = construct_app_environment, .fini = desctruct_app_environment);

#pragma region same_thread_taa_nosgx_is_effective

/**
 * @brief Test if same_thread_taa_nosgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_same_thread_taa_nosgx_is_effective()
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            fill_lfb(app_filling_sequence, &app_filling_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, same_thread_taa_nosgx_is_effective, .disabled = false)
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
    cr_expect(test_core_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_taa_eexit_is_effective

/**
 * @brief Test if same_thread_taa_eexit is effective with a successful rate above or equal to 10% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_same_thread_taa_eexit_is_effective()
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, same_thread_taa_eexit_is_effective, .disabled = false)
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
    cr_expect(test_core_same_thread_taa_eexit_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_taa_eexit_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_taa_eexit_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_taa_eexit_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_taa_eexit_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_taa_eexit_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_taa_aex_is_effective

/**
 * @brief Test if same_thread_taa_aex is effective with a successful rate above 10% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_same_thread_taa_aex_is_effective()
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ASSERT(!mprotect(app_faulting_buffer.buffer, app_faulting_buffer.size, PROT_NONE));
            flush_enclyser_buffer(&app_encoding_buffer);
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, same_thread_taa_aex_is_effective, .disabled = false)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x81;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_same_thread_taa_aex_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_taa_aex_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_taa_aex_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_taa_aex_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_taa_aex_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_taa_aex_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_taa_nosgx_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_thread_taa_nosgx_is_effective_victim_thread(void *arg)
{
    int i;

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
static void *test_core_cross_thread_taa_nosgx_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_thread_taa_nosgx_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_taa_nosgx_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_taa_nosgx_is_effective_adversary_thread, NULL));

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

Test(taa, cross_thread_taa_nosgx_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_taa_ecall_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_thread_taa_ecall_is_effective_victim_thread(void *arg)
{
    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_thread_taa_ecall_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_thread_taa_ecall_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_taa_ecall_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_taa_ecall_is_effective_adversary_thread, NULL));

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

Test(taa, cross_thread_taa_ecall_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_thread_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_taa_nosgx_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_core_taa_nosgx_is_effective_victim_thread(void *arg)
{
    int i;

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
static void *test_core_cross_core_taa_nosgx_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_core_taa_nosgx_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_taa_nosgx_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_taa_nosgx_is_effective_adversary_thread, NULL));

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

Test(taa, cross_core_taa_nosgx_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_core_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_core_taa_ecall_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_core_taa_ecall_is_effective_victim_thread(void *arg)
{
    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_core_taa_ecall_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_core_taa_ecall_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_taa_ecall_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_taa_ecall_is_effective_adversary_thread, NULL));

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

Test(taa, cross_core_taa_ecall_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_core_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_taa_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion

#pragma region msd

TestSuite(mds, .init = construct_app_environment, .fini = desctruct_app_environment);

#pragma region same_thread_mds_nosgx_is_effective

/**
 * @brief Test if same_thread_mds_nosgx is effective with a successful rate above or equal to 10% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_same_thread_mds_nosgx_is_effective()
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            fill_lfb(app_filling_sequence, &app_filling_buffer);
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

Test(mds, same_thread_mds_nosgx_is_effective, .disabled = false)
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
    cr_expect(test_core_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_mds_eexit_is_effective

/**
 * @brief Test if same_thread_mds_eexit is effective with a successful rate above or equal to 10% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_same_thread_mds_eexit_is_effective()
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, same_thread_mds_eexit_is_effective, .disabled = false)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
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
    cr_expect(test_core_same_thread_mds_eexit_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_mds_eexit_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_mds_eexit_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_mds_eexit_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_mds_eexit_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_mds_eexit_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region same_thread_mds_aex_is_effective

/**
 * @brief Test if same_thread_mds_aex is effective with a successful rate above or equal to 10% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_same_thread_mds_aex_is_effective()
{
    int i, offset, allowance;
    int core;
    cpu_set_t cpuset;

    core = 1;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ASSERT(!mprotect(app_faulting_buffer.buffer, app_faulting_buffer.size, PROT_NONE));
            flush_enclyser_buffer(&app_encoding_buffer);
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] >= 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, same_thread_mds_aex_is_effective, .disabled = false)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
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
    cr_expect(test_core_same_thread_mds_aex_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_same_thread_mds_aex_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_same_thread_mds_aex_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_same_thread_mds_aex_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_same_thread_mds_aex_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_same_thread_mds_aex_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region cross_thread_mds_nosgx_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_thread_mds_nosgx_is_effective_victim_thread(void *arg)
{
    int i;

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
static void *test_core_cross_thread_mds_nosgx_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_thread_mds_nosgx_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_mds_nosgx_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_mds_nosgx_is_effective_adversary_thread, NULL));

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

Test(mds, cross_thread_mds_nosgx_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region corss_thread_mds_ecall_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_thread_mds_ecall_is_effective_victim_thread(void *arg)
{
    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_thread_mds_ecall_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_thread_mds_ecall_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_thread_mds_ecall_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_thread_mds_ecall_is_effective_adversary_thread, NULL));

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

Test(mds, cross_thread_mds_ecall_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_thread_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_thread_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_thread_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_thread_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_thread_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_thread_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region corss_core_mds_nosgx_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_core_mds_nosgx_is_effective_victim_thread(void *arg)
{
    int i;

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
static void *test_core_cross_core_mds_nosgx_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_core_mds_nosgx_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_mds_nosgx_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_mds_nosgx_is_effective_adversary_thread, NULL));

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

Test(mds, cross_core_mds_nosgx_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_core_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region corss_core_mds_ecall_is_effective

/**
 * @brief The victim function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_core_mds_ecall_is_effective_victim_thread(void *arg)
{
    ecall_rep_fill_lfb(global_eid, app_filling_sequence, &app_filling_buffer);

    return NULL;
}

/**
 * @brief The adversary function run by pthread
 * 
 * @param arg data passed to the thread function
 * @return void* always return NULL
 */
static void *test_core_cross_core_mds_ecall_is_effective_adversary_thread(void *arg)
{
    int i;

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
static int test_core_cross_core_mds_ecall_is_effective()
{
    int offset, allowance;
    int victim_core, adversary_core;
    pthread_t victim_thread, adversary_thread;
    cpu_set_t victim_cpuset, adversary_cpuset;

    victim_core = 1;
    adversary_core = victim_core + app_sysinfo.nr_cores - 1;

    CPU_ZERO(&victim_cpuset);
    CPU_ZERO(&adversary_cpuset);
    CPU_SET(victim_core, &victim_cpuset);
    CPU_SET(adversary_core, &adversary_cpuset);

    allowance = 16;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;

        ASSERT(!pthread_create(&victim_thread, NULL, test_core_cross_core_mds_ecall_is_effective_victim_thread, NULL));
        ASSERT(!pthread_create(&adversary_thread, NULL, test_core_cross_core_mds_ecall_is_effective_adversary_thread, NULL));

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

Test(mds, cross_core_mds_ecall_is_effective, .disabled = false)
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
    cr_expect(test_core_cross_core_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_cross_core_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_cross_core_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_cross_core_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_cross_core_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_cross_core_mds_ecall_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion

#pragma region verw

TestSuite(verw, .init = construct_app_environment, .fini = desctruct_app_environment);

#pragma region verw_against_same_thread_taa_nosgx_is_effective

/**
 * @brief Test if verw is effective against same_thread_taa_nosgx with a successful rate above 90% for all offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_verw_against_same_thread_taa_nosgx_is_effective()
{
    int i, offset, allowance;

    allowance = 0;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            fill_lfb(app_filling_sequence, &app_filling_buffer);
            clear_lfb(app_clearing_sequence, &app_clearing_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] < 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(verw, verw_against_same_thread_taa_nosgx_is_effective, .disabled = false)
{
    app_attack_spec.major = ATTACK_MAJOR_TAA;
    app_attack_spec.minor = ATTACK_MINOR_STABLE;

    app_filling_buffer.value = 0x1;
    app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&app_filling_buffer);

    app_attaking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
    app_attaking_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&app_attaking_buffer);

    app_clearing_sequence = CLEARING_SEQUENCE_VERW;

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_verw_against_same_thread_taa_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma region verw_against_same_thread_mds_nosgx_is_effective

/**
 * @brief Test if verw is effective against same_thread_mds_nosgx with a successful rate above 90% for all offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_verw_against_same_thread_mds_nosgx_is_effective()
{
    int i, offset, allowance;

    allowance = 32;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            fill_lfb(app_filling_sequence, &app_filling_buffer);
            clear_lfb(app_clearing_sequence, &app_clearing_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] < 10 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(verw, verw_against_same_thread_mds_nosgx_is_effective, .disabled = false)
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

    app_clearing_sequence = CLEARING_SEQUENCE_VERW;

    app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_verw_against_same_thread_mds_nosgx_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion

#pragma endregion