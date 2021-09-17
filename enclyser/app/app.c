#pragma region shared

#include <criterion/criterion.h>

#include "enclyser/app/app.h"
#include "enclyser/app/enclave_u.h"
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

    malloc_enclyser_buffer(&app_filling_buffer);
    malloc_enclyser_buffer(&app_clearing_buffer);
    malloc_enclyser_buffer(&app_faulting_buffer);

    malloc_enclyser_buffer(&app_attaking_buffer);
    malloc_enclyser_buffer(&app_encoding_buffer);
    malloc_enclyser_buffer(&app_printing_buffer);

    ASSERT(signal(SIGSEGV, sigsegv_handler) != SIG_ERR);

    sleep(2); // IMPORTANT! FIXME robust against signals */
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

/**
 * @brief Print the system information that is related to the project.
 * 
 */
static void print_system_info()
{
    uint32_t eax, ebx, ecx, edx;

    eax = 7;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    cr_log_info("HLE: %d", (ebx >> 4) & 0x1);
    cr_log_info("RTM: %d", (ebx >> 11) & 0x1);
    cr_log_info("RTM_ALWAYS_ABORT: %d", (edx >> 11) & 0x1);
    cr_log_info("TSX_FORCE_ABORT: %d", (edx >> 13) & 0x1);

    if ((edx >> 13) & 0x1) /** TSX_FORCE_ABORT MSR */
    {
        uint32_t eax, ecx, edx;
        ecx = 0x10f;

        native_rdmsr(&eax, &ecx, &edx);

        cr_log_info("TSX_FORCE_ABORT MSR");
        cr_log_info("    RTM_FORCE_ABORT: %d", (eax >> 0) & 0x1);
        cr_log_info("    TSX_CPUID_CLEAR: %d", (eax >> 1) & 0x1);
        cr_log_info("    SDV_ENABLE_RTM: %d", (eax >> 2) & 0x1);
    }

    cr_log_info("SRBDS_CTRL: %d", (edx >> 9) & 0x1);
    cr_log_info("MD_CLEAR: %d", (edx >> 10) & 0x1);
    cr_log_info("IBRS & IBPB: %d", (edx >> 26) & 0x1);
    cr_log_info("STIBP: %d", (edx >> 27) & 0x1);
    cr_log_info("L1D_FLUSH: %d", (edx >> 28) & 0x1);
    cr_log_info("IA32_ARCH_CAPABILITIES: %d", (edx >> 29) & 0x1);
    cr_log_info("SSBD: %d", (edx >> 31) & 0x1);

    if ((edx >> 29) & 0x1) /** IA32_ARCH_CAPABILITIES MSR */
    {
        uint32_t eax, ecx, edx;
        ecx = 0x10a;

        native_rdmsr(&eax, &ecx, &edx);

        cr_log_info("IA32_ARCH_CAPABILITIES MSR");
        cr_log_info("    RDCL_NO: %d", (eax >> 0) & 0x1);
        cr_log_info("    IBRS_ALL: %d", (eax >> 1) & 0x1);
        cr_log_info("    RSBA: %d", (eax >> 2) & 0x1);
        cr_log_info("    SKIP_L1DFL_VMENTRY: %d", (eax >> 3) & 0x1);
        cr_log_info("    SSB_NO: %d", (eax >> 4) & 0x1);
        cr_log_info("    MDS_NO: %d", (eax >> 5) & 0x1);
        cr_log_info("    IF_PSCHANGE_MC_NO: %d", (eax >> 6) & 0x1);
        cr_log_info("    TSX_CTRL: %d", (eax >> 7) & 0x1);
        cr_log_info("    TAA_NO: %d", (eax >> 8) & 0x1);

        if ((eax >> 7) & 0x1) /** IA32_TSX_CTRL MSR */
        {
            uint32_t eax, ecx, edx;
            ecx = 0x10a;

            native_rdmsr(&eax, &ecx, &edx);

            cr_log_info("IA32_TSX_CTRL MSR");
            cr_log_info("    RTM_DISABLE: %d", (eax >> 0) & 0x1);
            cr_log_info("    TSX_CPUID_CLEAR: %d", (eax >> 1) & 0x1);
        }
    }
    if (((edx >> 26) & 0x1) | ((edx >> 27) & 0x1) | ((edx >> 31) & 0x1)) /** IA32_SPEC_CTRL MSR */
    {
        uint32_t eax, ecx, edx;
        ecx = 0x48;

        native_rdmsr(&eax, &ecx, &edx);

        cr_log_info("IA32_SPEC_CTRL MSR");
        cr_log_info("    IBRS: %d", (eax >> 0) & 0x1);
        cr_log_info("    STIBP: %d", (eax >> 1) & 0x1);
        cr_log_info("    SSBD: %d", (eax >> 2) & 0x1);
    }

    // if ((edx >> 26) & 0x1)  /** IA32_PRED_CMD MSR */
    // {
    //     uint32_t eax, ecx, edx;
    //     ecx = 0x49;

    //     native_rdmsr(&eax, &ecx, &edx);

    //     cr_log_info("IA32_PRED_CMD MSR");
    //     if ((edx >> 26) & 0x1)
    //         cr_log_info("    IBPB: %d", (eax >> 0) & 0x1);
    // }

    if ((edx >> 9) & 0x1) /** IA32_MCU_OPT_CTRL MSR */
    {
        uint32_t eax, ecx, edx;
        ecx = 0x123;

        native_rdmsr(&eax, &ecx, &edx);

        cr_log_info("IA32_MCU_OPT_CTRL MSR");
        if ((edx >> 9) & 0x1)
            cr_log_info("    RNGDS_MITG_DIS: %d", (eax >> 0) & 0x1);
    }

    eax = 1;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    cr_log_info("SSE2: %d", (edx >> 26) & 0x1);
    cr_log_info("AVX: %d", (ecx >> 28) & 0x1);

    eax = 7;
    ecx = 0;

    native_cpuid(&eax, &ebx, &ecx, &edx);

    cr_log_info("AVX512DQ: %d", (ebx >> 17) & 0x1);
}

Test(_system, print_system_info, .disabled = true)
{
    open_system_file();

    execute_command("cat /proc/cpuinfo | grep 'model name' -m 1 | sed 's/model name\t: //'");
    cr_log_info("cpu model name: %s", command_output);
    execute_command("cat /proc/cpuinfo | grep microcode -m 1 | awk '{print $3;}'");
    cr_log_info("microcode version: %s", command_output);

    execute_command("grep -c ^processor /proc/cpuinfo");
    cr_log_info("number of logical cores: %s", command_output);
    execute_command("grep 'cpu cores' /proc/cpuinfo -m 1 | awk '{print $4}'");
    cr_log_info("number of physical cores: %s", command_output);

    print_system_info();

    close_system_file();
}

#pragma endregion

#pragma region taa

TestSuite(taa, .init = construct_app_environment, .fini = desctruct_app_environment, .disabled = true);

/**
 * @brief Test if taa_same_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_same_thread_is_effective()
{
    int i, offset, allowance;

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
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] > 75 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, taa_same_thread_is_effective, .disabled = true)
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
    cr_expect(test_core_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if taa_cross_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_cross_thread_is_effective()
{

}

Test(taa, taa_cross_thread_is_effective, .disabled = true)
{

}

/**
 * @brief Test if taa_cross_core is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_cross_core_is_effective()
{

}

Test(taa, taa_cross_core_is_effective, .disabled = true)
{

}

/**
 * @brief Test if taa_eexit_same_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_eexit_same_thread_is_effective()
{
    int i, offset, allowance;

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
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] > 75 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, taa_eexit_same_thread_is_effective, .disabled = true)
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
    cr_expect(test_core_taa_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_taa_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_taa_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_taa_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_taa_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_taa_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if taa_eexit_cross_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_eexit_cross_thread_is_effective()
{

}

Test(taa, taa_eexit_cross_thread_is_effective, .disabled = true)
{

}

/**
 * @brief Test if taa_eexit_cross_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_eexit_cross_thread_is_effective()
{

}

Test(taa, taa_eexit_cross_thread_is_effective, .disabled = true)
{

}

/**
 * @brief Test if taa_eexit_cross_core is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_eexit_cross_core_is_effective()
{

}

Test(taa, taa_eexit_cross_core_is_effective, .disabled = true)
{

}

/**
 * @brief Test if taa_aex_same_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_aex_same_thread_is_effective()
{
    int i, offset, allowance;

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
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] > 75 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(taa, taa_aex_same_thread_is_effective, .disabled = true)
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
    cr_expect(test_core_taa_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_taa_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_taa_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_taa_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_taa_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_taa_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if taa_aex_cross_thread is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_aex_cross_thread_is_effective()
{

}

Test(taa, taa_aex_cross_thread_is_effective, .disabled = true)
{

}

/**
 * @brief Test if taa_aex_cross_core is effective with a successful rate above 75% for at least 75% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_taa_aex_cross_core_is_effective()
{

}

Test(taa, taa_aex_cross_core_is_effective, .disabled = true)
{

}

#pragma endregion

#pragma region msd

TestSuite(mds, .init = construct_app_environment, .fini = desctruct_app_environment, .disabled = true);

/**
 * @brief Test if mds_same_thread is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_same_thread_is_effective()
{
    int i, offset, allowance;

    allowance = 32;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            fill_lfb(FILLING_SEQUENCE_STR_STORE, &app_filling_buffer);
            attack(&app_attack_spec, &app_attaking_buffer, &app_encoding_buffer);
            reload(&app_encoding_buffer, &app_printing_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] > 50 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, mds_same_thread_is_effective)
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
    cr_expect(test_core_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if mds_corss_thread is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_corss_thread_is_effective()
{

}

Test(mds, mds_corss_thread_is_effective)
{

}

/**
 * @brief Test if mds_corss_core is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_corss_core_is_effective()
{

}

Test(mds, mds_corss_core_is_effective)
{

}

/**
 * @brief Test if mds_eexit_same_thread is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_eexit_same_thread_is_effective()
{
    int i, offset, allowance;

    allowance = 32;
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
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] > 50 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, mds_eexit_same_thread_is_effective, .disabled = true)
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
    cr_expect(test_core_mds_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_mds_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_mds_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_mds_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_mds_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_mds_eexit_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if mds_eexit_corss_thread is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_eexit_corss_thread_is_effective()
{

}

Test(mds, mds_eexit_corss_thread_is_effective)
{

}

/**
 * @brief Test if mds_eexit_corss_core is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_eexit_corss_core_is_effective()
{

}

Test(mds, mds_eexit_corss_core_is_effective)
{

}

/**
 * @brief Test if mds_aex_same_thread is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_aex_same_thread_is_effective()
{
    int i, offset, allowance;

    allowance = 32;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            ASSERT(!mprotect(app_faulting_buffer.buffer, app_faulting_buffer.size, PROT_NONE));
            flush_enclyser_buffer(&app_encoding_buffer);
            ecall_grooming(global_eid, app_filling_sequence, &app_filling_buffer, app_clearing_sequence, &app_clearing_buffer, &app_faulting_buffer);
        }
        if (!(app_printing_buffer.buffer[offset + app_filling_buffer.value] > 50 || allowance--))
        {
            return -1;
        }
        reset(&app_printing_buffer);
    }
    return 0;
}

Test(mds, mds_aex_same_thread_is_effective, .disabled = true)
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
    cr_expect(test_core_mds_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_mds_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_mds_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_mds_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_mds_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_mds_aex_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if mds_aex_corss_thread is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_aex_corss_thread_is_effective()
{

}

Test(mds, mds_aex_corss_thread_is_effective)
{

}

/**
 * @brief Test if mds_aex_corss_core is effective with a successful rate above 50% for at least 50% offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_mds_aex_corss_core_is_effective()
{

}

Test(mds, mds_aex_corss_core_is_effective)
{

}

#pragma endregion

#pragma region verw

TestSuite(verw, .init = construct_app_environment, .fini = desctruct_app_environment, .disabled = true);

/**
 * @brief Test if verw is effective against taa_same_thread with a successful rate above 90% for all offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_verw_against_taa_same_thread_is_effective()
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

Test(verw, verw_against_taa_same_thread_is_effective, .disabled = true)
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
    cr_expect(test_core_verw_against_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_verw_against_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_verw_against_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_verw_against_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_verw_against_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_verw_against_taa_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

/**
 * @brief Test if verw is effective against mds_same_thread with a successful rate above 90% for all offset.
 * 
 * @return int 0 if passed, -1 if failed.
 */
static int test_core_verw_against_mds_same_thread_is_effective()
{
    int i, offset, allowance;

    allowance = 32;
    for (offset = 0; offset < 64; offset++)
    {
        app_attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            flush_enclyser_buffer(&app_encoding_buffer);
            fill_lfb(FILLING_SEQUENCE_STR_STORE, &app_filling_buffer);
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

Test(verw, verw_against_mds_same_thread_is_effective)
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
    cr_expect(test_core_verw_against_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
    cr_expect(test_core_verw_against_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_GP_STORE");

    app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    cr_expect(test_core_verw_against_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
    cr_expect(test_core_verw_against_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_NT_STORE");

    app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    cr_expect(test_core_verw_against_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_LOAD");

    app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
    cr_expect(test_core_verw_against_mds_same_thread_is_effective() == 0, "FILLING_SEQUENCE_STR_STORE");
}

#pragma endregion