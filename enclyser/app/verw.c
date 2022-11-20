#include "enclyser/app/verw.h"

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
//         attack_spec.offset = offset;
//         for (i = 0; i < REPETITION_TIME; i++)
//         {
//             flush_buffer(&app_encoding_buffer);
//             fill_lfb(app_filling_sequence, &app_filling_buffer);
//             clear_lfb(app_clearing_sequence, &app_clearing_buffer);
//             attack(&attack_spec, &app_attacking_buffer, &app_encoding_buffer);
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
//     attack_spec.major = ATTACK_MAJOR_TAA;
//     attack_spec.minor = ATTACK_MINOR_STABLE;

//     app_filling_buffer.value = 0x1;
//     app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
//     assign_buffer(&app_filling_buffer);

//     app_attacking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
//     app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
//     assign_buffer(&app_attacking_buffer);

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
//         attack_spec.offset = offset;
//         for (i = 0; i < REPETITION_TIME; i++)
//         {
//             flush_buffer(&app_encoding_buffer);
//             fill_lfb(app_filling_sequence, &app_filling_buffer);
//             clear_lfb(app_clearing_sequence, &app_clearing_buffer);
//             attack(&attack_spec, &app_attacking_buffer, &app_encoding_buffer);
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
//     attack_spec.major = ATTACK_MAJOR_MDS;
//     attack_spec.minor = ATTACK_MINOR_STABLE;

//     app_filling_buffer.value = 0x1;
//     app_filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
//     assign_buffer(&app_filling_buffer);

//     app_attacking_buffer.value = 0xff; // IMPORTANT: MUST BE NON-ZERO VALUE
//     app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
//     app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
//     assign_buffer(&app_attacking_buffer);
//     cripple_buffer(&app_attacking_buffer);

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