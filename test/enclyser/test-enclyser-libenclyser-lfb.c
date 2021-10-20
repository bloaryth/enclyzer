#include <criterion/criterion.h>

#pragma region /** logical correctness of fill_lfb */

#include "enclyser/libenclyser/lfb.h"

/**
 * @brief suite_lfb::test_fill_lfb
 * 
 */
enclyser_buffer_t filling_buffer;

void test_fill_lfb_log_init()
{
    open_system_file();

    filling_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    malloc_enclyser_buffer(&filling_buffer);

    sleep(2);
}

void test_fill_lfb_log_fini()
{
    free_enclyser_buffer(&filling_buffer);

    close_system_file();
}

Test(suite_lfb, test_fill_lfb_log, .init = test_fill_lfb_log_init, .fini = test_fill_lfb_log_fini, .disabled = false)
{
    int i;
    int filling_sequence;

    /**
     * @brief FILLING_SEQUENCE_GP_LOAD
     * 
     */
    filling_sequence = FILLING_SEQUENCE_GP_LOAD;
    filling_buffer.value = 0x5;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&filling_buffer);
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&filling_buffer);
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i % 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_GP_STORE
     * 
     */
    filling_sequence = FILLING_SEQUENCE_GP_STORE;
    filling_buffer.value = 0x10;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i % 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_NT_LOAD
     * 
     */
    filling_sequence = FILLING_SEQUENCE_NT_LOAD;
    filling_buffer.value = 0x5;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&filling_buffer);
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&filling_buffer);
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i % 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_NT_STORE
     * 
     */
    filling_sequence = FILLING_SEQUENCE_NT_STORE;
    filling_buffer.value = 0x20;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i % 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_STR_LOAD
     * 
     */
    filling_sequence = FILLING_SEQUENCE_STR_LOAD;
    filling_buffer.value = 0x5;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    assign_enclyser_buffer(&filling_buffer);
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    assign_enclyser_buffer(&filling_buffer);
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i % 0x40);
    }

    /**
     * @brief FILLING_SEQUENCE_STR_STORE
     * 
     */
    filling_sequence = FILLING_SEQUENCE_STR_STORE;
    filling_buffer.value = 0x30;
    filling_buffer.order = BUFFER_ORDER_CONSTANT;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value);
    }
    filling_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
    fill_lfb(filling_sequence, &filling_buffer);
    for (i = 0; i < filling_buffer.size; i++)
    {
        cr_expect(filling_buffer.buffer[i] == filling_buffer.value + i % 0x40);
    }
}

#pragma endregion

#pragma region /** architectural correctness of fill_lfb */

#include "enclyser/libenclyser/attack.h"
#include "enclyser/libenclyser/flush_reload.h"
#include "enclyser/libenclyser/lfb.h"

enclyser_attack_t attack_spec;
enclyser_buffer_t filling_buffer;
enclyser_buffer_t attaking_buffer;
enclyser_buffer_t encoding_buffer;
enclyser_buffer_t printing_buffer;

void test_fill_lfb_arch_init()
{
    open_system_file();

    attack_spec = (enclyser_attack_t){
        .major = ATTACK_MAJOR_TAA,
        .minor = ATTACK_MINOR_STABLE,
        .offset = 0};

    filling_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_FILLING_BUFFER_SIZE,
        .value = 0x1,
        .order = BUFFER_ORDER_OFFSET_INLINE,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    attaking_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_ATTACKING_BUFFER_SIZE,
        .value = 0xff, // IMPORTANT: MUST BE NON-ZERO VALUE
        .order = BUFFER_ORDER_CONSTANT,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    encoding_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_ENCODING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    printing_buffer = (enclyser_buffer_t){
        .buffer = NULL,
        .shadow = NULL,
        .size = DEFAULT_PRINTING_BUFFER_SIZE,
        .value = DEFAULT_BUFFER_VALUE,
        .order = DEFAULT_BUFFER_ORDER,
        .mem_type = DEFAULT_BUFFER_MEM_TYPE,
        .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

    malloc_enclyser_buffer(&filling_buffer);
    malloc_enclyser_buffer(&attaking_buffer);
    malloc_enclyser_buffer(&encoding_buffer);
    malloc_enclyser_buffer(&printing_buffer);

    assign_enclyser_buffer(&filling_buffer);
    assign_enclyser_buffer(&attaking_buffer);
}

void test_fill_lfb_arch_fini()
{
    free_enclyser_buffer(&filling_buffer);
    free_enclyser_buffer(&attaking_buffer);
    free_enclyser_buffer(&encoding_buffer);
    free_enclyser_buffer(&printing_buffer);

    close_system_file();
}

Test(suite_lfb, test_fill_lfb_arch, .init = test_fill_lfb_arch_init, .fini = test_fill_lfb_arch_fini, .disabled = false)
{
    int i, j, offset, allowance;
    int filling_sequence_array[6] = {FILLING_SEQUENCE_GP_LOAD, FILLING_SEQUENCE_GP_STORE,
                                     FILLING_SEQUENCE_NT_LOAD, FILLING_SEQUENCE_NT_STORE,
                                     FILLING_SEQUENCE_STR_LOAD, FILLING_SEQUENCE_STR_STORE};

    for (j = 0; j < 6; j++)
    {
        allowance = 32;
        for (offset = 0; offset < 64; offset++)
        {
            attack_spec.offset = offset;
            for (i = 0; i < REPETITION_TIME; i++)
            {
                flush_enclyser_buffer(&encoding_buffer);
                fill_lfb(filling_sequence_array[j], &filling_buffer);
                attack(&attack_spec, &attaking_buffer, &encoding_buffer);
                reload(&encoding_buffer, &printing_buffer);
            }
            cr_expect(printing_buffer.buffer[offset + filling_buffer.value] > 50 || allowance--);
            reset(&printing_buffer);
        }
    }
}

#pragma endregion

// #pragma region /** architectural correctness of clear_lfb */

// /**
//  * @brief suite_lfb::test_clear_lfb
//  * 
//  */
// #include "enclyser/libenclyser/attack.h"
// #include "enclyser/libenclyser/flush_reload.h"
// #include "enclyser/libenclyser/lfb.h"

// enclyser_attack_t attack_spec;
// enclyser_buffer_t filling_buffer;
// enclyser_buffer_t clearing_buffer;
// enclyser_buffer_t attaking_buffer;
// enclyser_buffer_t encoding_buffer;
// enclyser_buffer_t printing_buffer;

// void test_clear_lfb_init()
// {
//     open_system_file();

//     attack_spec = (enclyser_attack_t){
//         .major = ATTACK_MAJOR_TAA,
//         .minor = ATTACK_MINOR_STABLE,
//         .offset = 0};

//     filling_buffer = (enclyser_buffer_t){
//         .buffer = NULL,
//         .shadow = NULL,
//         .size = DEFAULT_FILLING_BUFFER_SIZE,
//         .value = 0x1,
//         .order = BUFFER_ORDER_OFFSET_INLINE,
//         .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//         .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

//     clearing_buffer = (enclyser_buffer_t){
//         .buffer = NULL,
//         .shadow = NULL,
//         .size = DEFAULT_CLEARING_BUFFER_SIZE,
//         .value = DEFAULT_BUFFER_VALUE,
//         .order = DEFAULT_BUFFER_ORDER,
//         .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//         .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

//     attaking_buffer = (enclyser_buffer_t){
//         .buffer = NULL,
//         .shadow = NULL,
//         .size = DEFAULT_ATTACKING_BUFFER_SIZE,
//         .value = 0xff, // IMPORTANT: MUST BE NON-ZERO VALUE
//         .order = BUFFER_ORDER_CONSTANT,
//         .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//         .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

//     encoding_buffer = (enclyser_buffer_t){
//         .buffer = NULL,
//         .shadow = NULL,
//         .size = DEFAULT_ENCODING_BUFFER_SIZE,
//         .value = DEFAULT_BUFFER_VALUE,
//         .order = DEFAULT_BUFFER_ORDER,
//         .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//         .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

//     printing_buffer = (enclyser_buffer_t){
//         .buffer = NULL,
//         .shadow = NULL,
//         .size = DEFAULT_PRINTING_BUFFER_SIZE,
//         .value = DEFAULT_BUFFER_VALUE,
//         .order = DEFAULT_BUFFER_ORDER,
//         .mem_type = DEFAULT_BUFFER_MEM_TYPE,
//         .access_ctrl = DEFAULT_BUFFER_ACCESS_CTRL};

//     malloc_enclyser_buffer(&filling_buffer);
//     malloc_enclyser_buffer(&clearing_buffer);
//     malloc_enclyser_buffer(&attaking_buffer);
//     malloc_enclyser_buffer(&encoding_buffer);
//     malloc_enclyser_buffer(&printing_buffer);

//     assign_enclyser_buffer(&filling_buffer);
//     assign_enclyser_buffer(&attaking_buffer);
// }

// void test_clear_lfb_fini()
// {
//     free_enclyser_buffer(&filling_buffer);
//     free_enclyser_buffer(&clearing_buffer);
//     free_enclyser_buffer(&attaking_buffer);
//     free_enclyser_buffer(&encoding_buffer);
//     free_enclyser_buffer(&printing_buffer);

//     close_system_file();
// }

// Test(suite_lfb, test_clear_lfb, .init = test_clear_lfb_init, .fini = test_clear_lfb_fini, .disabled = false)
// {
//     int i, j, offset, allowance;
//     int filling_sequence_array[6] = {FILLING_SEQUENCE_GP_LOAD, FILLING_SEQUENCE_GP_STORE,
//                                      FILLING_SEQUENCE_NT_LOAD, FILLING_SEQUENCE_NT_STORE,
//                                      FILLING_SEQUENCE_STR_LOAD, FILLING_SEQUENCE_STR_STORE};

//     allowance = 0;
//     for (j = 0; j < 6; j++)
//     {
//         for (offset = 0; offset < 64; offset++)
//         {
//             attack_spec.offset = offset;
//             for (i = 0; i < REPETITION_TIME; i++)
//             {
//                 flush_enclyser_buffer(&encoding_buffer);
//                 fill_lfb(filling_sequence_array[j], &filling_buffer);
//                 clear_lfb(CLEARING_SEQUENCE_VERW, &clearing_buffer);
//                 attack(&attack_spec, &attaking_buffer, &encoding_buffer);
//                 reload(&encoding_buffer, &printing_buffer);
//             }
//             cr_expect(printing_buffer.buffer[offset + filling_buffer.value] < 10 || allowance--);
//             // if (printing_buffer.buffer[offset + filling_buffer.value] >= 10)
//             // {
//             //     INFO("0x%x, 0x%x", filling_sequence_array[j], offset + filling_buffer.value);
//             //     print(&printing_buffer, 0);
//             // }
//             reset(&printing_buffer);
//         }
//     }
// }

// #pragma endregion