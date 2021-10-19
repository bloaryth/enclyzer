#include <criterion/criterion.h>
#include "enclyser/libenclyser/attack.h"

#pragma region /** architectural correctness of attack */

#include "enclyser/libenclyser/attack.h"
#include "enclyser/libenclyser/flush_reload.h"
#include "enclyser/libenclyser/lfb.h"

enclyser_attack_t attack_spec;
enclyser_buffer_t filling_buffer;
enclyser_buffer_t attaking_buffer;
enclyser_buffer_t encoding_buffer;
enclyser_buffer_t printing_buffer;

void test_attack_arch_init()
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

void test_attack_arch_fini()
{
    free_enclyser_buffer(&filling_buffer);
    free_enclyser_buffer(&attaking_buffer);
    free_enclyser_buffer(&encoding_buffer);
    free_enclyser_buffer(&printing_buffer);

    close_system_file();
}

Test(suite_attack, test_attack_arch, .init = test_attack_arch_init, .fini = test_attack_arch_fini, .disabled = false)
{
    int i, offset, allowance;

    /** ATTACK_MAJOR_MDS */
    attack_spec.major = ATTACK_MAJOR_MDS;
    attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
    cripple_enclyser_buffer(&attaking_buffer);
    allowance = 32;
    for (offset = 0; offset < 64; offset++)
    {
        attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            fill_lfb(FILLING_SEQUENCE_STR_STORE, &filling_buffer);
            flush_enclyser_buffer(&encoding_buffer);
            attack(&attack_spec, &attaking_buffer, &encoding_buffer);
            reload(&encoding_buffer, &printing_buffer);
        }
        cr_expect(printing_buffer.buffer[offset + filling_buffer.value] > 50 || allowance--);
        if (!(printing_buffer.buffer[offset + filling_buffer.value] > 50 || allowance)){
            print(&printing_buffer, 0);
        }
        reset(&printing_buffer);
    }
    attaking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_PRESENT;
    cripple_enclyser_buffer(&attaking_buffer);

    /** ATTACK_MAJOR_TAA */
    attack_spec.major = ATTACK_MAJOR_TAA;
    allowance = 32;
    for (offset = 0; offset < 64; offset++)
    {
        attack_spec.offset = offset;
        for (i = 0; i < REPETITION_TIME; i++)
        {
            fill_lfb(FILLING_SEQUENCE_STR_STORE, &filling_buffer);
            flush_enclyser_buffer(&encoding_buffer);
            attack(&attack_spec, &attaking_buffer, &encoding_buffer);
            reload(&encoding_buffer, &printing_buffer);
        }
        cr_expect(printing_buffer.buffer[offset + filling_buffer.value] > 32 || allowance--);
        reset(&printing_buffer);
    }
}