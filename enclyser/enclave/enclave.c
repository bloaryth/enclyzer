#include "enclyser/enclave/enclave.h"

#include "enclyser/enclave/enclave_t.h"

/* ========== Secrets ========== */

uint8_t __attribute__((aligned(0x1000))) secret[DEFAULT_FILLING_BUFFER_SIZE];

uint8_t *ecall_get_secret(void) { return secret; }

void ecall_assign_secret(buffer_t *buffer) {
  assign_buffer(buffer);
}

/* ========== Gromming & Printing ========== */

/**
 * @brief [ECALL] First fill lfb and then clear lfb by repestive \p
 * filling_sequence and \p clearing_sequence.
 *
 * @param filling_sequence the filling sequence selector
 * @param filling_buffer the buffer that a filling sequence operates on
 * @param clearing_sequence the clearing sequence selector
 * @param clearing_buffer the buffer that a clearing sequence operates on
 * @param faulting_buffer the buffer that raises SIGSEGV if accessed
 */
void ecall_grooming(int filling_sequence, buffer_t *filling_buffer,
                    int clearing_sequence, buffer_t *clearing_buffer,
                    buffer_t *faulting_buffer) {
  fill_lfb(filling_sequence, filling_buffer);
  clear_lfb(clearing_sequence, clearing_buffer);
  // faulting_buffer->buffer[0] = DEFAULT_BUFFER_VALUE;
  (void)faulting_buffer; /** bypass the warning about unsed parameter */
}

void ecall_print_buffer(buffer_t *buffer) {
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      printf("%d ", buffer->buffer[i * 8 + j]);
    }
    printf("\n");
  }
}

/* ========== Spectre ========== */

// unsigned int array1_size = 16;
// uint8_t array1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
// uint8_t array2[256 * 512];

// char *secret2 = "The Magic Words are Squeamish Ossifrage.";
// uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

// uint8_t victim_function_code[256] = {0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48,
// 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x89, 0x55,
//                                      0xe8, 0x48, 0x89, 0x4d, 0xe0, 0x4c,
//                                      0x89, 0x45, 0xd8, 0x8b, 0x45, 0xfc,
//                                      0x48, 0x39, 0x45, 0xd8, 0x73, 0x30,
//                                      0x48, 0x8b, 0x45, 0xe0, 0x0f, 0xb6,
//                                      0x10, 0x48, 0x8b, 0x4d, 0xf0, 0x48,
//                                      0x8b, 0x45, 0xd8, 0x48, 0x01, 0xc8,
//                                      0x0f, 0xb6, 0x00, 0x0f, 0xb6, 0xc0,
//                                      0xc1, 0xe0, 0x09, 0x48, 0x63, 0xc8,
//                                      0x48, 0x8b, 0x45, 0xe8, 0x48, 0x01,
//                                      0xc8, 0x0f, 0xb6, 0x00, 0x21, 0xc2,
//                                      0x48, 0x8b, 0x45, 0xe0, 0x88, 0x10,
//                                      0x90, 0x5d, 0xc3, 0x66, 0x0f, 0x1f,
//                                      0x84, 0x00, 0x00, 0x00, 0x00, 0x00};

// void victim_function(unsigned int array1_size, uint8_t *array1, uint8_t
// *array2, uint8_t *temp, size_t x)
// {
//     if (x < array1_size)
//     {
//         *temp &= array2[array1[x] * 512];
//     }
// }

// void *ecall_get_victim_function_addr()
// {
//     return victim_function;
// }