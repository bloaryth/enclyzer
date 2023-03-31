#include "enclyzer/enclave/enclave.h"

#include "enclyzer/enclave/enclave_t.h"

/* ========== Secrets ========== */

uint8_t __attribute__((aligned(0x1000))) secret[DEFAULT_FILLING_BUFFER_SIZE];

uint8_t *ecall_get_secret(void) { return secret; }

void ecall_assign_secret(buffer_t *buffer) {
  assign_buffer(buffer);
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