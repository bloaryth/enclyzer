#include "enclyser/app/system.h"

#pragma region _system

Test(_system, print_system_info)
{
    open_system_file();

    get_system_info(&app_sysinfo);
    print_system_info(&app_sysinfo);

    close_system_file();
}

// #include <sys/mman.h>

// void *function_addr;
// void *shadowed_victim_function;

// Test(_system, get_mmap_address)
// {
//     // void (*shadowed_victim_function)(unsigned int, uint8_t *, uint8_t *, uint8_t *, size_t);
    
//     // ASSERT(ecall_get_victim_function_addr(global_eid, &function_addr) == SGX_SUCCESS);
//     EXPECT(ecall_get_victim_function_addr(global_eid, &function_addr) == SGX_SUCCESS);
//     // int err = erron
//     printf("%p %ld\n", function_addr, ((unsigned long)function_addr >> 31) & 1);

//     // shadowed_victim_function = mmap((void *)((unsigned long)function_addr ^ (1UL << 32)), 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, -1, 0);
//     // printf("%p %ld\n", shadowed_victim_function, ((unsigned long)shadowed_victim_function >> 31) & 1);
// }

#pragma endregion
