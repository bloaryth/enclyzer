#include "enclyser/app/system.h"

#pragma region _system

Test(_system, print_system_info)
{
    open_system_file();

    get_system_info(&app_sysinfo);
    print_system_info(&app_sysinfo);

    close_system_file();
}

#pragma endregion
