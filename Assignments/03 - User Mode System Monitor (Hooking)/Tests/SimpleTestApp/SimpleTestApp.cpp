#include <iostream>
#include <Windows.h>

#define START_TEST(api) std::cout << "Running (" << __FUNCTION__ << ")...\nTesting -> (" #api ") API...";
#define END_TEST() std::cout << "Finsied (" << __FUNCTION__ << ").\n\n";


int testShellExecuteA()
{
    const char* command = "cmd /C sleep 1";  // Command to execute

    START_TEST(ShellExecuteA);
    // Call ShellExecuteA to execute the command
    HINSTANCE result = ShellExecuteA(nullptr, "open", "cmd.exe", command, nullptr, SW_SHOW);

    if ((int)result <= 32)
    {
        // ShellExecuteA returned an error
        MessageBoxA(nullptr, "Failed to execute the command!", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    END_TEST();

    return 0;
}



int main()
{
    int ret = 0;
    std::cout << "Welcome to the testing app!\n";
    
    ret = testShellExecuteA();
    if (ret != 0) return ret;

    return ret;
}
