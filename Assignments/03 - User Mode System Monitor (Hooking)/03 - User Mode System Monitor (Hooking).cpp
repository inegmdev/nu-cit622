#include <iostream>
#include <Windows.h>
#include <string>
#include <codecvt>

#include "Detoury.h"
#include "detours.h"

static bool IsFileValid(const wchar_t* filePath) {
    DWORD fileAttributes = GetFileAttributes(filePath);
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

static bool IsFile32Bit(const wchar_t* filePath, bool* is32Bit) {
    HANDLE fileHandle = CreateFile(
        filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        ERR_LN("Failed to open the file for reading.");
        return 0; // ERROR 
    }
    
    // Reading the DOS file header
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
        ERR_LN("Failed to read the DOS header.");
        CloseHandle(fileHandle);
        return 0; // ERROR
    }

    if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS ntHeaders;
        SetFilePointer(fileHandle, dosHeader.e_lfanew, NULL, FILE_BEGIN);
        if (ReadFile(fileHandle, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead, NULL)) {
            if (ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                DBG_LN("ntHeaders.FileHeader.Machine: " << std::hex <<  " 0x" << ntHeaders.FileHeader.Machine);
                DBG_LN("ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386: " << (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386));
                *is32Bit = (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
            }
            else {
                ERR_LN("Not valid PE file.");
                return 0;
            }
        }
        else {
            ERR_LN("Failed to read the NT header.");
            return 0;
        }
    }
    else {
        ERR_LN("Not valid PE file.");
        return 0;
    }
    return 1;
}

#define WCHAR_ARG(str,argIndex) std::wstring wide##str = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(argv[argIndex]); \
                                const wchar_t* ##str = wide##str.c_str()

static std::string WideCharToMultiByteString(const wchar_t* wideString)
{
    int requiredLength = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
    if (requiredLength == 0)
    {
        throw std::runtime_error("Failed to convert the string from wide-char to multi-byte.");
    }

    std::string convertedString(requiredLength, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &convertedString[0], requiredLength, nullptr, nullptr);

    return convertedString;
}

static int checkInputs(const wchar_t* targetExecPath, const wchar_t* dllPath) {
    if (!IsFileValid(targetExecPath)) {
        ERR("Invalid executable: (");
        std::wcerr << targetExecPath;
        std::cerr << ")." << std::endl;
        return 1;
    }
    if (!IsFileValid(dllPath)) {
        ERR("Invalid DLL: (");
        std::wcerr << dllPath;
        std::cerr << ")." << std::endl;
        return 1;
    }
    bool isExec32Bit = 0, isDll32Bit = 0;

    if (IsFile32Bit(targetExecPath, &isExec32Bit)) {
        if (isExec32Bit == 1) {
            INFO_LN("Executable is 32-Bit.");
        }
        else {
            INFO_LN("Executable is 64-Bit.");
        }

    }
    else {
        ERR("Failed to read the executable (");
        std::wcerr << targetExecPath;
        std::cerr << ")." << std::endl;
        return 1;
    }

    if (IsFile32Bit(dllPath, &isDll32Bit)) {
        if (isExec32Bit == 1) {
            INFO_LN("DLL is 32-Bit.");
        }
        else {
            INFO_LN("DLL is 64-Bit.");
        }

    }
    else {
        ERR("Failed to read the DLL (");
        std::wcerr << dllPath;
        std::cerr << ")." << std::endl;
        return 1;
    }

    // Check if both DLL and Executable are the same architecture
    if (isExec32Bit != isDll32Bit) {
        ERR_LN("Can not inject DLL "
            << ((isDll32Bit) ? "32-Bit" : "64-Bit")
            << " in executable "
            << ((isExec32Bit) ? "32-Bit" : "64-Bit"));
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    // Check the inputs
    if (argc != 3) {
        ERR_LN("Invalid call for the program.");
        INFO_LN("Usage: " << argv[0] << " <target_executable> <dll_path>");
        return 1;
    }

    WCHAR_ARG(targetExecPath, 1);
    WCHAR_ARG(dllPath, 2);

    // Check the inputs
    if (checkInputs(targetExecPath, dllPath) == 1) {
        return 1;
    }

    // Prepare for Detours
    /*
BOOL WINAPI DetourCreateProcessWithDllsW(_In_opt_ LPCWSTR lpApplicationName,
                                         _Inout_opt_ LPWSTR lpCommandLine,
                                         _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                         _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                         _In_ BOOL bInheritHandles,
                                         _In_ DWORD dwCreationFlags,
                                         _In_opt_ LPVOID lpEnvironment,
                                         _In_opt_ LPCWSTR lpCurrentDirectory,
                                         _In_ LPSTARTUPINFOW lpStartupInfo,
                                         _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                         _In_ DWORD nDlls,
                                         _In_reads_(nDlls) LPCSTR *rlpDlls,
                                         _In_opt_ PDETOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW);
    */
    STARTUPINFO startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };

    std::string dllPathStr = WideCharToMultiByteString(dllPath);
    LPCSTR lpcstrDllPath = dllPathStr.c_str();

    bool bRet = DetourCreateProcessWithDll(
        targetExecPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, // Creation flags
        NULL, // Environment
        NULL, // Current directory
        &startupInfo, // Startup information 
        &processInfo, // Process information
        lpcstrDllPath,
        NULL);

    if (bRet)
    {
        INFO_LN("Process created and DLL injected successfully.");
        INFO_LN("PID:(" << processInfo.dwProcessId << ")");

        // Resume the suspended process
        INFO_LN("Resume the process after injection.");
        ResumeThread(processInfo.hThread);
        
        INFO_LN("Wait for the process to terminate, you can now interact with the process or wait till it's finished.");
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        INFO_LN("Process terminated.");

        // Clean up the process handles
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
    else
    {
        DWORD errNum = GetLastError();
        ERR_LN("Failed to create process. System error : (" << errNum << ").");
        if (errNum == ERROR_ELEVATION_REQUIRED) {
            INFO_LN("Process requires adminstrator privileges to run.");
        }
    }
}
