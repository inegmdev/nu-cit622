#pragma once

/* IMPORTANT: This file is autogenerated from Hooks Generator Tool */
/* Note: If you want to add an include please add it in `hooks_template.cpp` and then run the generator tool */

#include <Windows.h>
#include <processthreadsapi.h>

/* Logging */
#define Log(...) {  \
    logger.write(__VA_ARGS__); \
}

// String conversions

static LPSTR ConvertLPWSTRToLPSTR(LPWSTR wideString)
{
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, NULL, 0, NULL, NULL);
    LPSTR multiByteString = new char[bufferSize];
    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, multiByteString, bufferSize, NULL, NULL);
    return multiByteString;
}
#define CreateLpstrFromLpwstr(nameWideStr) LPSTR lpstr_##nameWideStr = ConvertLPWSTRToLPSTR(##nameWideStr);
#define GetLpstrFromLpwstr(nameWideStr) lpstr_##nameWideStr
#define ClearLpstrFromLpwstr(nameWideStr) delete[] lpstr_##nameWideStr

static LPCSTR ConvertLPCWSTRToLPCSTR(LPCWSTR wideString)
{
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, NULL, 0, NULL, NULL);
    LPSTR multiByteString = new char[bufferSize];
    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, multiByteString, bufferSize, NULL, NULL);
    return multiByteString;
}
#define CreateLpcstrFromLpcwstr(nameWideStr) LPCSTR lpcstr_##nameWideStr = ConvertLPCWSTRToLPCSTR(##nameWideStr);
#define GetLpcstrFromLpcwstr(nameWideStr) lpcstr_##nameWideStr
#define ClearLpcstrFromLpcwstr(nameWideStr) delete[] lpcstr_##nameWideStr


/*****************************************************************************/
/*                                   HOOKS                                   */
/*****************************************************************************/

/**
 * File related
 */

static BOOL(WINAPI* True_CopyFileA) (
    LPCSTR  lpExistingFileName,
    LPCSTR  lpNewFileName,
    BOOL    bFailIfExists
    ) = CopyFileA;

static BOOL WINAPI Hook_CopyFileA(
    LPCSTR  lpExistingFileName,
    LPCSTR  lpNewFileName,
    BOOL    bFailIfExists
) {
    Log("{"
            "{"
                "'Function': 'CopyFileA', "
                "'Parameters': "
                "{"
                    "{"
                        "'lpExistingFileName': '{}', "
                        "'lpNewFileName': '{}', "
                        "'bFailIfExists': '{}'"
                    "}"
                "}"
            "}"
        "}"
        , lpExistingFileName, lpNewFileName, bFailIfExists
    );

    return True_CopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
}


static HANDLE(WINAPI* True_CreateFileA) (
    LPCSTR                 lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES  lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
    ) = CreateFileA;

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR                 lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES  lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
) {
    Log("{{ 'Function': 'CreateFileA', 'Parameters': {{ 'lpFileName': '{}', 'dwDesiredAccess': '{}', 'dwShareMode': '{}', 'dwCreationDisposition': '{}', 'dwFlagsAndAttributes': '{}', 'hTemplateFile': '{}'}} }}"
        , lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );

    return True_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

static HANDLE(WINAPI* True_CreateFileW) (
    LPCWSTR                lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES  lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
    ) = CreateFileW;

static HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR                lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES  lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
) {
     Log(L"{{ 'Function': 'CreateFileW', 'Parameters': {{ 'lpFileName': '{}', 'dwDesiredAccess': '{}', 'dwShareMode': '{}', 'dwCreationDisposition': '{}', 'dwFlagsAndAttributes': '{}', 'hTemplateFile': '{}'}} }}"
        , lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );
    return True_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


/**
 * processthreadsapi.h -> CreateProcessAsUserW
 */
static BOOL(WINAPI* True_CreateProcessAsUserW) (
    HANDLE                hToken,
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) = CreateProcessAsUserW;

static BOOL WINAPI Hook_CreateProcessAsUserW(
    HANDLE                hToken,
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    CreateLpcstrFromLpcwstr(lpApplicationName);
    CreateLpstrFromLpwstr(lpCommandLine);
    CreateLpcstrFromLpcwstr(lpCurrentDirectory);
   
    Log("{"
            "'Function' : 'CreateProcessAsUserW',"
            "'Parameters' : {"
                "'hToken' : '{}' ,"
                "'lpApplicationName' : '{}' ,"
                "'lpCommandLine' : '{}' ,"
                "'dwCreationFlags' : '{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}' ,"
                "'lpEnvironment' : '{}' ,"
                "'lpCurrentDirectory' : '{}' ,"
                "'lpProcessInformation' : '{"
                    "'dwProcessId' : '{}'"
                "}'"
            "}"
        "}",
        hToken,
        GetLpcstrFromLpcwstr(lpApplicationName),
        GetLpstrFromLpwstr(lpCommandLine),
        (dwCreationFlags & CREATE_BREAKAWAY_FROM_JOB) ? "CREATE_BREAKAWAY_FROM_JOB | " : "",
        (dwCreationFlags & CREATE_DEFAULT_ERROR_MODE) ? "CREATE_DEFAULT_ERROR_MODE | " : "",
        (dwCreationFlags & CREATE_NEW_CONSOLE) ? "CREATE_NEW_CONSOLE | " : "",
        (dwCreationFlags & CREATE_NEW_PROCESS_GROUP) ? "CREATE_NEW_PROCESS_GROUP | " : "",
        (dwCreationFlags & CREATE_NO_WINDOW) ? "CREATE_NO_WINDOW | " : "",
        (dwCreationFlags & CREATE_PROTECTED_PROCESS) ? "CREATE_PROTECTED_PROCESS | " : "",
        (dwCreationFlags & CREATE_PRESERVE_CODE_AUTHZ_LEVEL) ? "CREATE_PRESERVE_CODE_AUTHZ_LEVEL | " : "",
        (dwCreationFlags & CREATE_SECURE_PROCESS) ? "CREATE_SECURE_PROCESS | " : "",
        (dwCreationFlags & CREATE_SEPARATE_WOW_VDM) ? "CREATE_SEPARATE_WOW_VDM | " : "",
        (dwCreationFlags & CREATE_SHARED_WOW_VDM) ? "CREATE_SHARED_WOW_VDM | " : "",
        (dwCreationFlags & CREATE_SUSPENDED) ? "CREATE_SUSPENDED | " : "",
        (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) ? "CREATE_UNICODE_ENVIRONMENT | " : "",
        (dwCreationFlags & DEBUG_ONLY_THIS_PROCESS) ? "DEBUG_ONLY_THIS_PROCESS | " : "",
        (dwCreationFlags & DEBUG_PROCESS) ? "DEBUG_PROCESS | " : "",
        (dwCreationFlags & DETACHED_PROCESS) ? "DETACHED_PROCESS | " : "",
        (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) ? "EXTENDED_STARTUPINFO_PRESENT | " : "",
        (dwCreationFlags & INHERIT_PARENT_AFFINITY) ? "INHERIT_PARENT_AFFINITY" : "",
        lpEnvironment,
        GetLpcstrFromLpcwstr(lpCurrentDirectory),
        lpProcessInformation->dwProcessId
    );

    // Cleanup
    ClearLpcstrFromLpcwstr(lpApplicationName);
    ClearLpstrFromLpwstr(lpCommandLine);
    ClearLpcstrFromLpcwstr(lpCurrentDirectory);

    return True_CreateProcessAsUserW(
        hToken, 
        lpApplicationName, 
        lpCommandLine, 
        lpProcessAttributes, 
        lpThreadAttributes, 
        bInheritHandles, 
        dwCreationFlags, 
        lpEnvironment, 
        lpCurrentDirectory, 
        lpStartupInfo, 
        lpProcessInformation
        );
}
/* ---------------------------------- */

static HANDLE(WINAPI* True_CreateMutexA) (
    LPSECURITY_ATTRIBUTES  lpMutexAttributes,
    BOOL                   bInitialOwner,
    LPCSTR                 lpName
    ) = CreateMutexA;

static HANDLE WINAPI Hook_CreateMutexA(
    LPSECURITY_ATTRIBUTES  lpMutexAttributes,
    BOOL                   bInitialOwner,
    LPCSTR                 lpName
) {
    Log("{{ 'Function': 'CreateMutexA', 'Parameters': {{ 'bInitialOwner': '{}', 'lpName': '{}'}} }}"
        , bInitialOwner, lpName
    );

    return True_CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
}


static BOOL(WINAPI* True_CreateProcessA) (
    LPCSTR                 lpApplicationName,
    LPSTR                  lpCommandLine,
    LPSECURITY_ATTRIBUTES  lpProcessAttributes,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    BOOL                   bInheritHandles,
    DWORD                  dwCreationFlags,
    LPVOID                 lpEnvironment,
    LPCSTR                 lpCurrentDirectory,
    LPSTARTUPINFOA         lpStartupInfo,
    LPPROCESS_INFORMATION  lpProcessInformation
    ) = CreateProcessA;

static BOOL WINAPI Hook_CreateProcessA(
    LPCSTR                 lpApplicationName,
    LPSTR                  lpCommandLine,
    LPSECURITY_ATTRIBUTES  lpProcessAttributes,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    BOOL                   bInheritHandles,
    DWORD                  dwCreationFlags,
    LPVOID                 lpEnvironment,
    LPCSTR                 lpCurrentDirectory,
    LPSTARTUPINFOA         lpStartupInfo,
    LPPROCESS_INFORMATION  lpProcessInformation
) {
    Log("{{ 'Function': 'CreateProcessA', 'Parameters': {{ 'lpApplicationName': '{}', 'lpCommandLine': '{}', 'bInheritHandles': '{}', 'dwCreationFlags': '{}', 'lpEnvironment': '{}', 'lpCurrentDirectory': '{}'}} }}"
        , lpApplicationName, lpCommandLine, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory
    );

    return True_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


static BOOL(WINAPI* True_DeleteFileA) (
    LPCSTR  lpFileName
    ) = DeleteFileA;

static BOOL WINAPI Hook_DeleteFileA(
    LPCSTR  lpFileName
) {
    Log("{{ 'Function': 'DeleteFileA', 'Parameters': {{ 'lpFileName': '{}'}} }}"
        , lpFileName
    );

    return True_DeleteFileA(lpFileName);
}

/**
 * processthreadsapi.h -> ExitProcess
 */
static void (WINAPI* True_ExitProcess) (
    UINT  uExitCode
    ) = ExitProcess;
static void WINAPI Hook_ExitProcess(
    UINT  uExitCode
) {
    Log("{"
            "'Function': 'ExitProcess', "
            "'Parameters': { "
                "'uExitCode': '{}' "
            "}"
        "}"
        , uExitCode
    );

    return True_ExitProcess(uExitCode);
}
/* ----------------------------------------- */

static HANDLE(WINAPI* True_FindFirstFileA) (
    LPCSTR              lpFileName,
    LPWIN32_FIND_DATAA  lpFindFileData
    ) = FindFirstFileA;

static HANDLE WINAPI Hook_FindFirstFileA(
    LPCSTR              lpFileName,
    LPWIN32_FIND_DATAA  lpFindFileData
) {
    Log("{{ 'Function': 'FindFirstFileA', 'Parameters': {{ 'lpFileName': '{}'}} }}"
        , lpFileName
    );

    return True_FindFirstFileA(lpFileName, lpFindFileData);
}


static BOOL(WINAPI* True_FindNextFileA) (
    HANDLE              hFindFile,
    LPWIN32_FIND_DATAA  lpFindFileData
    ) = FindNextFileA;

static BOOL WINAPI Hook_FindNextFileA(
    HANDLE              hFindFile,
    LPWIN32_FIND_DATAA  lpFindFileData
) {
    Log("{{ 'Function': 'FindNextFileA', 'Parameters': {{ 'hFindFile': '{}'}} }}"
        , hFindFile
    );

    return True_FindNextFileA(hFindFile, lpFindFileData);
}


/**
 * processenv.h -> GetCommandLineA
 */
static LPSTR(WINAPI* True_GetCommandLineA) (
    VOID
) = GetCommandLineA;

static LPSTR WINAPI Hook_GetCommandLineA(
) {
    LPSTR commandLine = True_GetCommandLineA();
    Log("{"
            "'Function': 'GetCommandLineA', "
            "'Parameters': 'n/a' ,"
            "'Return' : { "
                "'CommandLine' : '{}'"
            "}"
        "}",
        commandLine
    );
    return commandLine;
}
/* ----------------------------------------- */


/**
 * processenv.h -> GetCommandLineW
 */
static LPWSTR (WINAPI* True_GetCommandLineW) (
    VOID
) = GetCommandLineW;

static LPWSTR  WINAPI Hook_GetCommandLineW(
) {
    LPWSTR commandLine = True_GetCommandLineW();
    Log(L"{"
            "'Function': 'GetCommandLineW', "
            "'Parameters': 'n/a', "
            "'Return': { "
                "'CommandLine' : '{}'"
            "} "
        "}",
        commandLine
    );
    return commandLine;
}
/* ----------------------------------------- */


/**
 * fileapi.h -> GetFullPathNameA 
 */
static DWORD (WINAPI* True_GetFullPathNameA) (
    LPCSTR lpFileName,
    DWORD  nBufferLength,
    LPSTR  lpBuffer,
    LPSTR  *lpFilePart
) = GetFullPathNameA;

static DWORD WINAPI Hook_GetFullPathNameA(
    LPCSTR lpFileName,
    DWORD  nBufferLength,
    LPSTR  lpBuffer,
    LPSTR  *lpFilePart
) {
    Log("{"
            "'Function': 'GetFullPathNameA', "
            "'Parameters': { "
                "'lpFileName' : '{}', "
                "'nBufferLength' : '{}', "
                "'lpBuffer' : '{}' "
            "}"
        "}",
        lpFileName,
        nBufferLength,
        lpBuffer
    );
    return True_GetFullPathNameA(
        lpFileName,
        nBufferLength,
        lpBuffer,
        lpFilePart
    );
}
/* ----------------------------------------- */


/**
 * fileapi.h -> GetFullPathNameW
 */
static DWORD (WINAPI* True_GetFullPathNameW) (
    LPCWSTR lpFileName,
    DWORD   nBufferLength,
    LPWSTR  lpBuffer,
    LPWSTR  *lpFilePart
) = GetFullPathNameW;

static DWORD WINAPI Hook_GetFullPathNameW(
    LPCWSTR lpFileName,
    DWORD   nBufferLength,
    LPWSTR  lpBuffer,
    LPWSTR  *lpFilePart
) {
    Log(L"{"
            "'Function': 'GetFullPathNameW', "
            "'Parameters': { "
                "'lpFileName' : '{}', "
                "'nBufferLength' : '{}', "
                "'lpBuffer' : '{}' "
            "}"
        "}",
        lpFileName,
        nBufferLength,
        lpBuffer
    );
    return True_GetFullPathNameW(
        lpFileName,
        nBufferLength,
        lpBuffer,
        lpFilePart
    );
}
/* ----------------------------------------- */


/**
 * processthreadsapi.h -> GetStartupInfoW
 */
static void (WINAPI* True_GetStartupInfoW) (
    LPSTARTUPINFOW  lpStartupInfo
    ) = GetStartupInfoW;

static void WINAPI Hook_GetStartupInfoW(
    LPSTARTUPINFOW  lpStartupInfo
) {
    LPWSTR lpDesktop = lpStartupInfo->lpDesktop;
    CreateLpstrFromLpwstr(lpDesktop);

    LPWSTR lpTitle = lpStartupInfo->lpTitle;
    CreateLpstrFromLpwstr(lpTitle);



    Log("{"
            "'Function': 'GetStartupInfoW', "
            "'Parameters': { "
                "'lpStartupInfo' : { "
                    "'lpDesktop' : '{}', "
                    "'lpTitle' : '{}', "
                    "'dwX' : '{}', "
                    "'dwY' : '{}', "
                    "'dwXSize' : '{}', "
                    "'dwYSize' : '{}', "
                    "'dwXCountChars' : '{}', "
                    "'dwYCountChars' : '{}', "
                    "'dwFlags' : '{}{}{}{}{}{}{}{}{}{}{}{}{}{}', "
                    "'wShowWindow' : '{}'"
                "}"
            "}"
        "}",
        GetLpstrFromLpwstr(lpDesktop),
        GetLpstrFromLpwstr(lpTitle),
        lpStartupInfo->dwX,
        lpStartupInfo->dwY,
        lpStartupInfo->dwXSize,
        lpStartupInfo->dwYSize,
        lpStartupInfo->dwXCountChars,
        lpStartupInfo->dwYCountChars,
        (lpStartupInfo->dwFlags & STARTF_FORCEONFEEDBACK) ? "STARTF_FORCEONFEEDBACK | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_FORCEOFFFEEDBACK) ? "STARTF_FORCEOFFFEEDBACK | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_PREVENTPINNING) ? "STARTF_PREVENTPINNING | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_RUNFULLSCREEN) ? "STARTF_RUNFULLSCREEN | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_TITLEISAPPID) ? "STARTF_TITLEISAPPID | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_TITLEISLINKNAME) ? "STARTF_TITLEISLINKNAME | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_UNTRUSTEDSOURCE) ? "STARTF_UNTRUSTEDSOURCE | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USECOUNTCHARS) ? "STARTF_USECOUNTCHARS | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USEFILLATTRIBUTE) ? "STARTF_USEFILLATTRIBUTE | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USEHOTKEY) ? "STARTF_USEHOTKEY | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USEPOSITION) ? "STARTF_USEPOSITION | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USESHOWWINDOW) ? "STARTF_USESHOWWINDOW | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USESIZE) ? "STARTF_USESIZE | " : "" ,
        (lpStartupInfo->dwFlags & STARTF_USESTDHANDLES) ? "STARTF_USESTDHANDLES " : "" ,
        lpStartupInfo->wShowWindow
    );

    ClearLpstrFromLpwstr(lpDesktop);
    ClearLpstrFromLpwstr(lpTitle);

    return True_GetStartupInfoW(lpStartupInfo);
}
/* ----------------------------------------- */


static HANDLE(WINAPI* True_OpenMutexA) (
    DWORD  dwDesiredAccess,
    BOOL  bInheritHandle,
    LPCSTR  lpName
    ) = OpenMutexA;

static HANDLE WINAPI Hook_OpenMutexA(
    DWORD  dwDesiredAccess,
    BOOL  bInheritHandle,
    LPCSTR  lpName
) {
    Log("{{ 'Function': 'OpenMutexA', 'Parameters': {{ 'dwDesiredAccess': '{}', 'bInheritHandle': '{}', 'lpName': '{}'}} }}"
        , dwDesiredAccess, bInheritHandle, lpName
    );

    return True_OpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
}

/**
 * processthreadsapi.h -> OpenProcess
 */
static HANDLE(WINAPI* True_OpenProcess) (
    DWORD  dwDesiredAccess,
    BOOL   bInheritHandle,
    DWORD  dwProcessId
) = OpenProcess;

static HANDLE WINAPI Hook_OpenProcess(
    DWORD  dwDesiredAccess,
    BOOL   bInheritHandle,
    DWORD  dwProcessId
) {
    Log("{"
            "'Function': 'OpenProcess', "
            "'Parameters': { "
                "'dwDesiredAccess': '{}{}{}{}{}{}{}{}{}{}{}{}{}{}', "
                "'bInheritHandle': '{}', "
                "'dwProcessId': '{}'"
            "}"
        "}",
        (dwDesiredAccess & PROCESS_ALL_ACCESS) ? "PROCESS_ALL_ACCESS | " : "" ,
        (dwDesiredAccess & PROCESS_CREATE_PROCESS) ? "PROCESS_CREATE_PROCESS | " : "" ,
        (dwDesiredAccess & PROCESS_CREATE_THREAD) ? "PROCESS_CREATE_THREAD | " : "" ,
        (dwDesiredAccess & PROCESS_DUP_HANDLE) ? "PROCESS_DUP_HANDLE | " : "" ,
        (dwDesiredAccess & PROCESS_QUERY_INFORMATION) ? "PROCESS_QUERY_INFORMATION | " : "" ,
        (dwDesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION) ? "PROCESS_QUERY_LIMITED_INFORMATION | " : "" ,
        (dwDesiredAccess & PROCESS_SET_INFORMATION) ? "PROCESS_SET_INFORMATION | " : "" ,
        (dwDesiredAccess & PROCESS_SET_QUOTA) ? "PROCESS_SET_QUOTA | " : "" ,
        (dwDesiredAccess & PROCESS_SUSPEND_RESUME) ? "PROCESS_SUSPEND_RESUME | " : "" ,
        (dwDesiredAccess & PROCESS_TERMINATE) ? "PROCESS_TERMINATE | " : "" ,
        (dwDesiredAccess & PROCESS_VM_OPERATION) ? "PROCESS_VM_OPERATION | " : "" ,
        (dwDesiredAccess & PROCESS_VM_READ) ? "PROCESS_VM_READ | " : "" ,
        (dwDesiredAccess & PROCESS_VM_WRITE) ? "PROCESS_VM_WRITE | " : "" ,
        (dwDesiredAccess & SYNCHRONIZE) ? "SYNCHRONIZE | " : "" , 
        bInheritHandle,
        dwProcessId
    );

    return True_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}
/* ----------------------------------------- */


static LSTATUS(WINAPI* True_RegCloseKey) (
    HKEY  hKey
    ) = RegCloseKey;

static LSTATUS WINAPI Hook_RegCloseKey(
    HKEY  hKey
) {
    Log("{{ 'Function': 'RegCloseKey', 'Parameters': {{}} }}"

    );

    return True_RegCloseKey(hKey);
}


static LSTATUS(WINAPI* True_RegDeleteKeyA) (
    HKEY    hKey,
    LPCSTR  lpSubKey
    ) = RegDeleteKeyA;

static LSTATUS WINAPI Hook_RegDeleteKeyA(
    HKEY    hKey,
    LPCSTR  lpSubKey
) {
    Log("{{ 'Function': 'RegDeleteKeyA', 'Parameters': {{ 'lpSubKey': '{}'}} }}"
        , lpSubKey
    );

    return True_RegDeleteKeyA(hKey, lpSubKey);
}


static LSTATUS(WINAPI* True_RegDeleteValueA) (
    HKEY    hKey,
    LPCSTR  lpValueName
    ) = RegDeleteValueA;

static LSTATUS WINAPI Hook_RegDeleteValueA(
    HKEY    hKey,
    LPCSTR  lpValueName
) {
    Log("{{ 'Function': 'RegDeleteValueA', 'Parameters': {{ 'lpValueName': '{}'}} }}"
        , lpValueName
    );

    return True_RegDeleteValueA(hKey, lpValueName);
}


static LSTATUS(WINAPI* True_RegOpenKeyA) (
    HKEY    hKey,
    LPCSTR  lpSubKey,
    PHKEY   phkResult
    ) = RegOpenKeyA;

static LSTATUS WINAPI Hook_RegOpenKeyA(
    HKEY    hKey,
    LPCSTR  lpSubKey,
    PHKEY   phkResult
) {
    Log("{{ 'Function': 'RegOpenKeyA', 'Parameters': {{ 'lpSubKey': '{}'}} }}"
        , lpSubKey
    );

    return True_RegOpenKeyA(hKey, lpSubKey, phkResult);
}


static LSTATUS(WINAPI* True_RegSaveKeyA) (
    HKEY                         hKey,
    LPCSTR                       lpFile,
    LPSECURITY_ATTRIBUTES  lpSecurityAttributes
    ) = RegSaveKeyA;

static LSTATUS WINAPI Hook_RegSaveKeyA(
    HKEY                         hKey,
    LPCSTR                       lpFile,
    LPSECURITY_ATTRIBUTES  lpSecurityAttributes
) {
    Log("{{ 'Function': 'RegSaveKeyA', 'Parameters': {{ 'lpFile': '{}'}} }}"
        , lpFile
    );

    return True_RegSaveKeyA(hKey, lpFile, lpSecurityAttributes);
}


static LSTATUS(WINAPI* True_RegSetValueA) (
    HKEY    hKey,
    LPCSTR  lpSubKey,
    DWORD   dwType,
    LPCSTR  lpData,
    DWORD   cbData
    ) = RegSetValueA;

static LSTATUS WINAPI Hook_RegSetValueA(
    HKEY    hKey,
    LPCSTR  lpSubKey,
    DWORD   dwType,
    LPCSTR  lpData,
    DWORD   cbData
) {
    Log("{{ 'Function': 'RegSetValueA', 'Parameters': {{ 'lpSubKey': '{}', 'dwType': '{}', 'lpData': '{}', 'cbData': '{}'}} }}"
        , lpSubKey, dwType, lpData, cbData
    );

    return True_RegSetValueA(hKey, lpSubKey, dwType, lpData, cbData);
}


static BOOL(WINAPI* True_ReleaseMutex) (
    HANDLE  hMutex
    ) = ReleaseMutex;

static BOOL WINAPI Hook_ReleaseMutex(
    HANDLE  hMutex
) {
    Log("{{ 'Function': 'ReleaseMutex', 'Parameters': {{ 'hMutex': '{}'}} }}"
        , hMutex
    );

    return True_ReleaseMutex(hMutex);
}

/**
 * shellapi.h -> ShellExecuteA
 */
static HINSTANCE(WINAPI* True_ShellExecuteA) (
    HWND    hwnd,
    LPCSTR  lpOperation,
    LPCSTR  lpFile,
    LPCSTR  lpParameters,
    LPCSTR  lpDirectory,
    INT     nShowCmd
    ) = ShellExecuteA;

static HINSTANCE WINAPI Hook_ShellExecuteA(
    HWND    hwnd,
    LPCSTR  lpOperation,
    LPCSTR  lpFile,
    LPCSTR  lpParameters,
    LPCSTR  lpDirectory,
    INT     nShowCmd
) {
    Log("{"
            "'Function': 'ShellExecuteA', "
            "'Parameters': { "
                "'lpOperation': '{}', "
                "'lpFile': '{}', "
                "'lpParameters': '{}', "
                "'lpDirectory': '{}', "
                "'nShowCmd': '{}'"
            "}"
        "}",
        lpOperation,
        lpFile,
        lpParameters,
        lpDirectory,
        nShowCmd
    );

    return True_ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}
/*-------------------------------------*/


/**
 * shellapi.h -> ShellExecuteW
 */
static HINSTANCE (WINAPI* True_ShellExecuteW) (
    HWND    hwnd,
    LPCWSTR lpOperation,
    LPCWSTR lpFile,
    LPCWSTR lpParameters,
    LPCWSTR lpDirectory,
    INT     nShowCmd
) = ShellExecuteW;

static HINSTANCE WINAPI Hook_ShellExecuteW(
    HWND    hwnd,
    LPCWSTR lpOperation,
    LPCWSTR lpFile,
    LPCWSTR lpParameters,
    LPCWSTR lpDirectory,
    INT     nShowCmd
) {
    Log(L"{"
            "'Function': 'ShellExecuteW', "
            "'Parameters': "
            "{"
                "'lpOperation' : '{}' ,"
                "'lpFile' : '{}' ,"
                "'lpParameters' : '{}' ,"
                "'lpDirectory' : '{}' ,"
                "'nShowCmd' : '{}' ,"
            "}"
        "}",
        lpOperation,
        lpFile,
        lpParameters,
        lpDirectory,
        nShowCmd
    );

    return True_ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}
/*-------------------------------------*/

static void (WINAPI* True_Sleep) (
    DWORD  dwMilliseconds
    ) = Sleep;

static void WINAPI Hook_Sleep(
    DWORD  dwMilliseconds
) {
    Log("{{ 'Function': 'Sleep', 'Parameters': {{ 'dwMilliseconds': '{}'}} }}"
        , dwMilliseconds
    );

    return True_Sleep(dwMilliseconds);
}


static LPVOID(WINAPI* True_VirtualAlloc) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
    ) = VirtualAlloc;

static LPVOID WINAPI Hook_VirtualAlloc(
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
) {
    Log("{{ 'Function': 'VirtualAlloc', 'Parameters': {{ 'lpAddress': '{}', 'dwSize': '{}', 'flAllocationType': '{}', 'flProtect': '{}'}} }}"
        , lpAddress, dwSize, flAllocationType, flProtect
    );

    return True_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}


static LPVOID(WINAPI* True_VirtualAllocEx) (
    HANDLE  hProcess,
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
    ) = VirtualAllocEx;

static LPVOID WINAPI Hook_VirtualAllocEx(
    HANDLE  hProcess,
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
) {
    Log("{{ 'Function': 'VirtualAllocEx', 'Parameters': {{ 'hProcess': '{}', 'lpAddress': '{}', 'dwSize': '{}', 'flAllocationType': '{}', 'flProtect': '{}'}} }}"
        , hProcess, lpAddress, dwSize, flAllocationType, flProtect
    );

    return True_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}


/*****************************************************************************/
/*                               DETOUR ATTACH                               */
/*****************************************************************************/

#define HOOK_API(API)     DetourAttach((PVOID *) & True_##API, Hook_##API); \
    Log("'Registered `" #API "` '")

void DetourAttach_AllHooks() {

    HOOK_API(CopyFileA);
    HOOK_API(CreateFileA);
    HOOK_API(CreateFileW);
    HOOK_API(CreateProcessAsUserW);
    HOOK_API(CreateMutexA);
    HOOK_API(CreateProcessA);
    HOOK_API(DeleteFileA);
    HOOK_API(ExitProcess);
    HOOK_API(FindFirstFileA);
    HOOK_API(FindNextFileA);
    // processenv.h -> GetCommandLineA
    // HOOK_API(GetCommandLineA);
    // processenv.h -> GetCommandLineW
    // HOOK_API(GetCommandLineW);
    // fileapi.h -> GetFullPathNameA 
    // HOOK_API(GetFullPathNameA);
    // fileapi.h -> GetFullPathNameW
    // HOOK_API(GetFullPathNameW);
    
    // processthreadsapi.h -> GetStartupInfoW
    HOOK_API(GetStartupInfoW);
    
    HOOK_API(OpenMutexA);

    // processthreadsapi.h -> OpenProcess
    HOOK_API(OpenProcess);

    HOOK_API(RegCloseKey);
    HOOK_API(RegDeleteKeyA);
    HOOK_API(RegDeleteValueA);
    HOOK_API(RegOpenKeyA);
    HOOK_API(RegSaveKeyA);
    HOOK_API(RegSetValueA);
    HOOK_API(ReleaseMutex);
    // shellapi.h -> ShellExecuteA
    HOOK_API(ShellExecuteA);
    // shellapi.h -> ShellExecuteW
    HOOK_API(ShellExecuteW);
    HOOK_API(Sleep);
    HOOK_API(VirtualAlloc);
    HOOK_API(VirtualAllocEx);
}
