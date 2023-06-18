#pragma once

/* IMPORTANT: This file is autogenerated from Hooks Generator Tool */
/* Note: If you want to add an include please add it in `hooks_template.cpp` and then run the generator tool */

#include <Windows.h>
#include <processthreadsapi.h>

/* Logging */
#define Log(...) {  \
    logger.write(__VA_ARGS__); \
}

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
                "\"Function\": \"CopyFileA\", "
                "\"Parameters\": "
                "{"
                    "{"
                        "\"lpExistingFileName\": \"{}\", "
                        "\"lpNewFileName\": \"{}\", "
                        "\"bFailIfExists\": \"{}\""
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
    Log("{{ \"Function\": \"CreateFileA\", \"Parameters\": {{ \"lpFileName\": \"{}\", \"dwDesiredAccess\": \"{}\", \"dwShareMode\": \"{}\", \"dwCreationDisposition\": \"{}\", \"dwFlagsAndAttributes\": \"{}\", \"hTemplateFile\": \"{}\"}} }}"
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
     Log(L"{{ \"Function\": \"CreateFileW\", \"Parameters\": {{ \"lpFileName\": \"{}\", \"dwDesiredAccess\": \"{}\", \"dwShareMode\": \"{}\", \"dwCreationDisposition\": \"{}\", \"dwFlagsAndAttributes\": \"{}\", \"hTemplateFile\": \"{}\"}} }}"
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
    Log(L"{"
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
        lpApplicationName,
        lpCommandLine,
        (dwCreationFlags & CREATE_BREAKAWAY_FROM_JOB) ? L"CREATE_BREAKAWAY_FROM_JOB | " : L"",
        (dwCreationFlags & CREATE_DEFAULT_ERROR_MODE) ? L"CREATE_DEFAULT_ERROR_MODE | " : L"",
        (dwCreationFlags & CREATE_NEW_CONSOLE) ? L"CREATE_NEW_CONSOLE | " : L"",
        (dwCreationFlags & CREATE_NEW_PROCESS_GROUP) ? L"CREATE_NEW_PROCESS_GROUP | " : L"",
        (dwCreationFlags & CREATE_NO_WINDOW) ? L"CREATE_NO_WINDOW | " : L"",
        (dwCreationFlags & CREATE_PROTECTED_PROCESS) ? L"CREATE_PROTECTED_PROCESS | " : L"",
        (dwCreationFlags & CREATE_PRESERVE_CODE_AUTHZ_LEVEL) ? L"CREATE_PRESERVE_CODE_AUTHZ_LEVEL | " : L"",
        (dwCreationFlags & CREATE_SECURE_PROCESS) ? L"CREATE_SECURE_PROCESS | " : L"",
        (dwCreationFlags & CREATE_SEPARATE_WOW_VDM) ? L"CREATE_SEPARATE_WOW_VDM | " : L"",
        (dwCreationFlags & CREATE_SHARED_WOW_VDM) ? L"CREATE_SHARED_WOW_VDM | " : L"",
        (dwCreationFlags & CREATE_SUSPENDED) ? L"CREATE_SUSPENDED | " : L"",
        (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) ? L"CREATE_UNICODE_ENVIRONMENT | " : L"",
        (dwCreationFlags & DEBUG_ONLY_THIS_PROCESS) ? L"DEBUG_ONLY_THIS_PROCESS | " : L"",
        (dwCreationFlags & DEBUG_PROCESS) ? L"DEBUG_PROCESS | " : L"",
        (dwCreationFlags & DETACHED_PROCESS) ? L"DETACHED_PROCESS | " : L"",
        (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) ? L"EXTENDED_STARTUPINFO_PRESENT | " : L"",
        (dwCreationFlags & INHERIT_PARENT_AFFINITY) ? L"INHERIT_PARENT_AFFINITY" : L"",
        lpEnvironment,
        lpCurrentDirectory,
        lpProcessInformation->dwProcessId
    );
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
    Log("{{ \"Function\": \"CreateMutexA\", \"Parameters\": {{ \"bInitialOwner\": \"{}\", \"lpName\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"CreateProcessA\", \"Parameters\": {{ \"lpApplicationName\": \"{}\", \"lpCommandLine\": \"{}\", \"bInheritHandles\": \"{}\", \"dwCreationFlags\": \"{}\", \"lpEnvironment\": \"{}\", \"lpCurrentDirectory\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"DeleteFileA\", \"Parameters\": {{ \"lpFileName\": \"{}\"}} }}"
        , lpFileName
    );

    return True_DeleteFileA(lpFileName);
}


static void (WINAPI* True_ExitProcess) (
    UINT  uExitCode
    ) = ExitProcess;

static void WINAPI Hook_ExitProcess(
    UINT  uExitCode
) {
    Log("{{ \"Function\": \"ExitProcess\", \"Parameters\": {{ \"uExitCode\": \"{}\"}} }}"
        , uExitCode
    );

    return True_ExitProcess(uExitCode);
}


static HANDLE(WINAPI* True_FindFirstFileA) (
    LPCSTR              lpFileName,
    LPWIN32_FIND_DATAA  lpFindFileData
    ) = FindFirstFileA;

static HANDLE WINAPI Hook_FindFirstFileA(
    LPCSTR              lpFileName,
    LPWIN32_FIND_DATAA  lpFindFileData
) {
    Log("{{ \"Function\": \"FindFirstFileA\", \"Parameters\": {{ \"lpFileName\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"FindNextFileA\", \"Parameters\": {{ \"hFindFile\": \"{}\"}} }}"
        , hFindFile
    );

    return True_FindNextFileA(hFindFile, lpFindFileData);
}


static LPSTR(WINAPI* True_GetCommandLineA) (
    ) = GetCommandLineA;

static LPSTR WINAPI Hook_GetCommandLineA(
) {
    Log("{{ \"Function\": \"GetCommandLineA\", \"Parameters\": {{}} }}"

    );

    return True_GetCommandLineA();
}


static void (WINAPI* True_GetStartupInfoW) (
    LPSTARTUPINFOW  lpStartupInfo
    ) = GetStartupInfoW;

static void WINAPI Hook_GetStartupInfoW(
    LPSTARTUPINFOW  lpStartupInfo
) {
    Log("{{ \"Function\": \"GetStartupInfoW\", \"Parameters\": {{}} }}"

    );

    return True_GetStartupInfoW(lpStartupInfo);
}


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
    Log("{{ \"Function\": \"OpenMutexA\", \"Parameters\": {{ \"dwDesiredAccess\": \"{}\", \"bInheritHandle\": \"{}\", \"lpName\": \"{}\"}} }}"
        , dwDesiredAccess, bInheritHandle, lpName
    );

    return True_OpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
}


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
    Log("{{ \"Function\": \"OpenProcess\", \"Parameters\": {{ \"dwDesiredAccess\": \"{}\", \"bInheritHandle\": \"{}\", \"dwProcessId\": \"{}\"}} }}"
        , dwDesiredAccess, bInheritHandle, dwProcessId
    );

    return True_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}


static LSTATUS(WINAPI* True_RegCloseKey) (
    HKEY  hKey
    ) = RegCloseKey;

static LSTATUS WINAPI Hook_RegCloseKey(
    HKEY  hKey
) {
    Log("{{ \"Function\": \"RegCloseKey\", \"Parameters\": {{}} }}"

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
    Log("{{ \"Function\": \"RegDeleteKeyA\", \"Parameters\": {{ \"lpSubKey\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"RegDeleteValueA\", \"Parameters\": {{ \"lpValueName\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"RegOpenKeyA\", \"Parameters\": {{ \"lpSubKey\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"RegSaveKeyA\", \"Parameters\": {{ \"lpFile\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"RegSetValueA\", \"Parameters\": {{ \"lpSubKey\": \"{}\", \"dwType\": \"{}\", \"lpData\": \"{}\", \"cbData\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"ReleaseMutex\", \"Parameters\": {{ \"hMutex\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"Sleep\", \"Parameters\": {{ \"dwMilliseconds\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"VirtualAlloc\", \"Parameters\": {{ \"lpAddress\": \"{}\", \"dwSize\": \"{}\", \"flAllocationType\": \"{}\", \"flProtect\": \"{}\"}} }}"
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
    Log("{{ \"Function\": \"VirtualAllocEx\", \"Parameters\": {{ \"hProcess\": \"{}\", \"lpAddress\": \"{}\", \"dwSize\": \"{}\", \"flAllocationType\": \"{}\", \"flProtect\": \"{}\"}} }}"
        , hProcess, lpAddress, dwSize, flAllocationType, flProtect
    );

    return True_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}


/*****************************************************************************/
/*                               DETOUR ATTACH                               */
/*****************************************************************************/

#define HOOK_API(API)     DetourAttach((PVOID *) & True_##API, Hook_##API); \
    Log("\"Registered `" #API "` \"")

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
    HOOK_API(GetCommandLineA);
    HOOK_API(GetStartupInfoW);
    HOOK_API(OpenMutexA);
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
