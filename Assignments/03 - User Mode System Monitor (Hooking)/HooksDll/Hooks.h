#pragma once

/* IMPORTANT: This file is autogenerated from Hooks Generator Tool */
/* Note: If you want to add an include please add it in `hooks_template.cpp` and then run the generator tool */

#include <Windows.h>

/* Logging */
#define Log(...) {  \
    logger.write(__VA_ARGS__); \
}

/*****************************************************************************/
/*                                   HOOKS                                   */
/*****************************************************************************/



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
    Log("{{ \"HookedFunction\": \"CopyFileA\", \"Parameters\": {{ \"lpExistingFileName\": \"{}\", \"lpNewFileName\": \"{}\", \"bFailIfExists\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"CreateFileA\", \"Parameters\": {{ \"lpFileName\": \"{}\", \"dwDesiredAccess\": \"{}\", \"dwShareMode\": \"{}\", \"dwCreationDisposition\": \"{}\", \"dwFlagsAndAttributes\": \"{}\", \"hTemplateFile\": \"{}\"}} }}"
        , lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );

    return True_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


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
    Log("{{ \"HookedFunction\": \"CreateMutexA\", \"Parameters\": {{ \"bInitialOwner\": \"{}\", \"lpName\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"CreateProcessA\", \"Parameters\": {{ \"lpApplicationName\": \"{}\", \"lpCommandLine\": \"{}\", \"bInheritHandles\": \"{}\", \"dwCreationFlags\": \"{}\", \"lpEnvironment\": \"{}\", \"lpCurrentDirectory\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"DeleteFileA\", \"Parameters\": {{ \"lpFileName\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"ExitProcess\", \"Parameters\": {{ \"uExitCode\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"FindFirstFileA\", \"Parameters\": {{ \"lpFileName\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"FindNextFileA\", \"Parameters\": {{ \"hFindFile\": \"{}\"}} }}"
        , hFindFile
    );

    return True_FindNextFileA(hFindFile, lpFindFileData);
}


static LPSTR(WINAPI* True_GetCommandLineA) (
    ) = GetCommandLineA;

static LPSTR WINAPI Hook_GetCommandLineA(
) {
    Log("{{ \"HookedFunction\": \"GetCommandLineA\", \"Parameters\": {{}} }}"

    );

    return True_GetCommandLineA();
}


static void (WINAPI* True_GetStartupInfoW) (
    LPSTARTUPINFOW  lpStartupInfo
    ) = GetStartupInfoW;

static void WINAPI Hook_GetStartupInfoW(
    LPSTARTUPINFOW  lpStartupInfo
) {
    Log("{{ \"HookedFunction\": \"GetStartupInfoW\", \"Parameters\": {{}} }}"

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
    Log("{{ \"HookedFunction\": \"OpenMutexA\", \"Parameters\": {{ \"dwDesiredAccess\": \"{}\", \"bInheritHandle\": \"{}\", \"lpName\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"OpenProcess\", \"Parameters\": {{ \"dwDesiredAccess\": \"{}\", \"bInheritHandle\": \"{}\", \"dwProcessId\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"RegCloseKey\", \"Parameters\": {{}} }}"

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
    Log("{{ \"HookedFunction\": \"RegDeleteKeyA\", \"Parameters\": {{ \"lpSubKey\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"RegDeleteValueA\", \"Parameters\": {{ \"lpValueName\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"RegOpenKeyA\", \"Parameters\": {{ \"lpSubKey\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"RegSaveKeyA\", \"Parameters\": {{ \"lpFile\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"RegSetValueA\", \"Parameters\": {{ \"lpSubKey\": \"{}\", \"dwType\": \"{}\", \"lpData\": \"{}\", \"cbData\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"ReleaseMutex\", \"Parameters\": {{ \"hMutex\": \"{}\"}} }}"
        , hMutex
    );

    return True_ReleaseMutex(hMutex);
}


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
    Log("{{ \"HookedFunction\": \"ShellExecuteA\", \"Parameters\": {{ \"lpOperation\": \"{}\", \"lpFile\": \"{}\", \"lpParameters\": \"{}\", \"lpDirectory\": \"{}\", \"nShowCmd\": \"{}\"}} }}"
        , lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd
    );

    return True_ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}


static void (WINAPI* True_Sleep) (
    DWORD  dwMilliseconds
    ) = Sleep;

static void WINAPI Hook_Sleep(
    DWORD  dwMilliseconds
) {
    Log("{{ \"HookedFunction\": \"Sleep\", \"Parameters\": {{ \"dwMilliseconds\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"VirtualAlloc\", \"Parameters\": {{ \"lpAddress\": \"{}\", \"dwSize\": \"{}\", \"flAllocationType\": \"{}\", \"flProtect\": \"{}\"}} }}"
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
    Log("{{ \"HookedFunction\": \"VirtualAllocEx\", \"Parameters\": {{ \"hProcess\": \"{}\", \"lpAddress\": \"{}\", \"dwSize\": \"{}\", \"flAllocationType\": \"{}\", \"flProtect\": \"{}\"}} }}"
        , hProcess, lpAddress, dwSize, flAllocationType, flProtect
    );

    return True_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}


/*****************************************************************************/
/*                               DETOUR ATTACH                               */
/*****************************************************************************/

void DetourAttach_AllHooks() {

    DetourAttach((PVOID *) & True_CopyFileA, Hook_CopyFileA);
    Log("\"Registered `CopyFileA` \"");

    DetourAttach((PVOID *) &True_CreateFileA, Hook_CreateFileA);
    Log("\"Registered `CreateFileA` \"");

    DetourAttach((PVOID *) &True_CreateMutexA, Hook_CreateMutexA);
    Log("\"Registered `CreateMutexA` \"");

    DetourAttach((PVOID *) &True_CreateProcessA, Hook_CreateProcessA);
    Log("\"Registered `CreateProcessA` \"");

    DetourAttach((PVOID *) &True_DeleteFileA, Hook_DeleteFileA);
    Log("\"Registered `DeleteFileA` \"");

    DetourAttach((PVOID *) &True_ExitProcess, Hook_ExitProcess);
    Log("\"Registered `ExitProcess` \"");

    DetourAttach((PVOID *) &True_FindFirstFileA, Hook_FindFirstFileA);
    Log("\"Registered `FindFirstFileA` \"");

    DetourAttach((PVOID *) &True_FindNextFileA, Hook_FindNextFileA);
    Log("\"Registered `FindNextFileA` \"");

    DetourAttach((PVOID *) &True_GetCommandLineA, Hook_GetCommandLineA);
    Log("\"Registered `GetCommandLineA` \"");

    DetourAttach((PVOID *) &True_GetStartupInfoW, Hook_GetStartupInfoW);
    Log("\"Registered `GetStartupInfoW` \"");

    DetourAttach((PVOID *) &True_OpenMutexA, Hook_OpenMutexA);
    Log("\"Registered `OpenMutexA` \"");

    DetourAttach((PVOID *) &True_OpenProcess, Hook_OpenProcess);
    Log("\"Registered `OpenProcess` \"");

    DetourAttach((PVOID *) &True_RegCloseKey, Hook_RegCloseKey);
    Log("\"Registered `RegCloseKey` \"");

    DetourAttach((PVOID *) &True_RegDeleteKeyA, Hook_RegDeleteKeyA);
    Log("\"Registered `RegDeleteKeyA` \"");

    DetourAttach((PVOID *) &True_RegDeleteValueA, Hook_RegDeleteValueA);
    Log("\"Registered `RegDeleteValueA` \"");

    DetourAttach((PVOID *) &True_RegOpenKeyA, Hook_RegOpenKeyA);
    Log("\"Registered `RegOpenKeyA` \"");

    DetourAttach((PVOID *) &True_RegSaveKeyA, Hook_RegSaveKeyA);
    Log("\"Registered `RegSaveKeyA` \"");

    DetourAttach((PVOID *) &True_RegSetValueA, Hook_RegSetValueA);
    Log("\"Registered `RegSetValueA` \"");

    DetourAttach((PVOID *) &True_ReleaseMutex, Hook_ReleaseMutex);
    Log("\"Registered `ReleaseMutex` \"");

    DetourAttach((PVOID *) &True_ShellExecuteA, Hook_ShellExecuteA);
    Log("\"Registered `ShellExecuteA` \"");

    DetourAttach((PVOID *) &True_Sleep, Hook_Sleep);
    Log("\"Registered `Sleep` \"");

    DetourAttach((PVOID *) &True_VirtualAlloc, Hook_VirtualAlloc);
    Log("\"Registered `VirtualAlloc` \"");

    DetourAttach((PVOID *) &True_VirtualAllocEx, Hook_VirtualAllocEx);
    Log("\"Registered `VirtualAllocEx` \"");

}
