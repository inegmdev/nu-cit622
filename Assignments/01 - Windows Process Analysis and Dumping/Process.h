#pragma once

#include <string>     // For: std::wstring
#include <Windows.h>  // For: DWORD, HANDLE, PVOID, ULONG, PULONG
#include <winternl.h> // For: PROCESS_BASIC_INFORMATION
#include "Errors.h"   // For: StdError

class ProcessInfo {
public:
	static DWORD getPidByName(_In_ const std::wstring& processName);
	static StdError getPbiAndPebByPid(_In_ const DWORD processId, _Out_ PPROCESS_BASIC_INFORMATION pPbi, _Out_ PPEB pPeb);
	static VOID printProcessPbiAndPeb(_In_ PPROCESS_BASIC_INFORMATION pPbi, _In_ PPEB pPeb);
};

// Types
typedef NTSTATUS(NTAPI* tpfNtQueryInformationProcess) (
	_In_   HANDLE           ProcessHandle,
	_In_   PROCESSINFOCLASS ProcessInformationClass,
	_Out_  PVOID            ProcessInformation,
	_In_   ULONG            ProcessInformationLength,
	_Out_  PULONG           ReturnLength
	);
