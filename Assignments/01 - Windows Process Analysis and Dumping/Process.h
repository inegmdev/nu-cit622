#pragma once

#include <string> // For: std::wstring
#include <Windows.h> // For: DWORD, HANDLE, PVOID, ULONG, PULONG
#include <winternl.h> // For: PPEB

class ProcessInfo {
public:
	static DWORD getPidByName(const std::wstring& processName);
	static PPEB getPbiByPid(const DWORD processId);
};

// Types
typedef NTSTATUS(NTAPI* tpfNtQueryInformationProcess) (
	_In_   HANDLE           ProcessHandle,
	_In_   PROCESSINFOCLASS ProcessInformationClass,
	_Out_  PVOID            ProcessInformation,
	_In_   ULONG            ProcessInformationLength,
	_Out_  PULONG           ReturnLength
	);
