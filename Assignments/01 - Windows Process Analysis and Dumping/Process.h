#pragma once

#include <string>     // For: std::wstring
#include <Windows.h>  // For: DWORD, HANDLE, PVOID, ULONG, PULONG
#include <winternl.h> // For: PROCESS_BASIC_INFORMATION
#include "Errors.h"   // For: StdError

/*
	Types
*/
typedef struct {

} ProcessInfo_tstrLoaderData;
typedef struct {
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb;
	PEB_LDR_DATA ldr;

} ProcessInfo_tstrAllInfo, *ProcessInfo_tpstrAllInfo;

typedef NTSTATUS(NTAPI* tpfNtQueryInformationProcess) (
	_In_   HANDLE           ProcessHandle,
	_In_   PROCESSINFOCLASS ProcessInformationClass,
	_Out_  PVOID            ProcessInformation,
	_In_   ULONG            ProcessInformationLength,
	_Out_  PULONG           ReturnLength
	);

/*
	Classes
*/
class ProcessInfo {
public:
	static DWORD getPidByName(_In_ const std::wstring& processName);
	static StdError getPbiAndPebByPid(_In_ const DWORD processId, ProcessInfo_tpstrAllInfo pProcAllInfo);
	static VOID printProcessPbiAndPeb(_In_ ProcessInfo_tpstrAllInfo pProcAllInfo);
};


