#pragma once

#include <string>     // For: std::wstring
#include <Windows.h>  // For: DWORD, HANDLE, PVOID, ULONG, PULONG
#include <winternl.h> // For: PROCESS_BASIC_INFORMATION
#include "Errors.h"   // For: StdError

/*
	Defines
*/
#define ON                               (1U)
#define OFF                              (0U)

#define PROCESS_INFO__MAX_LOADER_ENTRIES (200U)

#define PROCESS_INFO_DEBUG               (OFF)

/*
	Types
*/

/* Process Info : Entry of loader data */
typedef struct {
	WCHAR moduleName[MAX_PATH];
} ProcessInfo_tstrLoaderDataEntry;

/* Process Info : Loader data info */
typedef struct {
	ProcessInfo_tstrLoaderDataEntry entries[PROCESS_INFO__MAX_LOADER_ENTRIES];
	uint16_t numEntries;
} ProcessInfo_tstrLoaderData, * ProcessInfo_tpstrLoaderData;

/* Process Info */
typedef struct {
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb;
	PEB_LDR_DATA ldr;
	ProcessInfo_tstrLoaderData ldrData;
} ProcessInfo_tstrAllInfo, *ProcessInfo_tpstrAllInfo;

/* Used for indirect call for NTDLL API */
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
	static StdError getProcInfoByPid(_In_ const DWORD processId, ProcessInfo_tpstrAllInfo pProcAllInfo);
	static VOID printProcInfo(_In_ ProcessInfo_tpstrAllInfo pProcAllInfo);
};


