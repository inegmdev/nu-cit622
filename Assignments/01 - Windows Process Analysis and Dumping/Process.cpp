#include "Process.h"

#include <iostream>
#include <tlhelp32.h>  // For: CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next

using namespace std;

DWORD ProcessInfo::getPidByName(const wstring& processExecName) {
	// Take a snapshot of all running processs
	//   [in] dwFlags = TH32CS_SNAPPROCESS -> Includes all the processes in the system to enumerate on them using Process32First and Process32Next
	//   [in] th32ProcessID = 0 -> indicates the current process.
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry = {sizeof(PROCESSENTRY32)};
		BOOL bRet = Process32First(hSnapshot, &processEntry);
		if (bRet == FALSE) {
			cout << "Error : " << hex << GetLastError() << endl;
			return NULL;
		}
		do {
			if (processExecName.compare(processEntry.szExeFile) == 0) {
				return processEntry.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &processEntry));
	}
	return NULL;
}

PPEB ProcessInfo::getPbiByPid(const DWORD processId) {
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	PPEB pPeb = NULL;

	// OpenProcess
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess == NULL) {
		cout << "[ERROR] Failed to open process (" << processId << "). Error: " << GetLastError() << endl;
		return NULL;
	}

	// Prepare to use the internal NtQueryInformationProcess API in "Ntdll.dll"
	HMODULE hNtDll = LoadLibrary(L"Ntdll.dll");
	if (hNtDll == NULL) {
		cout << "[ERROR] Failed to load the NTDLL library to fetch the NtQueryInformationProcess API." << endl;
		return NULL;
	}
	tpfNtQueryInformationProcess NtQueryInformationProcess = (tpfNtQueryInformationProcess) GetProcAddress(hNtDll, "NtQueryInformationProcess");

	// Use NtQueryInformationProcess to fetch the PBI structure for the process
	ULONG ulReturnLength = 0;
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ulReturnLength);
	if (ntStatus != 0 || ulReturnLength == 0) {
		cout << "[ERROR] Failed to query about the process information." << endl;
		FreeLibrary(hNtDll);
		return NULL;
	}

	return pPeb;
}
