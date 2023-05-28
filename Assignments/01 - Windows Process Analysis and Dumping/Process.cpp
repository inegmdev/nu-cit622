#include "Process.h"

#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>  // For: CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next
#include "TextTable.h"


using namespace std;

DWORD ProcessInfo::getPidByName(_In_ const wstring& processExecName) {
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

StdError ProcessInfo::getPbiAndPebByPid(_In_ const DWORD processId, _Out_ PPROCESS_BASIC_INFORMATION pPbi, PPEB pPeb) {
	// OpenProcess
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess == NULL) {
		cout << "[ERROR] Failed to open process (" << processId << "). Error: " << GetLastError() << endl;
		return ERROR_GEN_FAILURE;
	}

	// Prepare to use the internal NtQueryInformationProcess API in "Ntdll.dll"
	HMODULE hNtDll = LoadLibrary(L"Ntdll.dll");
	if (hNtDll == NULL) {
		cout << "[ERROR] Failed to load the NTDLL library to fetch the NtQueryInformationProcess API." << endl;
		return ERROR_GEN_FAILURE;
	}
	tpfNtQueryInformationProcess NtQueryInformationProcess = (tpfNtQueryInformationProcess) GetProcAddress(hNtDll, "NtQueryInformationProcess");

	// Use NtQueryInformationProcess to fetch the PBI structure for the process
	ULONG ulReturnLength = 0;
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pPbi, sizeof(PROCESS_BASIC_INFORMATION), &ulReturnLength);
	if (ntStatus != 0 || ulReturnLength == 0) {
		cout << "[ERROR] Failed to query about the process information." << endl;
		FreeLibrary(hNtDll);
		return ERROR_GEN_FAILURE;
	}
	SIZE_T _bytesRead = 0;
	BOOL boolStatus = ReadProcessMemory(hProcess, pPbi->PebBaseAddress, pPeb, sizeof(PEB), &_bytesRead);
	if (boolStatus == TRUE && _bytesRead != 0) {
		cout << "[ERROR] Failed to read the PEB structure." << endl;
		FreeLibrary(hNtDll);
		return ERROR_GEN_FAILURE;
	}

	// Free the loaded library
	FreeLibrary(hNtDll);
	return ERROR_SUCCESS;
}

VOID ProcessInfo::printProcessPbiAndPeb(_In_ PPROCESS_BASIC_INFORMATION pPbi, PPEB pPeb) {
	TextTable t('-', '|', '+');

	t.add("UniqueProcessId: ");
	t.add(to_string( pPbi->UniqueProcessId ));
	t.endOfRow();

	t.add("PebBaseAddress: ");
	std::stringstream ss;
	ss << "0x" << std::hex << pPbi->PebBaseAddress;
	t.add( ss.str() );
	t.endOfRow();

	std::cout << "PBI information for process" << std::endl;
	std::cout << t << std::endl;
}