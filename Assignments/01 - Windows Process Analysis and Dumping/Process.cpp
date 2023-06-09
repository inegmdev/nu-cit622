#include "Process.h"

#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>  // For: CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next
#include "TextTable.h"

#define CHECK_ReadProcessMemory_STATUS() do { \
		if (boolStatus == 0 && _bytesRead == 0) { \
			cout << "[ERROR] Failed to read process memory." << endl; \
			/* Get some more infromation about what happened */ \
			/* GetLastError */ \
			FreeLibrary(hNtDll); \
			return ERROR_GEN_FAILURE; \
		} \
	} while (0)

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

StdError ProcessInfo::getProcInfoByPid(_In_ const DWORD processId, ProcessInfo_tpstrAllInfo pProcAllInfo) {
	// Faster access local aliases
	PPROCESS_BASIC_INFORMATION pPbi = &(pProcAllInfo->pbi);
	PPEB pPeb = &(pProcAllInfo->peb);
	PPEB_LDR_DATA pLdr = &(pProcAllInfo->ldr);

	// OpenProcess
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
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
	CHECK_ReadProcessMemory_STATUS();

	_bytesRead = 0;
	boolStatus = ReadProcessMemory(hProcess, pPeb->Ldr, pLdr, sizeof(PEB_LDR_DATA), &_bytesRead);
	CHECK_ReadProcessMemory_STATUS();

	// Free the loaded library
	FreeLibrary(hNtDll);
	return ERROR_SUCCESS;
}

VOID ProcessInfo::printProcInfo(_In_ ProcessInfo_tpstrAllInfo pProcAllInfo) {
	// Aliases for faster access
	PPROCESS_BASIC_INFORMATION pPbi = &(pProcAllInfo->pbi);
	PPEB pPeb = &(pProcAllInfo->peb);
	PPEB_LDR_DATA pLdr = &(pProcAllInfo->ldr);

	TextTable pbiTable(' ', ' ', ' ');

	pbiTable.add("UniqueProcessId: ");
	pbiTable.add(to_string( pPbi->UniqueProcessId ));
	pbiTable.endOfRow();

	pbiTable.add("PebBaseAddress: ");
	std::stringstream ss;
	ss << "0x" << std::hex << pPbi->PebBaseAddress;
	pbiTable.add( ss.str() );
	pbiTable.endOfRow();

	std::cout << "PBI information for process" << std::endl;
	std::cout << pbiTable << std::endl;

	TextTable pebTable(' ', ' ', ' ');

	pebTable.add("BeingDebugged: ");
	pebTable.add(to_string(pPeb->BeingDebugged));
	pebTable.endOfRow();

	pebTable.add("Ldr: ");
	ss.str("");
	ss << "0x" << std::hex << pPeb->Ldr;
	pebTable.add(ss.str());
	pebTable.endOfRow();

	pebTable.add("ProcessParameters: ");
	ss.str("");
	ss << "0x" << std::hex << pPeb->ProcessParameters;
	pebTable.add(ss.str());
	pebTable.endOfRow();

	pebTable.add("SessionId: ");
	pebTable.add(to_string(pPeb->SessionId));
	pebTable.endOfRow();

	std::cout << "PEB information for process" << std::endl;
	std::cout << pebTable << std::endl;

	TextTable pebLdrDataTabel(' ', ' ', ' ');

	pebLdrDataTabel.add("InMemoryOrderModuleList (Flink): ");
	ss.str("");
	ss << "0x" << std::hex << pLdr->InMemoryOrderModuleList.Flink;
	pebLdrDataTabel.add(ss.str());
	pebLdrDataTabel.endOfRow();

	std::cout << "PEB LDR info" << std::endl;
	std::cout << pebLdrDataTabel << std::endl;


}