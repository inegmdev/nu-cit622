#include "Process.h"

#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>  // For: CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next
#include "TextTable.h"

#include <psapi.h> // For: GetModuleInformation
#include <wchar.h> // For: wcscpy_s, wcscat_s
#include <codecvt> // For: converting wchar_t to string

#define CHECK_ReadProcessMemory_STATUS() do { \
		if (boolStatus == 0 && bytesRead == 0) { \
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
	SIZE_T bytesRead = 0;
	BOOL boolStatus = ReadProcessMemory(hProcess, pPbi->PebBaseAddress, pPeb, sizeof(PEB), &bytesRead);
	CHECK_ReadProcessMemory_STATUS();

	bytesRead = 0;
	boolStatus = ReadProcessMemory(hProcess, pPeb->Ldr, pLdr, sizeof(PEB_LDR_DATA), &bytesRead);
	CHECK_ReadProcessMemory_STATUS();

	/* Traversing the LDR */
	LDR_DATA_TABLE_ENTRY module = { 0 };
	uint16_t currentModuleIndex = 0;
	// First link to the first LIST_ENTRY
	LIST_ENTRY* head = pLdr->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* current = head;
	
#if (PROCESS_INFO_DEBUG == ON)
	cout << "[DEBUG] head = 0x" << std::hex << head << endl;
	cout << "[DEBUG] current = 0x" << std::hex << current << endl;
#endif
	
	do {
		// Fetch the module data from the process memory
		boolStatus = ReadProcessMemory(
			hProcess, CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
			&module, sizeof(LDR_DATA_TABLE_ENTRY), &bytesRead
		);
		CHECK_ReadProcessMemory_STATUS();

		// Fetching data for the module
		// 1. Module Name
		boolStatus = ReadProcessMemory(
			hProcess, module.FullDllName.Buffer,
			&(pProcAllInfo->ldrData.entries[currentModuleIndex].moduleName),
			module.FullDllName.Length, &bytesRead);
		pProcAllInfo->ldrData.entries[currentModuleIndex].moduleName[module.FullDllName.Length / sizeof(WCHAR)] = L'\0';
		CHECK_ReadProcessMemory_STATUS();
		// 2. Module/Dll base address
		pProcAllInfo->ldrData.entries[currentModuleIndex].moduleBaseAddr = module.DllBase;
		// 3. Checksum of the dll
		pProcAllInfo->ldrData.entries[currentModuleIndex].moduleCheckSum = module.CheckSum;
		// 4. Module timestamp
		pProcAllInfo->ldrData.entries[currentModuleIndex].moduleTimeDateStamp = module.TimeDateStamp;

		if (module.FullDllName.Length > 0) {
			// If the full dll name is not empty, update the num of scanned modules so far
			currentModuleIndex += 1;
			pProcAllInfo->ldrData.numEntries = currentModuleIndex;
		}

		// Update current to next module
		current = module.InMemoryOrderLinks.Flink;
#if (PROCESS_INFO_DEBUG == ON)
		cout << "[DEBUG] next current = 0x" << std::hex << current << endl;
#endif

	} while (current != head);

	/*
		Clean up
	*/
	// Free loaded handles and modules
	FreeLibrary(hNtDll);
	CloseHandle(hProcess);
	return ERROR_SUCCESS;
}

static BOOL bFolderExists(const LPCWSTR folderPath) {
	DWORD attributes = GetFileAttributes(folderPath);
	// Check if it exists and it's a folder
	return (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

static HANDLE bCreateOutDumpFile(const LPCWSTR folderPath, const LPCWSTR fileName) {
	wchar_t filePath[MAX_PATH] = { 0 };
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::string tempStr = "";
	
	BOOL bRet = bFolderExists(folderPath);
	if (bRet == FALSE) {
		// Create the directory
		BOOL bRet = CreateDirectory(folderPath, NULL);
		tempStr.clear();
		tempStr.assign(converter.to_bytes(folderPath));
		CHECK_COND_AND_RET_IF_ERR(bRet != 0, "Failed to create the output " << tempStr << " directory.", NULL);
	}

	// Construct the filePath
	wcscpy_s(filePath, folderPath);
	wcscat_s(filePath, L"\\");
	wcscat_s(filePath, fileName);

	// Create the file
	HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	tempStr.clear();
	tempStr.assign(converter.to_bytes(filePath));
	CHECK_COND_AND_RET_IF_ERR((hFile != INVALID_HANDLE_VALUE), "Failed to create the output file (" << tempStr << ") dump.", NULL);

	std::cout << "File created " << tempStr << std::endl;

	return hFile;
}

VOID ProcessInfo::dumpProcessByPid(DWORD processId) {
	BOOL bRet = 0;

	HANDLE hProcess = NULL;
	hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE, processId);
	CHECK_COND_AND_RET_IF_ERR(hProcess != NULL, "Failed to open process " << processId << " to dump it.", );

	// Loading the PE module
	MODULEINFO moduleInfo = { 0 };

	// Check if the process is a 32-Bit process
	BOOL bIsWow64 = 0;
	if (IsWow64Process(hProcess, &bIsWow64)) {
		if (bIsWow64)
			std::cout << "Process is 32-Bit process run on 64-Bit." << std::endl;
		else
			std::cout << "Process is 64-Bit process ." << std::endl;
	}
	else {
		std::cout << "Failed to determine the process architecture" << std::endl;
	}
	
	// GetModuleHandle(NULL) = Get the handle for the module used to create the current process
	//HMODULE hModule = GetModuleHandle(NULL);
	HMODULE hModule = NULL;
	bRet = GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		NULL,
		&hModule
	);
	CHECK_COND_AND_RET_IF_ERR((bRet != 0) && hModule != NULL, "Failed to get the module handle for the current process executable.", );
	bRet = GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));

	CHECK_COND_AND_RET_IF_ERR((bRet != 0), "Failed to get the basic module information.", );

	const LPCWSTR folderPath = L"C:\\Users\\inegm\\AppData\\Local";
	const LPCWSTR fileName = L"dumped_file.exe";
	HANDLE hFile = bCreateOutDumpFile(folderPath, fileName);
	CHECK_COND_AND_RET_IF_ERR(hFile != NULL, "Failed to create the output dump file.", );

	// Checking first if the process memory is accessible
	SIZE_T bytesRead = 0;
	bRet = ReadProcessMemory(hProcess, moduleInfo.lpBaseOfDll, NULL, moduleInfo.SizeOfImage, &bytesRead);
	if (bRet == 0 || bytesRead == 0) {
		std::cout << "[ERROR] Failed to read the process memory." << std::endl;
		CloseHandle(hProcess);
		CloseHandle(hFile);
	}

	// Create a buffer in the heap to dump process memory into it and then in file
	BYTE* buffer = new BYTE[bytesRead];
	bRet = ReadProcessMemory(hProcess, moduleInfo.lpBaseOfDll, buffer, bytesRead, &bytesRead);
	if (bRet == 0 || bytesRead == 0) {
		std::cout << "[ERROR] Failed to read the process memory." << std::endl;
		CloseHandle(hProcess);
		CloseHandle(hFile);
		delete[] buffer;
		return;
	}

	DWORD bytesWritten = 0;
	bRet = WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
	if (bRet == 0) {
		std::cout << "[ERROR] Failed to write the dumped memory into file. Error:" << GetLastError() << std::endl;
	}

	delete[] buffer;
	CloseHandle(hFile);
	CloseHandle(hProcess);

	wchar_t filePath[MAX_PATH] = { 0 };
	wcscpy_s(filePath, folderPath);
	wcscat_s(filePath, fileName);

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::string filePathString = converter.to_bytes(filePath);
	std::cout << "[SUCCESS] Memory of process " << processId << " has been dumped into (" << filePathString << ")." << std::endl;
}

VOID ProcessInfo::printProcInfo(_In_ ProcessInfo_tpstrAllInfo pProcAllInfo) {
	// Aliases for faster access
	PPROCESS_BASIC_INFORMATION pPbi = &(pProcAllInfo->pbi);
	PPEB pPeb = &(pProcAllInfo->peb);
	ProcessInfo_tpstrLoaderData ldrData = &(pProcAllInfo->ldrData);

	/*
		PBI (Process Basic Info) Structure
	*/

	TextTable pbiTable(' ');

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

	/*
		PEB (Process Environment Block) Structure
	*/
	
	TextTable pebTable(' ');
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

	/*
		Loader Data Print
	*/
	TextTable ldrDataTable(' ');

	for (int i = 0; i < ldrData->numEntries; i++) {
		ss.str("");
		ss << "Module (" << std::dec <<  i << ") -> ";
		ldrDataTable.add(ss.str());
		std::string _str(
			std::begin(ldrData->entries[i].moduleName),
			std::end(ldrData->entries[i].moduleName) - 1);
		ldrDataTable.add(_str);
		ldrDataTable.endOfRow();
		
		ldrDataTable.add("");
		ss.str("");
		ss << "Baseaddress = 0x" << std::hex << ldrData->entries[i].moduleBaseAddr;
		ldrDataTable.add(ss.str());
		ldrDataTable.endOfRow();

		ldrDataTable.add("");
		ss.str("");
		ss << "Checksum = 0x" << std::hex << ldrData->entries[i].moduleCheckSum;
		ldrDataTable.add(ss.str());
		ldrDataTable.endOfRow();

		ldrDataTable.add("");
		ss.str("");
		ss << "TimeDateStamp = " << std::dec << ldrData->entries[i].moduleTimeDateStamp;
		ldrDataTable.add(ss.str());
		ldrDataTable.endOfRow();
	}

	std::cout << "PEB/Loader info: " << "(" << std::dec << ldrData->numEntries << ") modules has been detected." << std::endl;
	std::cout << ldrDataTable << std::endl;


}