﻿#include "Process.h"

#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>  // For: CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next

#include <psapi.h> // For: GetModuleInformation
#include <wchar.h> // For: wcscpy_s, wcscat_s
#include <codecvt> // For: converting wchar_t to string

#include <DbgHelp.h> // For: ImageDirectoryEntryToData

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

static BOOL vidEnableDebugPrivilege(VOID) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cout << "[ERROR] Failed to open process token. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        std::cout << "[ERROR] Failed to lookup privilege value. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        CloseHandle(hToken);
        std::cout << "[ERROR] Failed to adjust token privileges. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    CloseHandle(hToken);
    return 1;
}

VOID ProcessInfo::dumpProcessByPid(DWORD processId) {
    BOOL bRet = 0;

    /* In order to be able to dump the process, the app should have a SeDebugPrivilege */
    
    if (vidEnableDebugPrivilege())
    {
        // std::cout << "[SUCCESS] SeDebugPrivilege enabled successfully!" << std::endl;
        // Proceed with dumping other processes...
    }
    else
    {
        std::cout << "[ERROR] Failed to enable SeDebugPrivilege." << std::endl;
        return;
    }

    HANDLE hProcess = NULL;
    hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
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
#if 1
    HMODULE hModule = GetModuleHandle(NULL);
    CHECK_COND_AND_RET_IF_ERR(hModule != NULL, "Failed to get the module handle for the current process executable.", );
#else
    HMODULE hModule = NULL;
    bRet = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        NULL,
        &hModule
    );
    CHECK_COND_AND_RET_IF_ERR((bRet != 0) && hModule != NULL, "Failed to get the module handle for the current process executable.", );
#endif
    bRet = GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));
    //CHECK_COND_AND_RET_IF_ERR((bRet != 0), "Failed to get the basic module information.", );

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
    std::cout << "PBI (Process Basic Information):" << std::endl;
    std::cout << "  UniqueProcessId: " 
        << pPbi->UniqueProcessId << std::endl;
    std::cout << "  PebBaseAddress: " << "0x" 
        << std::hex << pPbi->PebBaseAddress << std::endl;
    std::cout << std::endl;

    /*
        PEB (Process Environment Block) Structure
    */

    std::cout << "PEB (Process Executable Block):" << std::endl;
    std::cout << "  BeingDebugged: " << pPeb->BeingDebugged << std::endl;
    std::cout << "  Ldr: " << "0x" << std::hex << pPeb->Ldr << std::endl;
    std::cout << "  ProcessParameters: " << "0x" << std::hex << pPeb->ProcessParameters << std::endl;
    std::cout << "  SessionId: " << pPeb->SessionId << std::endl;
    std::cout << std::endl;

    /*
        Loader Data Print
    */
    std::cout << "PEB/Loader info: " << "(" << std::dec << ldrData->numEntries << ") modules has been detected." << std::endl;

    for (int i = 0; i < ldrData->numEntries; i++) {
        std::string _str(
            std::begin(ldrData->entries[i].moduleName),
            std::end(ldrData->entries[i].moduleName) - 1);
        std::cout << "  Module (" << std::dec << i << ") -> " << _str << std::endl;
        std::cout << "    Baseaddress = 0x" << std::hex << ldrData->entries[i].moduleBaseAddr
            << ", Checksum = 0x" << std::hex << ldrData->entries[i].moduleCheckSum
            << ", TimeDateStamp = " << std::dec << ldrData->entries[i].moduleTimeDateStamp
            << std::endl;
    }
    std::cout << std::endl;
}

// Function to dump the DOS header of a module
void DumpDosHeader(const IMAGE_DOS_HEADER* dosHeader)
{
    std::cout << "DOS Header:" << std::endl;
    std::cout << std::hex ;
    std::cout << "  Magic Number: 0x" << dosHeader->e_magic << std::endl;
    std::cout << std::dec ;
    std::cout << "  Bytes on Last Page: " << dosHeader->e_cblp << std::endl;
    std::cout << "  Pages in File: " << dosHeader->e_cp << std::endl;
    std::cout << "  Relocations: " << dosHeader->e_crlc << std::endl;
    std::cout << "  Header Size (in paragraphs): " << dosHeader->e_cparhdr << std::endl;
    std::cout << std::hex ;
    std::cout << "  Minimum Extra Paragraphs: 0x" << dosHeader->e_minalloc << std::endl;
    std::cout << "  Maximum Extra Paragraphs: 0x" << dosHeader->e_maxalloc << std::endl;
    std::cout << "  Initial SS Value: 0x" << dosHeader->e_ss << std::endl;
    std::cout << "  Initial SP Value: 0x" << dosHeader->e_sp << std::endl;
    std::cout << "  Checksum: 0x" << dosHeader->e_csum << std::endl;
    std::cout << "  Initial IP Value: 0x" << dosHeader->e_ip << std::endl;
    std::cout << "  Initial CS Value: 0x" << dosHeader->e_cs << std::endl;
    std::cout << "  File Address of Relocation Table: 0x" << dosHeader->e_lfarlc << std::endl;
    std::cout << "  Overlay Number: 0x" << dosHeader->e_ovno << std::endl;
    std::cout << "  Reserved Words: ";
    for (int i = 0; i < 4; ++i)
    {
        std::cout << "0x" << dosHeader->e_res[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "  OEM Identifier: 0x" << dosHeader->e_oemid << std::endl;
    std::cout << "  OEM Information: 0x" << dosHeader->e_oeminfo << std::endl;
    std::cout << "  Reserved Words: ";
    for (int i = 0; i < 10; ++i)
    {
        std::cout << "0x" << dosHeader->e_res2[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "  File Address of New Exe Header: 0x" << dosHeader->e_lfanew << std::endl;
    std::cout << std::endl;
}



// Function to dump the NT header of a module
static void vidPrintNtHeader(const IMAGE_NT_HEADERS* ntHeader)
{
    std::cout << "NT Header:" << std::endl;
    std::cout << std::hex;
    std::cout << "  Signature: 0x" << ntHeader->Signature << std::endl;
    std::cout << std::endl;

    std::cout << "NT->FILE Header:" << std::endl;
    std::cout << std::hex;
    std::cout << "  Machine:               0x" << ntHeader->FileHeader.Machine              << std::endl;
    std::cout << "  NumberOfSections:      0x" << ntHeader->FileHeader.NumberOfSections     << std::endl;
    std::cout << "  TimeDateStamp:         0x" << ntHeader->FileHeader.TimeDateStamp        << std::endl;
    std::cout << "  PointerToSymbolTable:  0x" << ntHeader->FileHeader.PointerToSymbolTable << std::endl;
    std::cout << "  NumberOfSymbols:       0x" << ntHeader->FileHeader.NumberOfSymbols      << std::endl;
    std::cout << "  SizeOfOptionalHeader:  0x" << ntHeader->FileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << "  Characteristics:       0x" << ntHeader->FileHeader.Characteristics      << std::endl;
    std::cout << std::endl;
    
    std::cout << "NT->OPTIONAL Header:" << std::endl;
    std::cout << std::hex ;
    std::cout << "  Magic:                        0x" << ntHeader->OptionalHeader.Magic                        << std::endl;
    std::cout << "  MajorLinkerVersion:           0x" << (int) ntHeader->OptionalHeader.MajorLinkerVersion     << std::endl;
    std::cout << "  MinorLinkerVersion:           0x" << (int) ntHeader->OptionalHeader.MinorLinkerVersion     << std::endl;
    std::cout << "  SizeOfCode:                   0x" << ntHeader->OptionalHeader.SizeOfCode                   << std::endl;
    std::cout << "  SizeOfInitializedData:        0x" << ntHeader->OptionalHeader.SizeOfInitializedData        << std::endl;
    std::cout << "  SizeOfUninitializedData:      0x" << ntHeader->OptionalHeader.SizeOfUninitializedData      << std::endl;
    std::cout << "  AddressOfEntryPoint:          0x" << ntHeader->OptionalHeader.AddressOfEntryPoint          << std::endl;
    std::cout << "  BaseOfCode:                   0x" << ntHeader->OptionalHeader.BaseOfCode                   << std::endl;
    std::cout << "  ImageBase:                    0x" << ntHeader->OptionalHeader.ImageBase                    << std::endl;
    std::cout << "  SectionAlignment:             0x" << ntHeader->OptionalHeader.SectionAlignment             << std::endl;
    std::cout << "  FileAlignment:                0x" << ntHeader->OptionalHeader.FileAlignment                << std::endl;
    std::cout << "  MajorOperatingSystemVersion:  0x" << ntHeader->OptionalHeader.MajorOperatingSystemVersion  << std::endl;
    std::cout << "  MinorOperatingSystemVersion:  0x" << ntHeader->OptionalHeader.MinorOperatingSystemVersion  << std::endl;
    std::cout << "  MajorImageVersion:            0x" << ntHeader->OptionalHeader.MajorImageVersion            << std::endl;
    std::cout << "  MinorImageVersion:            0x" << ntHeader->OptionalHeader.MinorImageVersion            << std::endl;
    std::cout << "  MajorSubsystemVersion:        0x" << ntHeader->OptionalHeader.MajorSubsystemVersion        << std::endl;
    std::cout << "  MinorSubsystemVersion:        0x" << ntHeader->OptionalHeader.MinorSubsystemVersion        << std::endl;
    std::cout << "  Win32VersionValue:            0x" << ntHeader->OptionalHeader.Win32VersionValue            << std::endl;
    std::cout << "  SizeOfImage:                  0x" << ntHeader->OptionalHeader.SizeOfImage                  << std::endl;
    std::cout << "  SizeOfHeaders:                0x" << ntHeader->OptionalHeader.SizeOfHeaders                << std::endl;
    std::cout << "  CheckSum:                     0x" << ntHeader->OptionalHeader.CheckSum                     << std::endl;
    std::cout << "  Subsystem:                    0x" << ntHeader->OptionalHeader.Subsystem                    << std::endl;
    std::cout << "  DllCharacteristics:           0x" << ntHeader->OptionalHeader.DllCharacteristics           << std::endl;
    std::cout << "  SizeOfStackReserve:           0x" << ntHeader->OptionalHeader.SizeOfStackReserve           << std::endl;
    std::cout << "  SizeOfStackCommit:            0x" << ntHeader->OptionalHeader.SizeOfStackCommit            << std::endl;
    std::cout << "  SizeOfHeapReserve:            0x" << ntHeader->OptionalHeader.SizeOfHeapReserve            << std::endl;
    std::cout << "  SizeOfHeapCommit:             0x" << ntHeader->OptionalHeader.SizeOfHeapCommit             << std::endl;
    std::cout << "  LoaderFlags:                  0x" << ntHeader->OptionalHeader.LoaderFlags                  << std::endl;
    std::cout << "  NumberOfRvaAndSizes:          0x" << ntHeader->OptionalHeader.NumberOfRvaAndSizes          << std::endl;

    std::cout << std::endl;
}

// Function to dump the exported functions of a module
static void DumpExportedFunctions(HANDLE hProcess, HMODULE hModule)
{
    // Retrieve the module base address
    DWORD baseAddress = reinterpret_cast<DWORD>(hModule);

    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))
    {
        std::cout << "Failed to read DOS header. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Read the NT header
    IMAGE_NT_HEADERS ntHeader;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), nullptr))
    {
        std::cout << "Failed to read NT header. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Read the export directory
    IMAGE_EXPORT_DIRECTORY exportDirectory;
    DWORD exportDirSize = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
        &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
    {
        std::cout << "Failed to read export directory. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Read the export names
    DWORD* exportNames = new DWORD[exportDirectory.NumberOfNames];
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + exportDirectory.AddressOfNames),
        exportNames, sizeof(DWORD) * exportDirectory.NumberOfNames, nullptr))
    {
        std::cout << "Failed to read export names. Error code: " << GetLastError() << std::endl;
        delete[] exportNames;
        return;
    }

    // Print the exported function names
    std::cout << "Exported Functions:" << std::endl;
    for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i)
    {
        char functionName[256];
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + exportNames[i]),
            functionName, sizeof(functionName), nullptr))
        {
            std::cout << "Failed to read function name. Error code: " << GetLastError() << std::endl;
            break;
        }

        std::cout << "  " << functionName << std::endl;
    }
    std::cout << std::endl;

    delete[] exportNames;
}

// Function to dump the imported functions of a module
static void DumpImportedFunctions(HANDLE hProcess, HMODULE hModule)
{
    // Enumerate the modules in the target process
    HMODULE moduleHandles[1024];
    DWORD needed;
    if (!EnumProcessModules(hProcess, moduleHandles, sizeof(moduleHandles), &needed))
    {
        std::cout << "Failed to enumerate modules. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Determine the number of modules
    DWORD moduleCount = needed / sizeof(HMODULE);

    // Iterate through the modules
    for (DWORD i = 0; i < moduleCount; ++i)
    {
        // Retrieve the module base address
        DWORD baseAddress = reinterpret_cast<DWORD>(moduleHandles[i]);

        // Read the DOS header
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))
        {
            std::cout << "Failed to read DOS header. Error code: " << GetLastError() << std::endl;
            continue;
        }

        // Read the NT header
        IMAGE_NT_HEADERS ntHeader;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), nullptr))
        {
            std::cout << "Failed to read NT header. Error code: " << GetLastError() << std::endl;
            continue;
        }

        // Read the import directory
        IMAGE_IMPORT_DESCRIPTOR importDescriptor;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
            &importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr))
        {
            // No import directory found, move on to the next module
            continue;
        }

        // Iterate through the import descriptors
        while (importDescriptor.Name != 0)
        {
            // Read the module name
            char moduleName[256];
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + importDescriptor.Name),
                moduleName, sizeof(moduleName), nullptr))
            {
                std::cout << "Failed to read module name. Error code: " << GetLastError() << std::endl;
                break;
            }

            // Read the import lookup table
            IMAGE_THUNK_DATA thunkData;
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + importDescriptor.FirstThunk),
                &thunkData, sizeof(IMAGE_THUNK_DATA), nullptr))
            {
                std::cout << "Failed to read import lookup table. Error code: " << GetLastError() << std::endl;
                break;
            }

            // Iterate through the import lookup table
            while (thunkData.u1.AddressOfData != 0)
            {
                // Check if the import is by ordinal or by name
                if (thunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    // Import by ordinal
                    std::cout << "  Ordinal: " << (thunkData.u1.Ordinal & 0xFFFF) << std::endl;
                }
                else
                {
                    // Import by name
                    IMAGE_IMPORT_BY_NAME importByName;
                    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress + thunkData.u1.AddressOfData),
                        &importByName, sizeof(IMAGE_IMPORT_BY_NAME), nullptr))
                    {
                        std::cout << "Failed to read import by name. Error code: " << GetLastError() << std::endl;
                        break;
                    }

                    std::cout << "  Name: " << importByName.Name << std::endl;
                }

                // Move to the next entry in the import lookup table
                thunkData.u1.AddressOfData += sizeof(IMAGE_THUNK_DATA);
            }

            // Move to the next import descriptor
            importDescriptor.FirstThunk += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    std::cout << std::endl;
}

VOID ProcessInfo::printProcHeaders(_In_ const DWORD processId) {
    
    if (vidEnableDebugPrivilege())
    {
        // std::cout << "[SUCCESS] SeDebugPrivilege enabled successfully!" << std::endl;
        // Proceed with dumping other processes...
    }
    else
    {
        std::cout << "[ERROR] Failed to enable SeDebugPrivilege." << std::endl;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == nullptr)
    {
        std::cout << "Failed to open process. Error code: " << GetLastError() << std::endl;
        return;
    }

    HMODULE hModule = GetModuleHandle(nullptr);
    if (hModule == nullptr)
    {
        std::cout << "Failed to get module handle. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return;
    }

    DumpDosHeader(reinterpret_cast<const IMAGE_DOS_HEADER*>(hModule));

    const PIMAGE_NT_HEADERS ntHeaderAddr = reinterpret_cast<const PIMAGE_NT_HEADERS>(
        reinterpret_cast<const PBYTE>(hModule) + reinterpret_cast<const PIMAGE_DOS_HEADER>(hModule)->e_lfanew
    );
    vidPrintNtHeader(ntHeaderAddr);
    //DumpExportedFunctions(hProcess, hModule);
    //DumpImportedFunctions(hProcess, hModule);

    CloseHandle(hProcess);
    return;
}

static VOID vidPrintImportList(const HMODULE hModule)
{
    // Get the base address of the PE image
    PIMAGE_DOS_HEADER pDosHeader = 
        reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    PIMAGE_NT_HEADERS pNtHeaders = 
        reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<PBYTE>(hModule) + pDosHeader->e_lfanew
        );
    

    // Retrieve the pointer to the import directory entry
    IMAGE_DATA_DIRECTORY importDataDir = 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = 
        reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            reinterpret_cast<const PBYTE>(hModule) 
            + importDataDir.VirtualAddress
            );


    // Iterate through the import descriptors until the end of the list (NULL entry)
    while (
        pImportDescriptor != nullptr && 
        pImportDescriptor->OriginalFirstThunk != 0
        )
    { 
        // Get the module name
        LPCSTR moduleName = 
            reinterpret_cast<LPCSTR>(
                reinterpret_cast<const PBYTE>(hModule)
                + pImportDescriptor->Name
            );
        
        std::cout << "    Module Name: (" << moduleName << ")" << std::endl;

        // Iterate through the imported functions
        PIMAGE_THUNK_DATA pThunk = 
            reinterpret_cast<PIMAGE_THUNK_DATA>(
                reinterpret_cast<const PBYTE>(hModule)
                + pImportDescriptor->OriginalFirstThunk
            );
        while (pThunk->u1.AddressOfData != 0)
        {
            // Check if it's an ordinal import or named import
            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
            {
                // Ordinal import
                WORD ordinal = IMAGE_ORDINAL(pThunk->u1.Ordinal);
                std::cout << "      Ordinal: " << ordinal << std::endl;
            }
            else
            {
                // Named import
                PIMAGE_IMPORT_BY_NAME pImportByName = 
                    reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        reinterpret_cast<const PBYTE>(hModule)
                        + pThunk->u1.AddressOfData
                    );
                LPCSTR functionName = 
                    reinterpret_cast<LPCSTR>(pImportByName->Name);
                std::cout << "      Func : " << functionName
                    << std::endl;
            }

            // Move to the next imported function
            pThunk++;
        }

        // Move to the next import descriptor
        pImportDescriptor++;
    }
    std::cout << std::endl;
}

static VOID vidPrintExportList(const HMODULE hModule)
{
    // Get the base address of the PE image
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(hModule) + pDosHeader->e_lfanew
    );

    // Retrieve the pointer to the export directory entry
    IMAGE_DATA_DIRECTORY exportDataDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<const PBYTE>(hModule) + exportDataDir.VirtualAddress
    );

    // Get the module name
    LPCSTR moduleName = reinterpret_cast<LPCSTR>(reinterpret_cast<const PBYTE>(hModule) + pExportDirectory->Name);
 

    // Retrieve the exported functions
    PDWORD pAddressOfFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<const PBYTE>(hModule) + pExportDirectory->AddressOfFunctions);
    PWORD pAddressOfNameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<const PBYTE>(hModule) + pExportDirectory->AddressOfNameOrdinals);
    PDWORD pAddressOfNames = reinterpret_cast<PDWORD>(reinterpret_cast<const PBYTE>(hModule) + pExportDirectory->AddressOfNames);
    DWORD numberOfFunctions = pExportDirectory->NumberOfFunctions;

    if (numberOfFunctions == 0) {
        std::cout << "    No export list." << std::endl << std::endl;
        return;
    }

    std::cout << "Module Name: " << moduleName << std::endl;

    for (DWORD i = 0; i < numberOfFunctions; i++)
    {
        DWORD functionRVA = pAddressOfFunctions[i];
        WORD nameOrdinal = pAddressOfNameOrdinals[i];
        DWORD functionNameRVA = pAddressOfNames[nameOrdinal];

        // Check if the function is forwarded
        if (functionRVA >= exportDataDir.VirtualAddress && functionRVA < exportDataDir.VirtualAddress + exportDataDir.Size)
        {
            // Forwarded export
            LPCSTR forwardedFunctionName = reinterpret_cast<LPCSTR>(reinterpret_cast<const PBYTE>(hModule) + functionRVA);
            std::cout << "Forwarded Function: " << forwardedFunctionName << std::endl;
        }
        else
        {
            // Regular export
            LPCSTR functionName = reinterpret_cast<LPCSTR>(reinterpret_cast<const PBYTE>(hModule) + functionNameRVA);
            std::cout << "Function Name: " << functionName << std::endl;
        }
    }
    std::cout << std::endl;
}


VOID ProcessInfo::vidPrintProcExportsImports(_In_ const DWORD dwProcessId) {
#if 0 
    BOOL bRet = 0;

    // Open the process
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, dwProcessId
    );
    CHECK_COND_AND_RET_IF_ERR(
        hProcess != NULL, "Failed to open the process" << dwProcessId,
        );
    
    // Enumerate over all the modules in the image
    HMODULE* hModules = nullptr;
    DWORD cbNeeded = 0;

    bRet = EnumProcessModulesEx(
        hProcess, nullptr, 0, &cbNeeded, LIST_MODULES_ALL
    );
    CHECK_COND_AND_RET_IF_ERR(
        bRet != 0 && cbNeeded != 0,
        "Failed to enumerate the modules.",
    );

    // Alocate memory for the module handles
    hModules = new HMODULE[cbNeeded / sizeof(HMODULE)];
    bRet = EnumProcessModulesEx(
        hProcess, hModules, cbNeeded, &cbNeeded, LIST_MODULES_ALL
    );
    if (!(bRet != 0 && cbNeeded != 0)) {
        std::cout << 
        "[ERROR] Failed to enumerate the modules. System error code ("
        << GetLastError() << ")" << std::endl;
        delete[] hModules;
        CloseHandle(hProcess);
        return;
    }

    DWORD numModules = cbNeeded / sizeof(HMODULE);

    std::cout << std::dec;
    std::cout << std::endl;    
    std::cout << "List Modules: " << numModules << std::endl ;

    // For each module print the imports and exports
    for (int i=0; i<numModules; i++) {
        std::cout << 
        "  Module#" << i << ": (0x" << std::hex << hModules[i] << ")" 
        << std::endl;

        // Print the import list
        vidPrintImportList(hModules[i]);

        // Print the export list
        vidPrintExportList(hModules[i]);

        std::cout << std::endl;

    }
#else
    // Get the current module handle
    HMODULE hModule = GetModuleHandle(nullptr);
    if (hModule == nullptr)
    {
        std::cout << "[ERROR] Failed to get the module handle. Error code: " << GetLastError() << std::endl;
        return;
    }
    // Print the import list
    std::cout << "Import list:" << std::endl;
    vidPrintImportList(hModule);
    
    // Print the export list
    std::cout << "Export list:" << std::endl;
    vidPrintExportList(hModule);

#endif
}