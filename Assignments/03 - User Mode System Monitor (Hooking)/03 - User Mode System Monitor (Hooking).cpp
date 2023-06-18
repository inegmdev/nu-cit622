#include <iostream>
#include <Windows.h>
#include <string>
#include <codecvt>

#include "Detoury.h"

static bool IsFileValid(const wchar_t* filePath) {
    DWORD fileAttributes = GetFileAttributes(filePath);
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

static bool IsFile32Bit(const wchar_t* filePath, bool* is32Bit) {
    HANDLE fileHandle = CreateFile(
        filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        ERR_LN("Failed to open the file for reading.");
        return 0; // ERROR 
    }
    
    // Reading the DOS file header
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
        ERR_LN("Failed to read the DOS header.");
        CloseHandle(fileHandle);
        return 0; // ERROR
    }

    if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS ntHeaders;
        SetFilePointer(fileHandle, dosHeader.e_lfanew, NULL, FILE_BEGIN);
        if (ReadFile(fileHandle, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead, NULL)) {
            if (ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                DBG_LN("ntHeaders.FileHeader.Machine: " << std::hex <<  " 0x" << ntHeaders.FileHeader.Machine);
                DBG_LN("ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386: " << (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386));
                *is32Bit = (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
            }
            else {
                ERR_LN("Not valid PE file.");
                return 0;
            }
        }
        else {
            ERR_LN("Failed to read the NT header.");
            return 0;
        }
    }
    else {
        ERR_LN("Not valid PE file.");
        return 0;
    }
    return 1;
}

int main(int argc, char* argv[])
{
    // Check the inputs
    if (argc != 2) {
        ERR_LN("Invalid call for the program.");
        INFO_LN("Usage: " << argv[0] << " <executable_path> ");
        return 1;
    }

    std::wstring wideFilePath = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(argv[1]);
    const wchar_t* filePath = wideFilePath.c_str();

    if (!IsFileValid(filePath)) {
        ERR("Invalid file: (");
        std::wcerr << filePath;
        std::cerr << ")." << std::endl;
        return 1;
    }
    bool is32Bit = 0;

    if (IsFile32Bit(filePath, &is32Bit)) {
        if (is32Bit == 1) {
            INFO_LN("Executable is 32-Bit.");
        }
        else {
            INFO_LN("Executable is 64-Bit.");
        }
        
    }
    else {
        ERR("Failed to read the file (");
        std::wcerr << filePath; 
        std::cerr << ")." << std::endl;
    }

    std::cout << "Hello World!\n";
}
