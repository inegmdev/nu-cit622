# nu-cit622
Main repo for my CIT622 OS Security course in Nile University

## Assignment 1

### Introduction

In Windows operating systems, a process is a running instance of a program. Each process has its own virtual address space, which is isolated from other processes. The Process Environment Block (PEB) is a data structure used by Windows to store information about a process. The PEB contains a variety of data, including the process's environment variables, command line arguments, and module handles. The PEB is used by the Windows loader to set up the process's initial state, and it can be accessed by the process itself to retrieve information about its own execution context. The PEB is an important data structure for understanding how Windows processes work, and it is often used in malware analysis and reverse engineering.

In the assignment develop a Windows process memory parser that opens a running process i.e. “notepad.exe” and parse the “notepad.exe” PEB data structure and extract the PEB fields.

In order to  access “notepad.exe” find the process Id (PID) and get a handle to it using Windows API “OpenProcess” or you can traverse the Windows process list using the APIs “CreateToolhelp32Snapshot”, Process32First and Process32Next to find our “notepad.exe” process.

Once you get a handle to “notepad.exe”:
1. Print the basic information of "notepad.exe" process from the PEB data structure.
2. Parse the “notepad.exe” Portable Executable Header in memory and extract the NT and DOS headers and exported/import functions. Research the following data structure that contains this information such as PIMAGE_NT_HEADERS.  PIMAGE_EXPORT_DIRECTORY and PIMAGE_DOS_HEADER
3. Use the PEB to find the base address of loaded “kernel32.dll” and all other Dlls loaded by “notepad.exe”. You need to iterate through data structures internal to the Windows loader such as PTEB, PLIST_ENTRY, PEB_LDR_DATA and LDR_DATA_TABLE_ENTRY.
4. Bonus: Dump the “notepad.exe” from memory to a file on desk.

### Task List for Assignment#1

Develop Windows process memeory parser that opens a running process i.e. "notepad.exe" and do the following:

 - [x] Traverse the Windows process lisst using APIs `CreateToolhelp32Snapshot`, `Process32First` and `Process32Next` to find the "notepad.exe" process.
 - [x] Find the process ID (PID) and get a handle to it using Windows API `OpenProcess`.
 - [x] Parse the process PEB data structure and extract the PEB fileds.
 - [x] Print the basic information of "notepad.exe" process from the PEB data structure.
 - [x] Parse the "notepad.exe" Portable Executable (PE) Header in memory and extract:
     - [x] NT and DOS headers.
     - [ ] Exported/import functions.
    Research the following data structure that contains this information such as `PIMAGE_NT_HEADERS`, `PIMAGE_EXPORT_DIRECTORY`, and `PIMAGE_DOS_HEADER`.
 - [x] Use the PEB to find the base address of the loaded "kernel32.dll" and all other DLLs loaded by "notepad.exe". You need to iterate through data structures internal to the Windows loader such as `PTEB`, `PLIST_ENTRY`, `PEB_LDR_DATA` and `LDR_DATA_TABLE_ENTRY`.
 - [ ] Bonus: Dump the "notepad.exe" from memory to a file on desk.

### References
- [Process-Dump/pd/pd.cpp at main · glmcdona/Process-Dump](https://github.com/glmcdona/Process-Dump/blob/main/pd/pd.cpp)