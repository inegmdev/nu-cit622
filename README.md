# nu-cit622
Main repo for my CIT622 OS Security course in Nile University

## Assignment#1 : 🕵 Windows Process Analysis and Dumping

### Introduction

In Windows operating systems, a process is a running instance of a program. Each process has its own virtual address space, which is isolated from other processes. The Process Environment Block (**PEB**) is a data structure used by Windows to store information about a process. The **PEB** contains a variety of data, including the process's environment variables, command line arguments, and module handles. The **PEB** is used by the Windows loader to set up the process's initial state, and it can be accessed by the process itself to retrieve information about its own execution context. The **PEB** is an important data structure for understanding how Windows processes work, and it is often used in malware analysis and reverse engineering.

In the assignment develop a Windows process memory parser that opens a running process i.e. `notepad.exe` and parse the `notepad.exe` **PEB** data structure and extract the **PEB** fields.

In order to  access `notepad.exe` find the process Id (**PID**) and get a handle to it using Windows API `OpenProcess` or you can traverse the Windows process list using the APIs `CreateToolhelp32Snapshot`, `Process32First` and `Process32Next` to find our `notepad.exe` process.

Once you get a handle to `notepad.exe`:
1. Print the basic information of `notepad.exe` process from the **PEB** data structure.
2. Parse the `notepad.exe` Portable Executable Header in memory and extract the NT and DOS headers and exported/import functions. Research the following data structure that contains this information such as PIMAGE_NT_HEADERS.  PIMAGE_EXPORT_DIRECTORY and PIMAGE_DOS_HEADER
3. Use the **PEB** to find the base address of loaded `kernel32.dll` and all other Dlls loaded by `notepad.exe`. You need to iterate through data structures internal to the Windows loader such as `PTEB`, `PLIST_ENTRY`, `PEB_LDR_DATA` and `LDR_DATA_TABLE_ENTRY`.
4. Bonus: Dump the `notepad.exe` from memory to a file on desk.

### Task List for Assignment#1

Develop Windows process memeory parser that opens a running process i.e. `notepad.exe` and do the following:

 - [x] Traverse the Windows process lisst using APIs `CreateToolhelp32Snapshot`, `Process32First` and `Process32Next` to find the `notepad.exe` process.
 - [x] Find the process ID (**PID**) and get a handle to it using Windows API `OpenProcess`.
 - [x] Parse the process **PEB** data structure and extract the **PEB** fileds.
 - [x] Print the basic information of `notepad.exe` process from the **PEB** data structure.
 - [x] Parse the `notepad.exe` Portable Executable (PE) Header in memory and extract:
     - [x] NT and DOS headers.
     - [x] Exported/import functions.
    Research the following data structure that contains this information such as `PIMAGE_NT_HEADERS`, `PIMAGE_EXPORT_DIRECTORY`, and `PIMAGE_DOS_HEADER`.
 - [x] Use the **PEB** to find the base address of the loaded "kernel32.dll" and all other DLLs loaded by `notepad.exe`. You need to iterate through data structures internal to the Windows loader such as `PTEB`, `PLIST_ENTRY`, `PEB_LDR_DATA` and `LDR_DATA_TABLE_ENTRY`.
 - [ ] Bonus: Dump the `notepad.exe` from memory to a file on desk.

### References

- [Process-Dump/pd/pd.cpp at main · glmcdona/Process-Dump](https://github.com/glmcdona/Process-Dump/blob/main/pd/pd.cpp)

__________________________________

## Assignment#2: 🕵 Basic Process Monitor (🌽Kernel Mode)

### Introduction

Windows kernel drivers are software modules that run in the kernel mode of the Windows operating system. They are used to interact with hardware devices, system services, and other kernel components. Kernel drivers are loaded into memory when the system boots up and remain in memory until the system shuts down. They have direct access to hardware resources and can execute privileged instructions that are not available to user-mode programs. Because of their privileged access to the system, kernel drivers must be carefully designed and implemented to ensure that they are secure and reliable. Kernel drivers are typically written in C or C++ and are compiled into binary files with the .sys extension. They communicate with other kernel components and user-mode applications through system calls, IOCTLs (I/O control codes), and other communication mechanisms provided by the Windows Driver Model (WDM) or the Windows Driver Foundation (WDF).

#### Windows Kernel Simple Program Structure
```cpp
#include <ntddk.h>
void DriverUnload
(PDRIVER_OBJECT driver)
{
    // This function is called when the driver is unloaded
}
 
NTSTATUS DriverEntry
(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
   
    // This function is called when the driver is loaded
    driver->DriverUnload = DriverUnload;
   
    // Print a message to the kernel debugger
    DbgPrint("Hello, world!\n");
   
    return STATUS_SUCCESS;
}
```

This simple driver defines two functions: `DriverEntry` and `DriverUnload`. `DriverEntry` is the entry point for the driver and is called when the driver is loaded. `DriverUnload` is called when the driver is unloaded. In `DriverEntry`, the driver sets the `DriverUnload` function pointer to point to the `DriverUnload` function. It then prints a message to the kernel debugger using the DbgPrint function. When the driver is unloaded, the `DriverUnload` function is called, which can be used to free any resources that were allocated by the driver. To compile and build this driver, you will need to install the Windows Driver Kit (WDK) and use the appropriate build tools to build and sign the driver.
 
#### How to run Windows Kernel drivers

- Create a test virtaul machine **(DONOT TEST THE DRIVER IN YOUR HOST/MAIN SYSTEM)**
- Use the command: `sc create [service name] binPath= [path to your .sys file] type= kernel`

#### In this Assignment

Write a simple Windows kernel driver that prints the CPUID information from the kernel. Extend your kernel driver into a basic process monitor that logs processes being started. For example, after the driver being loaded any process starts (i.e. Chrome.exe) the driver will log the process info (Use `PsSetCreateProcessNotifyRoutine` and `PsSetNotifyLoadImageRoutine`)

#### API documentation
 
- https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
- https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine

#### Assignment deliverables

- The C/C++ sources for process monitor kernel project.
- Screenshot your program running in command line and output the various fields of process notify struct and CPUID.

## Tasklist for the assginement#2

- [ ] Write simple kerneel driver that prints the CPUID information from the kernel.
- [ ] Extend your kernel driver into a basic process monitor that logs processes being started. For example, after the driver being loaded any process starts (i.e. `Chrome.exe`) the driver will log the process info. Use `PsSetCreateProcessNotifyRoutine` and `PsSetNotifyLoadImageRoutine`.
  - [ ] Output the various fields of the process notify struct and CPUID.
- [ ] Deliver the source code for the project ans screenshots for the program while working.

__________________________________

## Assignment#3: 🔗 User Mode System Monitor (Hooking)

### Introduction
__________________________________

## Assignment#3: 🔐 Password and authentication credentials Attacks using Mimikatz

### What is Mimikatz

Mimikatz is a well-known tool test the security of a system. It is primarily used to extract password hashes, plaintext passwords, and other authentication credentials from a Windows system's memory. The tool is designed to exploit weaknesses in the Windows security model and can be used to escalate privileges and perform other malicious actions.

### How it works

To dump password and credentials, Mimikatz uses a technique called "pass-the-hash." This technique involves extracting password hashes from memory and then using them to authenticate with other systems without the need for the actual password. This means that even if the password is changed, an attacker can still use the hash to authenticate with other systems.

Mimikatz also has the ability to extract plaintext passwords from memory by scanning for them in clear text format. This is possible because Windows often stores passwords in plain text format in memory, making them vulnerable to extraction by tools like Mimikatz.

### What is expected in the assignment?

In this assignment you are asked to do a thoroughly analysis of Mimikatz and how it works. Starts from the Mimikatz source code on Github:

- Compile Mimikatz from source code.
- Run Mimikatz binariy (In a Virtual machine) and monitor the API calls using you user mode hooking tools ( Assignment 3) and/or ProcessExporer/ProcessMonitor.
- Write an analysis report that shows the following:
  - High level outline on how Mimikatz works and what API it calls to access Lsass process
  - How the “Pass the hash” technique works and where in the code this technique is implemented and how it implemented.
  - When you run Mimikatz on a victim virtual machine, what artifacts it leaves behind?
    - What files being dropped on a system?
    - What process is created, and victims process being accessed?
    - Any other important artifacts?

### Tool documentation

https://github.com/gentilkiwi/mimikatz

#### Assignment deliverables

- Full and detailed analysis report of min 10 pages and no longer than 20 pages.
- Screenshot Mimikatz running in command line and output the and how to dump user pass/credentials.