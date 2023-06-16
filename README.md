# nu-cit622
Main repo for my CIT622 OS Security course in Nile University

## [Assignment#1 : 🕵 Windows Process Analysis and Dumping](./Assignments/01%20-%20Windows%20Process%20Analysis%20and%20Dumping/README.md)

This assginement provides an introduction to the Process Environment Block (**PEB**) in Windows operating systems. The **PEB** is a data structure that stores information about a process, such as environment variables and module handles. It is used by the Windows loader to set up the process's initial state and can be accessed by the process itself. The assignment involves developing a Windows process memory parser that opens the "notepad.exe" process and extracts information from its **PEB**. This includes printing basic process information, parsing the Portable Executable Header to extract NT and DOS headers, and finding the base address of loaded DLLs using the PEB. There is also a bonus task to dump the "notepad.exe" from memory to a file. The provided references include a relevant code example.

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