# [Assignment#2: 🕵 Basic Process Monitor (🌽Kernel Mode)](./Assignments/02%20-%20Basic%20Process%20Monitor%20(Kernel%20Mode)/README.md)

## Introduction

Windows kernel drivers are software modules that run in the kernel mode of the Windows operating system. They are used to interact with hardware devices, system services, and other kernel components. Kernel drivers are loaded into memory when the system boots up and remain in memory until the system shuts down. They _have direct access_ to hardware resources and can execute privileged instructions that are not available to user-mode programs. Because of their privileged access to the system, kernel drivers must be carefully designed and implemented to ensure that they are secure and reliable. Kernel drivers are typically written in C or C++ and are compiled into binary files with the .sys extension. They communicate with other kernel components and user-mode applications through system calls, IOCTLs (I/O control codes), and other communication mechanisms provided by the Windows Driver Model (WDM) or the Windows Driver Foundation (WDF).

### Windows Kernel Simple Program Structure

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

### How to run Windows Kernel drivers

- Create a test virtaul machine **(DONOT TEST THE DRIVER IN YOUR HOST/MAIN SYSTEM)**
- Use the command: `sc create [service name] binPath= [path to your .sys file] type= kernel`

### In this Assignment

Write a simple Windows kernel driver that prints the CPUID information from the kernel. Extend your kernel driver into a basic process monitor that logs processes being started. For example, after the driver being loaded any process starts (i.e. Chrome.exe) the driver will log the process info (Use `PsSetCreateProcessNotifyRoutine` and `PsSetNotifyLoadImageRoutine`)

### API documentation

- https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
- https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine

### Assignment deliverables

- The C/C++ sources for process monitor kernel project.
- Screenshot your program running in command line and output the various fields of process notify struct and CPUID.

### 📃 Tasklist for the assginement#2

- [ ] Write simple kerneel driver that prints the CPUID information from the kernel.
- [ ] Extend your kernel driver into a basic process monitor that logs processes being started. For example, after the driver being loaded any process starts (i.e. `Chrome.exe`) the driver will log the process info. Use `PsSetCreateProcessNotifyRoutine` and `PsSetNotifyLoadImageRoutine`.
  - [ ] Output the various fields of the process notify struct and CPUID.
- [ ] Deliver the source code for the project ans screenshots for the program while working.

### References

* [Download the Windows Driver Kit (WDK) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#download-and-install-the-windows-11-version-22h2-wdk)
* [Disable Driver Signature Enforcement [Windows Guide] (windowsreport.com)](https://windowsreport.com/driver-signature-enforcement-windows-10/) - Put Windows in test mode
