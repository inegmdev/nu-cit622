# Assignment#2: 🕵 Basic Process Monitor (🌽Kernel Mode)

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

- [Download the Windows Driver Kit (WDK) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [__cpuid, __cpuidex | Microsoft Learn](https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170)
- [PsSetCreateProcessNotifyRoutine function (ntddk.h) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)
- [PsSetLoadImageNotifyRoutine function (ntddk.h) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)

### Assignment deliverables

- The C/C++ sources for process monitor kernel project.
- Screenshot your program running in command line and output the various fields of process notify struct and CPUID.

### 📃 Tasklist for the assginement#2

- [X] Create a VM Windows 10 and disable the driver signing from it (Test Mode)
- [X] Create an empty driver, and add initial syntax for a minimal driver.
- [X] Setup the link between the debugger and the remote computer.

  - [X] Provision a target VM ready for kernel debugging check [REF_LAB] and [REF_PROV_TEST]
  - [X] Deploy a driver to the test computer, check [REF_TUT_DBG].
- [X] Write simple kernel driver that prints the CPUID information from the kernel, check [REF_CPUID].
- [X] Extend your kernel driver into a basic process monitor that logs processes being started. For example, after the driver being loaded any process starts (i.e. `Chrome.exe`) the driver will log the process info. Use `PsSetCreateProcessNotifyRoutine` and `PsSetNotifyLoadImageRoutine`.
  - [X] Output the various fields of the process notify struct and CPUID.
- [X] Deliver the source code for the project and screenshots for the program while working.

### Screenshots

![kernel-driver-logging-cpuid.jpg](./__OUT/screenshots/kernel-driver-logging-cpuid.jpg)
![kernel-driver-logging-processinfo.jpg](./__OUT/screenshots/kernel-driver-logging-processinfo.jpg)

### Report and Demo Video

Take a look on the full log output from the kernel driver using WinDbg - [full-kernel-driver-log-using-windbg-inside-vstudio.txt](./__OUT/reports/full-kernel-driver-log-using-windbg-inside-vstudio.txt)
Also check the video added for a walk through the demo - [CIT622 - [Project Demo] Process Monitoring Windows Kernel Driver - Youtube](https://youtu.be/d_TJgxzFkjQ)

### References

1. [Download the Windows Driver Kit (WDK) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#download-and-install-the-windows-11-version-22h2-wdk)
2. [Write a Hello World Windows Driver (KMDF) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/writing-a-very-small-kmdf--driver)
3. [REF_LAB] [Debug Windows drivers step-by-step lab (echo kernel mode) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-)
4. [REF_PROV_TEST] [Provision a computer for driver deployment and testing (WDK 10) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-gb/windows-hardware/drivers/gettingstarted/provision-a-target-computer-wdk-8-1)
5. [REF_DEP_DRIVER] [Deploying a Driver to a Test Computer - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-gb/windows-hardware/drivers/develop/deploying-a-driver-to-a-test-computer)
6. [REF_TUT_DBG] [(50) How to Set Up Kernel Debugging in Windows - YouTube](https://www.youtube.com/watch?v=h6p-Kt-Cx9E)
7. [REF_CPUID] [CPUID — CPU Identification (felixcloutier.com)](https://www.felixcloutier.com/x86/cpuid)
8. [Disable Driver Signature Enforcement [Windows Guide] (windowsreport.com)](https://windowsreport.com/driver-signature-enforcement-windows-10/) - Put Windows in test mode
