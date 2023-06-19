# nu-cit622

Main repo for my CIT622 OS Security course in Nile University

## [Assignment#1 : 🕵 Windows Process Analysis and Dumping](./Assignments/01%20-%20Windows%20Process%20Analysis%20and%20Dumping/README.md)

This assginement provides an introduction to the Process Environment Block (**PEB**) in Windows operating systems. The **PEB** is a data structure that stores information about a process, such as environment variables and module handles. It is used by the Windows loader to set up the process's initial state and can be accessed by the process itself. The assignment involves developing a Windows process memory parser that opens the "notepad.exe" process and extracts information from its **PEB**. This includes printing basic process information, parsing the Portable Executable Header to extract NT and DOS headers, and finding the base address of loaded DLLs using the PEB. There is also a bonus task to dump the "notepad.exe" from memory to a file. The provided references include a relevant code example.

---

## [Assignment#2: 🕵 Basic Process Monitor (🌽Kernel Mode)](./Assignments/02%20-%20Basic%20Process%20Monitor%20(Kernel%20Mode)/README.md)

Assignment#2: Basic Process Monitor (Kernel Mode)" section, the focus is on developing a Windows kernel driver, which is a software module that operates in the kernel mode of the Windows operating system. Kernel drivers have direct access to hardware resources and can execute privileged instructions. The provided code demonstrates a simple kernel driver structure with functions for driver entry and driver unload. The assignment tasks include writing a kernel driver that prints CPUID information and extending it to create a basic process monitor that logs processes being started using PsSetCreateProcessNotifyRoutine and PsSetNotifyLoadImageRoutine functions. The section also provides API documentation and a task list for the assignment deliverables.

---

## [Assignment#3: 🔗 User Mode System Monitor (Hooking)](./Assignments/03%20-%20User%20Mode%20System%20Monitor%20(Hooking)/README.md)

* Function API hooking is a technique to intercept function calls and redirect them to a custom implementation.
* In C, function API hooking can be implemented using techniques like inline assembly, function pointers, or dynamic code generation.
* The example provided demonstrates function API hooking using function pointers to replace the MessageBoxA function.
* Microsoft Detours is a library for intercepting and modifying API calls in Windows applications, commonly used for debugging and adding new functionality.


## Assignment#4: 🔐 Password and authentication credentials Attacks using Mimikatz

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
