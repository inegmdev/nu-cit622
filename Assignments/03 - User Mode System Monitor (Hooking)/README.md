# Assignment#2: 🕵 User Mode System Monitor (Hooking)

## Introduction

### **What is API hooking?**

**Function API hooking** is a technique used in software development to intercept function calls made by a program and redirect them to a custom implementation. This technique can be used for a variety of purposes, such as debugging, instrumentation, or adding new functionality to an application. **To implement function API hooking in C** , you typically need to modify the target function to redirect its execution flow to a custom implementation. This can be achieved using various techniques, such as inline assembly, function pointers, or dynamic code generation.

### **Example on API hooking**

**Here is a simple example of function API hooking in C using the function pointer technique:**

```cpp
#include <stdio.h>
#include <windows.h>

// Define a function pointer type for the original MessageBoxA function
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

// Define a custom implementation of the MessageBoxA function
int WINAPI MyMessageBoxA
(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    // Print a message before calling the original function
    printf("Calling MyMessageBoxA\n");
    // Call the original function using the function pointer
    MESSAGEBOXA pMessageBoxA = (MESSAGEBOXA)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    int result = pMessageBoxA(hWnd, lpText, lpCaption, uType);
     // Print a message after calling the original function
     printf("Returned from MyMessageBoxA\n");
     return result;
}

int main () {
    // Replace the original MessageBoxA function with the custom implementation
    HMODULE hModule = GetModuleHandleA("user32.dll");
    DWORD dwOldProtect, dwNewProtect;
    MESSAGEBOXA pOriginalMessageBoxA = (MESSAGEBOXA)GetProcAddress(hModule, "MessageBoxA");
    VirtualProtect(pOriginalMessageBoxA, sizeof(MESSAGEBOXA), PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pOriginalMessageBoxA = (MESSAGEBOXA)InterlockedExchange((LONG*)&pOriginalMessageBoxA, (LONG)MyMessageBoxA);
    VirtualProtect(pOriginalMessageBoxA, sizeof(MESSAGEBOXA), dwOldProtect, &dwNewProtect);

    // Call the MessageBoxA function and observe the output
    MessageBoxA(NULL, "Hello, world!", "MyMessageBoxA", MB_OK);
    return 0;
}


```

**In this example** , we define a function pointer type for the original MessageBoxA function, and a custom implementation of the function called MyMessageBoxA. We then replace the original MessageBoxA function with the custom implementation using the InterlockedExchange function, which atomically replaces the function pointer in memory.

When the program calls the MessageBoxA function, the custom implementation is called instead, which prints a message before and after calling the original MessageBoxA function. This allows us to observe the behavior of the function and modify its behavior if necessary.

### Microsfot Detours

**Detours** ([https://github.com/microsoft/Detours](https://github.com/microsoft/Detours)) is a software library for Microsoft Windows that enables developers to intercept system and user-mode API calls and modify their behavior. It works by modifying the in-memory code of a running application to redirect API calls to a custom implementation. This can be useful for a variety of purposes, such as debugging, profiling, or adding new functionality to an application.

Detours can be used by developers to intercept API calls made by any user-mode process, and redirect them to a custom implementation. The library provides a simple and flexible API that allows developers to specify which APIs to intercept, and how they should be redirected.

Detours is widely used by developers in a variety of industries, including video game development, security research, and application performance optimization. It is also used by Microsoft internally for a variety of purposes, such as testing and development of new operating system features.

### What is expected in the assignment?

**Using Detours, hooking the following API:**

* **Process API**
  * ShellExecuteA
  * CreateProcessAsUser
  * ExitProcess
  * GetCommandLine
  * GetFullPathName - x
  * GetStartupInfo
  * OpenProcess
* **FileSystem API**
  * CreateFile
  * DeleteFile
  * CreateDirectoryEx - x
* **Registry API**
  * RegDeleteKey
  * RegCloseKey
  * RegEnumKeyEx - x
  * RegEnumValue - x
  * RegOpenKeyEx - x
  * RegSetValueEx - x
  * RegSetValue

Once you are hooking APIs, your program should print the function called, args/params

### Helper resources

* API documentation - [https://github.com/microsoft/Detours](https://github.com/microsoft/Detours).

### Deliverables

* The C/C++ sources for process parsing/dumping
* Screenshot your program running in command line and output the various fucntion args/params.

## 📃 Tasklist

* [x] Integrate Detours in the solution and use one API.
* [ ] Repeat the same thing for all of the APIs.
  * [x] **Process API**
    * [x] ShellExecuteA, ShellExecuteW
    * [x] CreateProcessAsUserA, CreateProcessAsUserW
    * [x] ExitProcess
    * [x] GetCommandLineA, GetCommandLineW
    * [x] GetStartupInfoW
    * [x] OpenProcess
  * [x] **FileSystem API**
    * [x] GetFullPathNameA, GetFullPathNameW
    * [x] CreateFileA, CreateFileW
    * [x] DeleteFileA, DeleteFileW
    * [x] CreateDirectoryExA, CreateDirectoryExW
  * [ ] **Registry API**
    * [x] RegDeleteKeyA, RegDeleteKeyW
    * [x] RegCloseKey
    * [x] RegEnumKeyExA, RegEnumKeyExW
    * [x] RegEnumValueA, RegEnumValueW
    * [ ] RegOpenKeyEx - x
    * [ ] RegSetValueEx - x
    * [ ] RegSetValue
* [x] Find a quick way to log/print to be able to capture and monitor all the APIs.

## Notes

### How to build MS Detours

*From source [REF_DETOURS_BUILD]*

You need to build a version of `detours.lib` for your C/C++ compiler. The steps to build detours are:

1. [Initialize the Microsoft C++ toolset command line environment](https://docs.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=vs-2019) for the architecture you are targeting.

   1. Identify where is your MS Visusal Studio BAT file for developer CLI, for example I have it here `C:\Program Files\Microsoft Visual Studio\2022\Community` .
   2. Under `\VC\Auxiliary\Build\` you will find `vcvars64.bat` file that you should trigger to setup the CMD env for 64.
      *Note: There's also a file for 32-bit environments.*
   3. Git checkout `v4.0.1` tag in Detours.
   4. Go back to Detours folder and open `cmd.exe` and then right the following command
      ```batch
      Detours> cd src
      Detours/src> "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

      **********************************************************************
      ** Visual Studio 2022 Developer Command Prompt v17.6.2
      ** Copyright (c) 2022 Microsoft Corporation
      **********************************************************************
      [vcvarsall.bat] Environment initialized for: 'x64'

      Detours/src> SET DETOURS_TARGET_PROCESSOR=X64
      Detours/src> nmake
      Detours/src> SET DETOURS_TARGET_PROCESSOR=X86
      Detours/src> nmake
      ```
2. Run with [`nmake`](https://docs.microsoft.com/en-us/cpp/build/reference/running-nmake)
   a. To build just the detours library, change to the `detours/src` directory and run the `nmake` command.
   b. To build detours and the samples, change to the `detours` directory and run the `nmake` command.
3. A `lib.<ARCH>` directory should now exist, containing the Detours static library, where `<ARCH>` is the target architecture you are compiling for. The `include` directory will also be generated during the build, it contains the headers for the library.

   > C:\detours> dir /b *.x64
   > bin.X64
   > lib.X64
   >
   > C:\detours> dir /b lib.X64
   > detours.lib
   > detours.pdb
   > syelog.lib
   >
   > C:\detours> dir /b include
   > detours.h
   > detver.h
   > syelog.h
   >

## Resources

1. [inegmdev/detoury: Detoury is a monitoring and instrumenting wrapper layer based on Microsoft Detours (github.com)](https://github.com/inegmdev/detoury)
2. [REF_DETOURS_BUILD] [FAQ · microsoft/Detours Wiki (github.com)](https://github.com/microsoft/detours/wiki/FAQ#compiling-with-detours-code)
