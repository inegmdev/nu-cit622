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
  * GetFullPathName
  * GetStartupInfo
  * OpenProcess
* **FileSystem API**
  * CreateFile
  * DeleteFile
  * CreateDirectoryEx
* **Registry API**
  * RegDeleteKey
  * RegCloseKey
  * RegEnumKeyEx
  * RegEnumValue
  * RegOpenKeyEx
  * RegSetValueEx
  * RegSetValue

Once you are hooking APIs, your program should print the function called, args/params

### Helper resources

* API documentation - [https://github.com/microsoft/Detours](https://github.com/microsoft/Detours).

### Deliverables

* The C/C++ sources for process parsing/dumping
* Screenshot your program running in command line and output the various fucntion args/params.

## 📃 Tasklist

* [ ] Integrate Detours in the solution and use one API.
* [ ] Repeat the same thing for all of the APIs.
* [ ] Find a quick way to log/print to be able to capture and monitor all the APIs.

## Resources

* [inegmdev/detoury: Detoury is a monitoring and instrumenting wrapper layer based on Microsoft Detours (github.com)](https://github.com/inegmdev/detoury)
