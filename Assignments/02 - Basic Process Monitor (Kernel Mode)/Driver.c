#include <ntddk.h>
#include <wdf.h>
#include <ntdef.h> // For: UNREFERENCED_PARAMETER

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KmdfHelloWorldEvtDeviceAdd;


VOID DriverUnload(PDRIVER_OBJECT driver)
{
    // Perform driver cleanup tasks
    UNREFERENCED_PARAMETER(driver);

    // Print a message to the kernel debugger
    DbgPrint("DriverUnload called\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    // Print a message to the kernel debugger
    DbgPrint("DriverEntry called\n");

    // Register the unload function
    driver->DriverUnload = DriverUnload;


    // Perform CPUID and print the information
    int info[4] = { 0 };
    __cpuid(info, 0);

    DbgPrint("CPUID Information:\n");
    DbgPrint("EAX: 0x%X\n", info[0]);
    DbgPrint("EBX: 0x%X\n", info[1]);
    DbgPrint("ECX: 0x%X\n", info[2]);
    DbgPrint("EDX: 0x%X\n", info[3]);

    return STATUS_SUCCESS;
}

