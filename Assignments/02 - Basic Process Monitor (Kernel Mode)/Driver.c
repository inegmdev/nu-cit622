

#include <ntdef.h> // For: UNREFERENCED_PARAMETER
#include <ntifs.h> // For: PsLookupProcessByProcessId, SeLocateProcessImageName

#include <wdf.h> // For: EVT_WDF_DRIVER_DEVICE_ADD 
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KmdfHelloWorldEvtDeviceAdd;

#define PREFIX "[KernelMonitor] "
#define DBG_LOG(...) DbgPrint(PREFIX __VA_ARGS__)

NTSTATUS GetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImageName
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS processHandle = NULL;

    // Open the process
    status = PsLookupProcessByProcessId(ProcessId, &processHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Query the process image file name
    status = SeLocateProcessImageName(processHandle, &ImageName);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(processHandle);
        return status;
    }

    // Dereference the process handle
    ObDereferenceObject(processHandle);

    return status;
}


// Callback function for process creation notifications
VOID ProcessCreateCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);

    // Get the process and image file names
    UNICODE_STRING processName, imageName;
    if (NT_SUCCESS(GetProcessImageName(ProcessId, &processName)) &&
        NT_SUCCESS(GetProcessImageName(PsGetCurrentProcessId(), &imageName)))
    {
        // Print process creation or termination information
        if (Create)
        {
            DBG_LOG("Process created - ID: %lu, Parent ID: %lu\n", HandleToULong(ProcessId), HandleToULong(ParentId));
            DBG_LOG("Process Name: %wZ\n", &processName);
            DBG_LOG("Image Name: %wZ\n", &imageName);
        }
        else
        {
            DBG_LOG("Process terminated - ID: %lu\n", HandleToULong(ProcessId));
            DBG_LOG("Process Name: %wZ\n", &processName);
            DBG_LOG("Image Name: %wZ\n", &imageName);
        }
    }
}


// Callback function for image load notifications
VOID ImageLoadCallback(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    // Image loaded
    DBG_LOG("Image loaded - Path: %wZ\n", FullImageName);
    // Perform logging or other processing as needed
}

#define VAL(reg, bitIndex) ((reg >> bitIndex) & 0b1)

VOID vidPrintCpuid(VOID)
{
    int cpuInfo[4] = { 0 } ;
    __cpuid(cpuInfo, 1);

    DBG_LOG("CPUID Information:\n");

    /*
        Source: https://www.felixcloutier.com/x86/cpuid
    */

    // EAX register
    ULONG eax = cpuInfo[0];
    DBG_LOG("EAX: %08x\n", eax);
    DBG_LOG("  Maximum Input Value Supported: %08x\n", eax & 0xFFFF      );
    DBG_LOG("  Processor Signature: %08x\n",           (eax >> 16) & 0xFF);
    DBG_LOG("  Processor Type: %08x\n",                (eax >> 12) & 0x3 );
    DBG_LOG("  Family Identifier: %08x\n",             (eax >> 8) & 0xF  );
    DBG_LOG("  Model Identifier: %08x\n",              (eax >> 4) & 0xF  );
    DBG_LOG("  Stepping Identifier: %08x\n",           eax & 0xF         );

    // EBX register
    ULONG ebx = cpuInfo[1];
    DBG_LOG("EBX: %08x\n", ebx);
    DBG_LOG("  Brand Index: %08x\n" "    - this number provides an entry into a brand string table that contains brand strings for IA-32 processors.\n", ebx & 0xFF);

    // ECX register
    ULONG ecx = cpuInfo[2];
    DBG_LOG("ECX: %08x\n", ecx);
    DBG_LOG("  0   SSE3          (0x%01x) Streaming SIMD Extensions 3 (SSE3). \n"       "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 0));
    DBG_LOG("  1   PCLMULQDQ     (0x%01x) PCLMULQDQ. \n"                                "                 - 1: supports the PCLMULQDQ instruction.\n"                                                                                                                                                                                                                                                                                         , VAL(ecx, 1));
    DBG_LOG("  2   DTES64        (0x%01x) 64-bit DS Area. \n"                           "                 - 1: supports DS area using 64-bit layout.\n"                                                                                                                                                                                                                                                                                       , VAL(ecx, 2));
    DBG_LOG("  3   MONITOR       (0x%01x) MONITOR/MWAIT. \n"                            "                 - 1: supports this feature.\n"                                                                                                                                                                                                                                                                                                      , VAL(ecx, 3));
    DBG_LOG("  4   DS-CPL        (0x%01x) CPL Qualified Debug Store. \n"                "                 - 1: supports the extensions to the Debug Store feature to allow for branch message storage qualified by CPL.\n"                                                                                                                                                                                                                    , VAL(ecx, 4));
    DBG_LOG("  5   VMX           (0x%01x) Virtual Machine Extensions. \n"               "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 5));
    DBG_LOG("  6   SMX           (0x%01x) Safer Mode Extensions. \n"                    "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 6));
    DBG_LOG("  7   EIST          (0x%01x) Enhanced Intel SpeedStep® technology. \n"     "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 7));
    DBG_LOG("  8   TM2           (0x%01x) Thermal Monitor 2. \n"                        "                 - 1: whether supports this technology.\n"                                                                                                                                                                                                                                                                                           , VAL(ecx, 8));
    DBG_LOG("  9   SSSE3         (0x%01x) \n"                                           "                 - 1: the presence of the Supplemental Streaming SIMD Extensions 3 (SSSE3).\n"                                                                                                "                 - 0: the instruction extensions are not present in the processor.\n"                                                                 , VAL(ecx, 9));
    DBG_LOG("  10  CNXT-ID       (0x%01x) L1 Context ID. \n"                            "                 - 1: the L1 data cache mode can be set to either adaptive mode or shared mode.\n"                                                                                            "                 - 0: this feature is not supported. See definition of the IA32_MISC_ENABLE MSR Bit 24 (L1 Data Cache Context Mode) for details.\n"   , VAL(ecx, 10));
    DBG_LOG("  11  SDBG          (0x%01x) \n"                                           "                 - 1: supports IA32_DEBUG_INTERFACE MSR for silicon debug.\n"                                                                                                                                                                                                                                                                        , VAL(ecx, 11));
    DBG_LOG("  12  FMA           (0x%01x) \n"                                           "                 - 1: supports FMA extensions using YMM state.\n"                                                                                                                                                                                                                                                                                    , VAL(ecx, 12));
    DBG_LOG("  13  CMPXCHG16B    (0x%01x) CMPXCHG16B Available. \n"                     "                 - 1: that the feature is available.\n"                                                                                                                                                                                                                                                                                              , VAL(ecx, 13));
    DBG_LOG("  14  xTPR          (0x%01x) Update Control  xTPR Update Control. \n"      "                 - 1: supports changing IA32_MISC_ENABLE[bit 23].\n"                                                                                                                                                                                                                                                                                 , VAL(ecx, 14));
    DBG_LOG("  15  PDCM          (0x%01x) Perfmon and Debug Capability: \n"             "                 - 1: supports the performance and debug feature indication MSR IA32_PERF_CAPABILITIES.\n"                                                                                                                                                                                                                                           , VAL(ecx, 15));
    DBG_LOG("  16  Reserved      (0x%01x) .\n"                                                                                                                                                                                                                                                                                                                                                                                                , VAL(ecx, 16));            
    DBG_LOG("  17  PCID          (0x%01x) Process-context identifiers. \n"              "                 - 1: supports PCIDs and that software may set CR4.PCIDE to 1.\n"                                                                                                                                                                                                                                                                    , VAL(ecx, 17));
    DBG_LOG("  18  DCA           (0x%01x) \n"                                           "                 - 1: supports the ability to prefetch data from a memory mapped device.\n"                                                                                                                                                                                                                                                          , VAL(ecx, 18));
    DBG_LOG("  19  SSE4_1        (0x%01x) \n"                                           "                 - 1: supports SSE4.1.\n"                                                                                                                                                                                                                                                                                                            , VAL(ecx, 19));
    DBG_LOG("  20  SSE4_2        (0x%01x) \n"                                           "                 - 1: supports SSE4.2.\n"                                                                                                                                                                                                                                                                                                            , VAL(ecx, 20));
    DBG_LOG("  21  x2APIC        (0x%01x) \n"                                           "                 - 1: supports x2APIC feature.\n"                                                                                                                                                                                                                                                                                                    , VAL(ecx, 21));
    DBG_LOG("  22  MOVBE         (0x%01x) \n"                                           "                 - 1: supports MOVBE instruction.\n"                                                                                                                                                                                                                                                                                                 , VAL(ecx, 22));
    DBG_LOG("  23  POPCNT        (0x%01x) \n"                                           "                 - 1: supports the POPCNT instruction.\n"                                                                                                                                                                                                                                                                                            , VAL(ecx, 23));
    DBG_LOG("  24  TSC-Deadline  (0x%01x) \n"                                           "                 - 1: that the processor’s local APIC timer supports one-shot operation using a TSC deadline value.\n"                                                                                                                                                                                                                               , VAL(ecx, 24));
    DBG_LOG("  25  AESNI         (0x%01x) \n"                                           "                 - 1: supports the AESNI instruction extensions.\n"                                                                                                                                                                                                                                                                                  , VAL(ecx, 25));
    DBG_LOG("  26  XSAVE         (0x%01x) \n"                                           "                 - 1: supports the XSAVE/XRSTOR processor extended states feature, the XSETBV/XGETBV instructions, and XCR0.\n"                                                                                                                                                                                                                      , VAL(ecx, 26));
    DBG_LOG("  27  OSXSAVE       (0x%01x) \n"                                           "                 - 1: that the OS has set CR4.OSXSAVE[bit 18] to enable XSETBV/XGETBV instructions to access XCR0 and to support processor extended state management using XSAVE/XRSTOR.\n"                                                                                                                                                          , VAL(ecx, 27));
    DBG_LOG("  28  AVX           (0x%01x) \n"                                           "                 - 1: supports the AVX instruction extensions.\n"                                                                                                                                                                                                                                                                                    , VAL(ecx, 28));
    DBG_LOG("  29  F16C          (0x%01x) \n"                                           "                 - 1: that processor supports 16-bit floating-point conversion instructions.\n"                                                                                                                                                                                                                                                      , VAL(ecx, 29));
    DBG_LOG("  30  RDRAND        (0x%01x) \n"                                           "                 - 1: that processor supports RDRAND instruction.\n"                                                                                                                                                                                                                                                                                 , VAL(ecx, 30));
    DBG_LOG("  31  Not Used      (0x%01x) Always returns 0.\n", VAL(ecx, 31));

    // EDX register
    ULONG edx = cpuInfo[3];
    DBG_LOG("EDX: %08x\n", edx);
    DBG_LOG("  0   FPU   (0x%01x):(%s) Floating-Point Unit.\n",                      VAL(edx, 0),  (VAL(edx, 0))  ? "Present" : "Not Present");
    DBG_LOG("  1   VME   (0x%01x):(%s) Virtual 8086 Mode Enhancements.\n",           VAL(edx, 1),  (VAL(edx, 1))  ? "Present" : "Not Present");
    DBG_LOG("  2   DE    (0x%01x):(%s) Debugging Extensions.\n",                     VAL(edx, 2),  (VAL(edx, 2))  ? "Present" : "Not Present");
    DBG_LOG("  3   PSE   (0x%01x):(%s) Page Size Extensions.\n",                     VAL(edx, 3),  (VAL(edx, 3))  ? "Present" : "Not Present");
    DBG_LOG("  4   TSC   (0x%01x):(%s) Time Stamp Counter.\n",                       VAL(edx, 4),  (VAL(edx, 4))  ? "Present" : "Not Present");
    DBG_LOG("  5   MSR   (0x%01x):(%s) Model Specific Registers.\n",                 VAL(edx, 5),  (VAL(edx, 5))  ? "Present" : "Not Present");
    DBG_LOG("  6   PAE   (0x%01x):(%s) Physical Address Extension.\n",               VAL(edx, 6),  (VAL(edx, 6))  ? "Present" : "Not Present");
    DBG_LOG("  7   MCE   (0x%01x):(%s) Machine Check Exception.\n",                  VAL(edx, 7),  (VAL(edx, 7))  ? "Present" : "Not Present");
    DBG_LOG("  8   CX8   (0x%01x):(%s) CMPXCHG8 Instruction.\n",                     VAL(edx, 8),  (VAL(edx, 8))  ? "Present" : "Not Present");
    DBG_LOG("  9   APIC  (0x%01x):(%s) Onboard APIC Support.\n",                     VAL(edx, 9),  (VAL(edx, 9))  ? "Present" : "Not Present");
    DBG_LOG("  10  Reserved.\n");
    DBG_LOG("  11  SEP   (0x%01x):(%s) SYSENTER/SYSEXIT Instructions.\n",            VAL(edx, 11), (VAL(edx, 11)) ? "Present" : "Not Present");
    DBG_LOG("  12  MTRR  (0x%01x):(%s) Memory Type Range Registers.\n",              VAL(edx, 12), (VAL(edx, 12)) ? "Present" : "Not Present");
    DBG_LOG("  13  PGE   (0x%01x):(%s) Page Global Enable.\n",                       VAL(edx, 13), (VAL(edx, 13)) ? "Present" : "Not Present");
    DBG_LOG("  14  MCA   (0x%01x):(%s) Machine Check Architecture.\n",               VAL(edx, 14), (VAL(edx, 14)) ? "Present" : "Not Present");
    DBG_LOG("  15  CMOV  (0x%01x):(%s) Conditional Move Instructions Supported.\n",  VAL(edx, 15), (VAL(edx, 15)) ? "Present" : "Not Present");
    DBG_LOG("  16  PAT   (0x%01x):(%s) Page Attribute Table.\n",                     VAL(edx, 16), (VAL(edx, 16)) ? "Present" : "Not Present");
    DBG_LOG("  17  PSE36 (0x%01x):(%s) 36-Bit Page Size Extensions.\n",              VAL(edx, 17), (VAL(edx, 17)) ? "Present" : "Not Present");
    DBG_LOG("  18  PSN   (0x%01x):(%s) Processor Serial Number.\n",                  VAL(edx, 18), (VAL(edx, 18)) ? "Present" : "Not Present");
    DBG_LOG("  19  CLFSH (0x%01x):(%s) CLFLUSH Instruction Supported.\n",            VAL(edx, 19), (VAL(edx, 19)) ? "Present" : "Not Present");
    DBG_LOG("  20  Reserved.\n");
    DBG_LOG("  21  DS    (0x%01x):(%s) Debug Store.\n",                              VAL(edx, 21), (VAL(edx, 21)) ? "Present" : "Not Present");
    DBG_LOG("  22  ACPI  (0x%01x):(%s) ACPI Support.\n",                             VAL(edx, 22), (VAL(edx, 22)) ? "Present" : "Not Present");
    DBG_LOG("  23  MMX   (0x%01x):(%s) MultiMedia Extensions.\n",                    VAL(edx, 23), (VAL(edx, 23)) ? "Present" : "Not Present");
    DBG_LOG("  24  FXSR  (0x%01x):(%s) FXSAVE/FXRSTOR Instructions Supported.\n",    VAL(edx, 24), (VAL(edx, 24)) ? "Present" : "Not Present");
    DBG_LOG("  25  SSE   (0x%01x):(%s) Streaming SIMD Extensions.\n",                VAL(edx, 25), (VAL(edx, 25)) ? "Present" : "Not Present");
    DBG_LOG("  26  SSE2  (0x%01x):(%s) SSE2 extensions.\n",                          VAL(edx, 26), (VAL(edx, 26)) ? "Present" : "Not Present");
    DBG_LOG("  27  SS    (0x%01x):(%s) Self Snoop.\n",                               VAL(edx, 27), (VAL(edx, 27)) ? "Present" : "Not Present");
    DBG_LOG("  28  HTT   (0x%01x):(%s) Max APIC IDs reserved field is Valid.\n"
             "                          - 0: indicates there is only a single logical processor in the package and software should assume only a single APIC ID is reserved.\n"
             "                          - 1: indicates the value in CPUID.1.EBX[23:16] (the Maximum number of addressable IDs for logical processors in this package) is valid for the package.\n"
             , VAL(edx, 28), (VAL(edx, 28)) ? "Mutliple" : "Single");
    DBG_LOG("  29  TM    (0x%01x):(%s) Thermal Monitor.\n",                          VAL(edx, 29), (VAL(edx, 29)) ? "Present" : "Not Present");
    DBG_LOG("  30  Reserved.\n");
    DBG_LOG("  31  PBE   (0x%01x):(%s) Pending Break Enable.\n",                     VAL(edx, 31), (VAL(edx, 31)) ? "Present" : "Not Present");

}


VOID DriverUnload(PDRIVER_OBJECT driver)
{
    // Perform driver cleanup tasks
    UNREFERENCED_PARAMETER(driver);
    // Print a message to the kernel debugger
    DBG_LOG("DriverUnload called\n");
    // Unregister process creation callback
    PsSetCreateProcessNotifyRoutine(ProcessCreateCallback, TRUE);
    // Unregister image load callback
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    DBG_LOG("Callbacks has been removed.\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    // Print a message to the kernel debugger
    DBG_LOG("DriverEntry called\n");

    // Register the unload function
    driver->DriverUnload = DriverUnload;

    // Perform CPUID and print the information
    vidPrintCpuid();

    // Register process creation callback
    PsSetCreateProcessNotifyRoutine(ProcessCreateCallback, FALSE);

    // Register image load callback
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    return STATUS_SUCCESS;
}

