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

#define VAL(reg, bitIndex) ((reg >> bitIndex) & 0b1)

VOID vidPrintCpuid(VOID)
{
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    DbgPrint("CPUID Information:\n");

    /*
        Source: https://www.felixcloutier.com/x86/cpuid
    */

    // EAX register
    ULONG eax = cpuInfo[0];
    DbgPrint("EAX: %08x\n", eax);
    DbgPrint("  Maximum Input Value Supported: %08x\n", eax & 0xFFFF      );
    DbgPrint("  Processor Signature: %08x\n",           (eax >> 16) & 0xFF);
    DbgPrint("  Processor Type: %08x\n",                (eax >> 12) & 0x3 );
    DbgPrint("  Family Identifier: %08x\n",             (eax >> 8) & 0xF  );
    DbgPrint("  Model Identifier: %08x\n",              (eax >> 4) & 0xF  );
    DbgPrint("  Stepping Identifier: %08x\n",           eax & 0xF         );

    // EBX register
    ULONG ebx = cpuInfo[1];
    DbgPrint("EBX: %08x\n", ebx);
    DbgPrint("  Brand Index: %08x\n" "    - this number provides an entry into a brand string table that contains brand strings for IA-32 processors.\n", ebx & 0xFF);

    // ECX register
    ULONG ecx = cpuInfo[2];
    DbgPrint("ECX: %08x\n", ecx);
    DbgPrint("  0   SSE3          (0x%01x) Streaming SIMD Extensions 3 (SSE3). \n"       "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 0));
    DbgPrint("  1   PCLMULQDQ     (0x%01x) PCLMULQDQ. \n"                                "                 - 1: supports the PCLMULQDQ instruction.\n"                                                                                                                                                                                                                                                                                         , VAL(ecx, 1));
    DbgPrint("  2   DTES64        (0x%01x) 64-bit DS Area. \n"                           "                 - 1: supports DS area using 64-bit layout.\n"                                                                                                                                                                                                                                                                                       , VAL(ecx, 2));
    DbgPrint("  3   MONITOR       (0x%01x) MONITOR/MWAIT. \n"                            "                 - 1: supports this feature.\n"                                                                                                                                                                                                                                                                                                      , VAL(ecx, 3));
    DbgPrint("  4   DS-CPL        (0x%01x) CPL Qualified Debug Store. \n"                "                 - 1: supports the extensions to the Debug Store feature to allow for branch message storage qualified by CPL.\n"                                                                                                                                                                                                                    , VAL(ecx, 4));
    DbgPrint("  5   VMX           (0x%01x) Virtual Machine Extensions. \n"               "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 5));
    DbgPrint("  6   SMX           (0x%01x) Safer Mode Extensions. \n"                    "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 6));
    DbgPrint("  7   EIST          (0x%01x) Enhanced Intel SpeedStep® technology. \n"     "                 - 1: supports this technology.\n"                                                                                                                                                                                                                                                                                                   , VAL(ecx, 7));
    DbgPrint("  8   TM2           (0x%01x) Thermal Monitor 2. \n"                        "                 - 1: whether supports this technology.\n"                                                                                                                                                                                                                                                                                           , VAL(ecx, 8));
    DbgPrint("  9   SSSE3         (0x%01x) \n"                                           "                 - 1: the presence of the Supplemental Streaming SIMD Extensions 3 (SSSE3).\n"                                                                                                "                 - 0: the instruction extensions are not present in the processor.\n"                                                                 , VAL(ecx, 9));
    DbgPrint("  10  CNXT-ID       (0x%01x) L1 Context ID. \n"                            "                 - 1: the L1 data cache mode can be set to either adaptive mode or shared mode.\n"                                                                                            "                 - 0: this feature is not supported. See definition of the IA32_MISC_ENABLE MSR Bit 24 (L1 Data Cache Context Mode) for details.\n"   , VAL(ecx, 10));
    DbgPrint("  11  SDBG          (0x%01x) \n"                                           "                 - 1: supports IA32_DEBUG_INTERFACE MSR for silicon debug.\n"                                                                                                                                                                                                                                                                        , VAL(ecx, 11));
    DbgPrint("  12  FMA           (0x%01x) \n"                                           "                 - 1: supports FMA extensions using YMM state.\n"                                                                                                                                                                                                                                                                                    , VAL(ecx, 12));
    DbgPrint("  13  CMPXCHG16B    (0x%01x) CMPXCHG16B Available. \n"                     "                 - 1: that the feature is available.\n"                                                                                                                                                                                                                                                                                              , VAL(ecx, 13));
    DbgPrint("  14  xTPR          (0x%01x) Update Control  xTPR Update Control. \n"      "                 - 1: supports changing IA32_MISC_ENABLE[bit 23].\n"                                                                                                                                                                                                                                                                                 , VAL(ecx, 14));
    DbgPrint("  15  PDCM          (0x%01x) Perfmon and Debug Capability: \n"             "                 - 1: supports the performance and debug feature indication MSR IA32_PERF_CAPABILITIES.\n"                                                                                                                                                                                                                                           , VAL(ecx, 15));
    DbgPrint("  16  Reserved      (0x%01x) .\n"                                                                                                                                                                                                                                                                                                                                                                                                , VAL(ecx, 16));            
    DbgPrint("  17  PCID          (0x%01x) Process-context identifiers. \n"              "                 - 1: supports PCIDs and that software may set CR4.PCIDE to 1.\n"                                                                                                                                                                                                                                                                    , VAL(ecx, 17));
    DbgPrint("  18  DCA           (0x%01x) \n"                                           "                 - 1: supports the ability to prefetch data from a memory mapped device.\n"                                                                                                                                                                                                                                                          , VAL(ecx, 18));
    DbgPrint("  19  SSE4_1        (0x%01x) \n"                                           "                 - 1: supports SSE4.1.\n"                                                                                                                                                                                                                                                                                                            , VAL(ecx, 19));
    DbgPrint("  20  SSE4_2        (0x%01x) \n"                                           "                 - 1: supports SSE4.2.\n"                                                                                                                                                                                                                                                                                                            , VAL(ecx, 20));
    DbgPrint("  21  x2APIC        (0x%01x) \n"                                           "                 - 1: supports x2APIC feature.\n"                                                                                                                                                                                                                                                                                                    , VAL(ecx, 21));
    DbgPrint("  22  MOVBE         (0x%01x) \n"                                           "                 - 1: supports MOVBE instruction.\n"                                                                                                                                                                                                                                                                                                 , VAL(ecx, 22));
    DbgPrint("  23  POPCNT        (0x%01x) \n"                                           "                 - 1: supports the POPCNT instruction.\n"                                                                                                                                                                                                                                                                                            , VAL(ecx, 23));
    DbgPrint("  24  TSC-Deadline  (0x%01x) \n"                                           "                 - 1: that the processor’s local APIC timer supports one-shot operation using a TSC deadline value.\n"                                                                                                                                                                                                                               , VAL(ecx, 24));
    DbgPrint("  25  AESNI         (0x%01x) \n"                                           "                 - 1: supports the AESNI instruction extensions.\n"                                                                                                                                                                                                                                                                                  , VAL(ecx, 25));
    DbgPrint("  26  XSAVE         (0x%01x) \n"                                           "                 - 1: supports the XSAVE/XRSTOR processor extended states feature, the XSETBV/XGETBV instructions, and XCR0.\n"                                                                                                                                                                                                                      , VAL(ecx, 26));
    DbgPrint("  27  OSXSAVE       (0x%01x) \n"                                           "                 - 1: that the OS has set CR4.OSXSAVE[bit 18] to enable XSETBV/XGETBV instructions to access XCR0 and to support processor extended state management using XSAVE/XRSTOR.\n"                                                                                                                                                          , VAL(ecx, 27));
    DbgPrint("  28  AVX           (0x%01x) \n"                                           "                 - 1: supports the AVX instruction extensions.\n"                                                                                                                                                                                                                                                                                    , VAL(ecx, 28));
    DbgPrint("  29  F16C          (0x%01x) \n"                                           "                 - 1: that processor supports 16-bit floating-point conversion instructions.\n"                                                                                                                                                                                                                                                      , VAL(ecx, 29));
    DbgPrint("  30  RDRAND        (0x%01x) \n"                                           "                 - 1: that processor supports RDRAND instruction.\n"                                                                                                                                                                                                                                                                                 , VAL(ecx, 30));
    DbgPrint("  31  Not Used      (0x%01x) Always returns 0.\n", VAL(ecx, 31));

    // EDX register
    ULONG edx = cpuInfo[3];
    DbgPrint("EDX: %08x\n", edx);
    DbgPrint("  0   FPU   (0x%01x):(%s) Floating-Point Unit.\n",                      VAL(edx, 0),  (VAL(edx, 0))  ? "Present" : "Not Present");
    DbgPrint("  1   VME   (0x%01x):(%s) Virtual 8086 Mode Enhancements.\n",           VAL(edx, 1),  (VAL(edx, 1))  ? "Present" : "Not Present");
    DbgPrint("  2   DE    (0x%01x):(%s) Debugging Extensions.\n",                     VAL(edx, 2),  (VAL(edx, 2))  ? "Present" : "Not Present");
    DbgPrint("  3   PSE   (0x%01x):(%s) Page Size Extensions.\n",                     VAL(edx, 3),  (VAL(edx, 3))  ? "Present" : "Not Present");
    DbgPrint("  4   TSC   (0x%01x):(%s) Time Stamp Counter.\n",                       VAL(edx, 4),  (VAL(edx, 4))  ? "Present" : "Not Present");
    DbgPrint("  5   MSR   (0x%01x):(%s) Model Specific Registers.\n",                 VAL(edx, 5),  (VAL(edx, 5))  ? "Present" : "Not Present");
    DbgPrint("  6   PAE   (0x%01x):(%s) Physical Address Extension.\n",               VAL(edx, 6),  (VAL(edx, 6))  ? "Present" : "Not Present");
    DbgPrint("  7   MCE   (0x%01x):(%s) Machine Check Exception.\n",                  VAL(edx, 7),  (VAL(edx, 7))  ? "Present" : "Not Present");
    DbgPrint("  8   CX8   (0x%01x):(%s) CMPXCHG8 Instruction.\n",                     VAL(edx, 8),  (VAL(edx, 8))  ? "Present" : "Not Present");
    DbgPrint("  9   APIC  (0x%01x):(%s) Onboard APIC Support.\n",                     VAL(edx, 9),  (VAL(edx, 9))  ? "Present" : "Not Present");
    DbgPrint("  10  Reserved.\n");
    DbgPrint("  11  SEP   (0x%01x):(%s) SYSENTER/SYSEXIT Instructions.\n",            VAL(edx, 11), (VAL(edx, 11)) ? "Present" : "Not Present");
    DbgPrint("  12  MTRR  (0x%01x):(%s) Memory Type Range Registers.\n",              VAL(edx, 12), (VAL(edx, 12)) ? "Present" : "Not Present");
    DbgPrint("  13  PGE   (0x%01x):(%s) Page Global Enable.\n",                       VAL(edx, 13), (VAL(edx, 13)) ? "Present" : "Not Present");
    DbgPrint("  14  MCA   (0x%01x):(%s) Machine Check Architecture.\n",               VAL(edx, 14), (VAL(edx, 14)) ? "Present" : "Not Present");
    DbgPrint("  15  CMOV  (0x%01x):(%s) Conditional Move Instructions Supported.\n",  VAL(edx, 15), (VAL(edx, 15)) ? "Present" : "Not Present");
    DbgPrint("  16  PAT   (0x%01x):(%s) Page Attribute Table.\n",                     VAL(edx, 16), (VAL(edx, 16)) ? "Present" : "Not Present");
    DbgPrint("  17  PSE36 (0x%01x):(%s) 36-Bit Page Size Extensions.\n",              VAL(edx, 17), (VAL(edx, 17)) ? "Present" : "Not Present");
    DbgPrint("  18  PSN   (0x%01x):(%s) Processor Serial Number.\n",                  VAL(edx, 18), (VAL(edx, 18)) ? "Present" : "Not Present");
    DbgPrint("  19  CLFSH (0x%01x):(%s) CLFLUSH Instruction Supported.\n",            VAL(edx, 19), (VAL(edx, 19)) ? "Present" : "Not Present");
    DbgPrint("  20  Reserved.\n");
    DbgPrint("  21  DS    (0x%01x):(%s) Debug Store.\n",                              VAL(edx, 21), (VAL(edx, 21)) ? "Present" : "Not Present");
    DbgPrint("  22  ACPI  (0x%01x):(%s) ACPI Support.\n",                             VAL(edx, 22), (VAL(edx, 22)) ? "Present" : "Not Present");
    DbgPrint("  23  MMX   (0x%01x):(%s) MultiMedia Extensions.\n",                    VAL(edx, 23), (VAL(edx, 23)) ? "Present" : "Not Present");
    DbgPrint("  24  FXSR  (0x%01x):(%s) FXSAVE/FXRSTOR Instructions Supported.\n",    VAL(edx, 24), (VAL(edx, 24)) ? "Present" : "Not Present");
    DbgPrint("  25  SSE   (0x%01x):(%s) Streaming SIMD Extensions.\n",                VAL(edx, 25), (VAL(edx, 25)) ? "Present" : "Not Present");
    DbgPrint("  26  SSE2  (0x%01x):(%s) SSE2 extensions.\n",                          VAL(edx, 26), (VAL(edx, 26)) ? "Present" : "Not Present");
    DbgPrint("  27  SS    (0x%01x):(%s) Self Snoop.\n",                               VAL(edx, 27), (VAL(edx, 27)) ? "Present" : "Not Present");
    DbgPrint("  28  HTT   (0x%01x):(%s) Max APIC IDs reserved field is Valid.\n"
             "                          - 0: indicates there is only a single logical processor in the package and software should assume only a single APIC ID is reserved.\n"
             "                          - 1: indicates the value in CPUID.1.EBX[23:16] (the Maximum number of addressable IDs for logical processors in this package) is valid for the package.\n"
             , VAL(edx, 28), (VAL(edx, 28)) ? "Mutliple" : "Single");
    DbgPrint("  29  TM    (0x%01x):(%s) Thermal Monitor.\n",                          VAL(edx, 29), (VAL(edx, 29)) ? "Present" : "Not Present");
    DbgPrint("  30  Reserved.\n");
    DbgPrint("  31  PBE   (0x%01x):(%s) Pending Break Enable.\n",                     VAL(edx, 31), (VAL(edx, 31)) ? "Present" : "Not Present");

}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    // Print a message to the kernel debugger
    DbgPrint("DriverEntry called\n");

    // Register the unload function
    driver->DriverUnload = DriverUnload;

#if 1 
    // Perform CPUID and print the information
    vidPrintCpuid();
#endif

    return STATUS_SUCCESS;
}

