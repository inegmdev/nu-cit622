// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>

#include "Logger.h"
#include "detours.h"
#include <shellapi.h>
/*****************************************************************************/
/*                             GLOBAL VARIABLES                              */
/*****************************************************************************/
Logger logger;

/*****************************************************************************/
/*                             HELPER FUNCTIONS                              */
/*****************************************************************************/

/* Needed to be used so that the dll library can be used with `withdll` */
__declspec(dllexport) void ordinal_1() {}

/*****************************************************************************/
/*                                  HOOKS                                    */
/*****************************************************************************/
#include "Hooks.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    LONG error;
    std::string s;
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        /* Logger Initialization */
        logger.init();
        Log("\"Started logging\"");

        /* Microsoft Detours Initialization */
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach_AllHooks();
        error = DetourTransactionCommit();
        if (error == NO_ERROR) {
            Log("\"Detoury successfully hooked the functions.\"");
        }
        else {
            Log("\"[ERROR] Detoury failed to hook the functions, returns {}.\"", error);
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        logger.deinit();
        break;
    }
    return TRUE;
}

