#pragma once
#define UMDF_USING_NTSTATUS
#include <ntstatus.h>
#include "structs.hpp"

#define DEBUG_PRINT

#ifdef DEBUG_PRINT

#define dprintf(...) wprintf(__VA_ARGS__)

#else

#define dprintf(...) do{}while(0);

#endif // DEBUG_PRINT

void Fastmemcpy(void* dest, void* src, int size);

#define HandleToULong( h ) ((ULONG)(ULONG_PTR)(h) )
#define HandleToLong( h )  ((LONG)(LONG_PTR) (h) )
#define ULongToHandle( ul ) ((HANDLE)(ULONG_PTR) (ul) )
#define LongToHandle( h )   ((HANDLE)(LONG_PTR) (h) )
#define PtrToUlong( p ) ((ULONG)(ULONG_PTR) (p) )
#define PtrToLong( p )  ((LONG)(LONG_PTR) (p) )
#define PtrToUint( p ) ((UINT)(UINT_PTR) (p) )
#define PtrToInt( p )  ((INT)(INT_PTR) (p) )
#define PtrToUshort( p ) ((unsigned short)(ULONG_PTR)(p) )
#define PtrToShort( p )  ((short)(LONG_PTR)(p) )
#define IntToPtr( i )    ((VOID *)(INT_PTR)((int)i))
#define UIntToPtr( ui )  ((VOID *)(UINT_PTR)((unsigned int)ui))
#define LongToPtr( l )   ((VOID *)(LONG_PTR)((long)l))
#define ULongToPtr( ul ) ((VOID *)(ULONG_PTR)((unsigned long)ul))

#define ULongToPeb32Ptr( ul ) ((PPEB32)(ULONG_PTR)((unsigned long)ul))

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlProcessHeap() (NtCurrentPeb()->ProcessHeap)
#define DefaultComSpecPath L"\\system32\\cmd.exe"
#define DefaultComSpecPathStringCount (sizeof(DefaultComSpecPath) - sizeof(UNICODE_NULL)) / sizeof(WCHAR)
// Windows 8 and above
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())

#define KI_USER_SHARED_DATA 0x7FFE0000
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)

EXTERN_C NTSYSAPI PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
EXTERN_C NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);

EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlInitUnicodeStringEx(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString);
EXTERN_C NTSYSAPI VOID NTAPI RtlInitUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);

EXTERN_C NTSTATUS NTAPI RtlCreateProcessParametersEx(
	_Out_ PRTL_USER_PROCESS_PARAMETERS * pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags
);

NTSTATUS CallCsrss(HANDLE hProcess, HANDLE hThread, PS_CREATE_INFO CreateInfo, UNICODE_STRING Win32ImagePath, UNICODE_STRING NtImagePath, CLIENT_ID ClientId, SECTION_IMAGE_INFORMATION SectionImageInfomation);