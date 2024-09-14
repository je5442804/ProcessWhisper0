#include <iostream>
#include "ntapi.hpp"
#include "otherapi.hpp"

using namespace std;

// No Console Process Create "Console SubSystem" Process without conhost.exe
// int wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
int wmain(int argc, wchar_t* argv[])
{
	wstring ImageName;
	if (argc == 2)
	{
		ImageName = argv[1];
	}
	else
	{
		ImageName = L"C:\\Windows\\Microsoft.NET\\Framework64\\v3.0\\Windows Communication Foundation\\SMConfigInstaller.exe";
		wprintf(L"[*] Default: %ls\n", ImageName.c_str());
	}
	
	NTSTATUS Status = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID ClientId = { 0 };

	UNICODE_STRING currentDirectory;
	RtlInitUnicodeStringEx(&currentDirectory, L"C:\\Windows\\System32\\");

	UNICODE_STRING commandLine;
	RtlInitUnicodeStringEx(&commandLine, ImageName.c_str());// L"C:\\Windows\\System32\\WerFault.exe"

	UNICODE_STRING imagePathName;
	RtlInitUnicodeStringEx(&imagePathName, ImageName.c_str());// L"C:\\Windows\\System32\\WerFault.exe"

	UNICODE_STRING NtPath = { 0 };
	wstring NtImageName = L"\\??\\";
	NtImageName += ImageName;
	RtlInitUnicodeStringEx(&NtPath, NtImageName.c_str());// L"C:\\Windows\\System32\\WerFault.exe"

	PS_CREATE_INFO CreateInfo = { 0 };
	RtlSecureZeroMemory(&CreateInfo, sizeof(PS_CREATE_INFO));
	CreateInfo.State = PsCreateInitialState;
	CreateInfo.Size = sizeof(PS_CREATE_INFO);
	CreateInfo.InitState.u1.s1.WriteOutputOnExit = TRUE;
	CreateInfo.InitState.u1.s1.DetectManifest = TRUE;
	CreateInfo.InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;
	//CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics = IMAGE_FILE_DLL; lol

	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;

	Status = RtlCreateProcessParametersEx(
		&ProcessParameters,
		&imagePathName,
		NULL,                        // Create a new DLL path
		&currentDirectory,
		&commandLine,
		NULL,                        // If null, a new environment will be created
		&imagePathName,                  // Window title is the exe path - needed for console apps
		&NtCurrentPeb()->ProcessParameters->DesktopInfo, // Copy our desktop name
		NULL,
		NULL,
		RTL_USER_PROCESS_PARAMETERS_NORMALIZED
	);

	ProcessParameters->ConsoleHandle = HANDLE_DETACHED_PROCESS;

	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] RtlCreateProcessParametersEx Failed: 0x%08x\n", Status);
		return Status;
	}

	SECTION_IMAGE_INFORMATION SectionImageInfomation = { 0 };
	ULONG AttributeListCount = 3;
	SIZE_T TotalLength = AttributeListCount * sizeof(PS_ATTRIBUTE) + sizeof(SIZE_T);
	PS_ATTRIBUTE_LIST AttributeList;

	RtlSecureZeroMemory(&AttributeList, sizeof(PS_ATTRIBUTE_LIST));
	AttributeList.TotalLength = TotalLength;

	AttributeList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
	AttributeList.Attributes[0].Size = NtPath.Length;
	AttributeList.Attributes[0].Value = (ULONG_PTR)NtPath.Buffer;

	AttributeList.Attributes[1].Attribute = PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE);
	AttributeList.Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList.Attributes[1].ValuePtr = &SectionImageInfomation;

	AttributeList.Attributes[2].Attribute = PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE);
	AttributeList.Attributes[2].Size = sizeof(CLIENT_ID);
	AttributeList.Attributes[2].Value = (ULONG_PTR)&ClientId;

	Status = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, &AttributeList);
	wprintf(L"[*] NtCreateUserProcess: 0x%08lx\n", Status);
	wprintf(L"[*] ManifestAddress: 0x%p, ManifestSize: %ld\n", (PVOID)CreateInfo.SuccessState.ManifestAddress, CreateInfo.SuccessState.ManifestSize);
	wprintf(L"[*] %ls-> PID=%lld, TID=%lld\n", imagePathName.Buffer, (ULONGLONG)ClientId.UniqueProcess, (ULONGLONG)ClientId.UniqueThread);

	Status = CallCsrss(hProcess, hThread, CreateInfo, imagePathName, NtPath, ClientId, SectionImageInfomation);
	wprintf(L"[*] CallCsrss: 0x%08lx\n", Status);

	int i = getchar();
	//Sleep(5000);

	NtResumeThread(hThread, NULL);

	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);

	i = getchar();
	//Sleep(15000);

	return Status;
}