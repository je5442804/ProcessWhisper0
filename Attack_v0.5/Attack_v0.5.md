# NtSetInformationProcess->ProcessInstrumentationCallback
任何版本都不支持跨进程架构进行注入

[LdrInitializeThunk] - Thread and initial process thread creation starting point
[KiUserExceptionDispatcher]- Kernel exception dispatcher will IRET here on 1 of 2 conditions.
Tthe process has no debug port.
The process has a debug port, but the debugger chose not to handle the exception.
[KiRaiseUserExceptionDispatcher]- Control flow will land here in certain instances during a system service when instead of returning a bad status code, it can simply invoke the user exception chain. For instance: CloseHandle() with an invalid handle value.
[KiUserCallbackDispatcher] - Control flow will land here for Win32K window and thread message based operations. It then calls into function table contained in the process PEB.
[KiUserApcDispatcher] - This is where user queued apc's are dispatched.

### Supported
[x86 Native]:
Windows 10 x86 (ALL NT10 x86->x86, none of Windows 11)
Tested:
Windows 10 LTSC 2019 x86 (10.0.17763.316/6054)
Windwos 10 1507 x86 (10.0.10240.16384)

[x64 OS, Wow64 Process]
Windows Vista -> Windows 8.1 (6000->9600, NT6 由于内核与Wow64处理的问题，Nt Syscall无法触发回调，但其他五种似乎仍然正常触发)
Windows 10 -> Windows 11 (10240->?, 正常工作)

[x64 Native]
Widnows Vista -> Windows 11