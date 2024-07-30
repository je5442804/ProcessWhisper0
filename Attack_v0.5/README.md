# NtSetInformationProcess->ProcessInstrumentationCallback
v0.5 在任何操作系统版本都不支持跨进程架构进行注入

## 限制
1: 老旧系统下Wow64 Nt syscall不触发，x86 Native 系统有很低的概率会崩溃，当然x64, wow64在某些罕见进程也可能会崩溃  
2: ADMIN+/SYSTEM 级别的Token, 因为远程注入必须要 SeDebugPrivilege 特权   
3: 需要内核到用户态的切换后回调触发，意味着某些进程需要很久，或特定行为操作后，或者根本无法等到它触发  
4: 已经在检测范围下  

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

## Reference
[1] https://everdox.blogspot.com/2013/02/instrumentationcallback-and-advanced.html  
[2] https://blog.xenoscr.net/2022/01/17/x86-Nirvana-Hooks.html  
[3] https://github.com/ec-d/instrumentation-callback-x86/blob/master/main.c  
[4] https://www.codeproject.com/Articles/543542/Windows-x64-System-Service-Hooks-and-Advanced-Debu  
[5] https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html  
[6] https://wbenny.github.io/2018/11/04/wow64-internals.html  
[7] https://web.archive.org/web/20160825133806/https://sww-it.ru/2016-04-11/1332   
