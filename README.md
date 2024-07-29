# ProcessWhisper_v0
Presume Possible Defense, Collected and Improved Known Process Injection  

# Extreme defense rules  
必须假设当前攻击源进程不属于可信目录白名单，不属于高可信进程  
1：CreateRemoteThread/NtCreateThreadEx  
Blocked  

2: SetThreadContext/NtSetThreadContext  
Blocked  

3: VirtualAllocEx/NtAllocVirtualMemory, MapViewOfSection,/NtMapViewOfSection  
不受限制，且仍然可以指定某一个地址进行Alloc/Map, RWX会被暗中标记可疑并记录，RX， X 还好一点

4: WriteProcessMemory/NtWriteVirtualMemory  
允许你的当前进程写 ”由你Alloc/Map“的内存块， 以及创建进程的时候写入的 PEB 的那几个参数的偏移位置，
其他一律block，所以外国佬开发的那些基于这个的，其实一大把都一样，什么对远程进程进行Patch的，很多类似的Callback什么的都还没公布，到这都不好使了.

5: VirtualProtect, NtProtectVirtualMemory  
同4 （还是同3来着，我忘了额）
RWX会被暗中标记可疑并记录，RX， X 还好一点

6：NtFreeVirtualMemory, NtUnmapViewOfSection  
block, 对，全拒绝，即使是你Alloc/ Map过去的，想都别想

7：冻结，挂起线程，冻结，挂起进程,  
只要能打得开句柄，总是允许的

8：NtSetInfomationProcess 回调钩子注入  
新加的根据 PROCESSINFOCLASS==ProcessInstrumentationCallback 拦截，不过挺有意思的，其实NT6 也能用，但是却不拦截，可能AV/EDR懒得做适配

9: Debug 一类API
emmm 不太清楚，似乎只记录但不管的


10: win32k/user32 
SetWindowsHookEx, SetProp(PROPagate), SetWindowsLongPtr/SetClassLongPtr
已知注入的NtUser* API全部拦截
但SendMessage/ PostMessage 这一类的防御似乎力不从心
