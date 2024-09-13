# ProcessWhisper v0
Presume Possible Defense, Collected and Improved Known Process Injection.  
It has been proven feasible to bypass all solutions, but before that, we should learn the relevant knowledge well.  

# Extreme defense rules  
<details>
<summary>Untrust</summary>

```bash  
0: 以下规则假设当前攻击源进程不是 "位于可信目录的签名文件", AKA: 不属于高度可信任进程

1：CreateRemoteThread/NtCreateThreadEx  
Blocked  

2: SetThreadContext/NtSetThreadContext  
Blocked  

3: VirtualAllocEx/NtAllocVirtualMemory, MapViewOfSection,/NtMapViewOfSection  
Allowed: 且仍然可以指定地址进行Alloc/Map, RWX会被暗中标记可疑并记录，RX， X 还好一点

4: WriteProcessMemory/NtWriteVirtualMemory  
Only Allowed if: 你的当前进程写 ”由你Alloc/Map“的内存块， 以及创建进程的时候写入的 PEB 的那几个参数的偏移位置

5: VirtualProtect, NtProtectVirtualMemory
变态 Only Allowed if: 由你的当前进程写 ”由你Alloc/Map“的内存块，
正常 Allowed: 不拦截

总是：RWX会被暗中标记可疑并记录，RX/X 还好一点

6：NtFreeVirtualMemory, NtUnmapViewOfSection  
变态 Blocked: 对，全拒绝，即使是你Alloc/ Map过去的，想都别想
正常 Only Allowed if: 由你的当前进程写 ”由你Alloc/Map“的内存块，

7：冻结，挂起线程，冻结，挂起进程,
变态 Only Blocked if: ？？？
正常 Allowed: 只要能打得开句柄，总是允许的

8：NtSetInfomationProcess 回调钩子注入  
新加的根据 PROCESSINFOCLASS==ProcessInstrumentationCallback 拦截，不过挺有意思的，其实NT6 也能用，但是却不拦截  

9: Debug 一类API
emmm 不太清楚，似乎只记录但不管的

10: win32k/user32 
SetWindowsHookEx, SetProp(PROPagate), SetWindowsLongPtr/SetClassLongPtr
已知注入的NtUser* API全部拦截
但SendMessage/ PostMessage 这一类的防御似乎力不从心
```


</details>

## Attack v0.1
Underground Dll Hijacking  
.NET COR Injection ignored temporarily  

v0.1.1: Classic Non-SideLoading Dll Hijacking  
v0.1.2: ProcessDeviceMap Dll Hijacking aka Object Overloading  
v0.1.3: Application Directory Spoof Dll Hijacking  
v0.1.4: Client Server Runtime Subsystem: AppCompatSxsData Activation Context Override Dll Hijacking  

## Attack v0.x
Reserved
## Attack v0.5
Improved InstrumentationCallback Shellcode Process Injection  
