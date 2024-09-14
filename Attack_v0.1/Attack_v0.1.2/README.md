# v0.1.2: ProcessDeviceMap Dll Hijacking aka Object Overloading
本质是符号链接？2022-2023 各种的FileObject DeviceMap漏洞有点相关  
nt!ObpLookupObjectName  
据我所知，RedirectGuard主要针对的是Token模拟的符号链接问题，重定向缓解不会影响这一类Set ProcessDeviceMap的吗？  
"Let me know the problem of Ntfs File Object, Directory Object and Symlink Object?"  
```
[!] Attack_v0.1.2 仅为探究，要兼容win 11 请使用 Attack_v0.1.2_Normal!!!  
[!] Shellcode: MessageBox: "Hello world"  

[Special Appoint Image File]  
[Dll Hijacking->Type: Special non-KnownDll&non-Assembly Hijacking] (Raw)  
--->  
[Dll Hijacking->Type: Special Hijacking] (Improved)   
[non-Separable & non-Breakaway]  
[Set Process]  
```

[C:\\Windows\\system32\\ddodiag.exe]  
在本小节中，例子主要参考于xpn大佬，Attack_v0.1.2 给出基于的 ProcessDeviceMap Dll 劫持后，结合内核对象一致性原理，大幅改进战术位置。  

注意！使用时我注意到了奇怪的缓存现象，这种感觉我难以合理地组织出语言来说。。。  

测试了 win11 最新正式版和 win 10 最新正式版, win 7/ win 2008  
Faild: win 2012 (ole32->combase/sechost....), win 11  
Attack v0.1.2 在 win 11 环境是被忽略状态，现已基本确认与用户态ntdll无关，球球内核调试大佬看看win 11 和 win 10 内核对文件系统DeviceMap查询与使用 修改和区别点，我相信ProcessDeviceMap还有更深的地方尚未被发掘。  

例子: NtQueryAttributesFile

a. 激进的 DeviceMap 重定向  
b. 普通的 DeviceMap 重定向  
c. 利用conhost ConsoleCallServer 的nls DLL加载， 重定向 *.nls -> my.Dll  
d. xxx  

另外，你也可以随意设置 ProcessDeviceMap 来触发环境变量Path 搜索，结合进程级别的环境变量设置实现劫持?

# Reference
[1] https://unit42.paloaltonetworks.com/junctions-windows-redirection-trust-mitigation/  
[2] https://blog.xpnsec.com/object-overloading/  
[3] https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Exploit/InsecureKernelResourceAccess.c  
[4] https://www.jiwo.org/ken/detail.php?id=2770  
[5] https://www.explo1t.online/article/64ecedab-76c0-499a-9496-e8313ad87e2f  
[6] https://y3a.github.io/2023/08/24/cve-2023-35359/  
[7] https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html  
[8] https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12  
