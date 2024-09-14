# v0.1.3: Application Directory Spoof Dll Hijacking

完全根据 Octoberfest73 & snovvcrash idea 和 poc 编写.
但想着这样没意思，于是使用了 *.dll Dll Hijacking.
就像部分dll 能以 PPL Authenticode 运行，先点个名 kernel32.dll/ntdll.dll
[Almost General Image File]
[Dll Hijacking->Type: non-KnownDll Hijacking] (Improved)
[non-Separable & non-Breakaway]

[C:\Windows\System32\WerFault.exe]
[C:\Windows\System32\setup\RasMigPlugin.dll]
注意！我不确定这会对系统造成什么影响，偶尔部分应用出现了很奇怪的崩溃现象.

测试表明具有通用性.

# Reference
[1] https://twitter.com/Octoberfest73/status/1642218159959691264
[2] https://gist.github.com/snovvcrash/3d5008d7e46d1cc60f0f8bdc8cdb66a5