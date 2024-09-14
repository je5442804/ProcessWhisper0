# v0.1.4: Client Server Runtime Subsystem: AppCompatSxsData Activation Context Override Dll Hijacking  

在本例劫持 SMConfigInstaller.exe 时需要将XmlLite.dll 移至 C:\Users\Public\  
事实上无需这么底层进行进程创建除了 ntdll.dll 以外似乎都能劫持, Manifest 似乎由于历史原因仍然不能用 UTF-8？  
缺点是不能断链分离.  
我不太确定其是否有副作用，但该方法具有很大的探索空间，且不仅仅用在这里，例如com劫持.  
```
[All Image File]
[Dll Hijacking->Type: Activation Context Hijacking]
[non-Separable & non-Breakaway]
```
# Reference
[1] https://www.zerodayinitiative.com/blog/2023/1/23/activation-context-cache-poisoning-exploiting-csrss-for-privilege-escalation  
[2] https://github.com/deroko/activationcontext  
