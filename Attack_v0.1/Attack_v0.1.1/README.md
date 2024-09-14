# v0.1.1: Classic Non-SideLoading Dll Hijacking
因为我们仅考虑位于可信目录下的可信exe的 DLL劫持，所以忽略Sideloading
部分劫持甚至可以用来UAC提权，也有一些劫持在更新补丁后已经被修补。


```
[Special Appoint Image File]  
[Landed Dll->Type: Unsupported Universal]  
[Support Command Only Operate]  
[Separable & Breakaway]  
```


v0.1.1 仅需要制作恰当的dll, 无需额外API调用
# DLL Hijack via Environment Variable, Phantom, Search Order
https://hijacklibs.net/#exe
# WinSxS Folder Hijack
在大方向上属于Phantom，当然也有认为它同时属于Search Order
https://www.securityjoes.com/post/hide-and-seek-in-windows-closet-unmasking-the-winsxs-hijacking-hideout
