use32

    mov edi, edi
    push ebp
    mov ebp, esp
    sub esp, 0x1c
    
    push edx
    push eax
    
    mov edx, 0xffffffff;// Flags
    mov eax, 0xffffffff;// NtCreateThreadEx
    mov DWORD [ebp-0x18], eax

    mov eax, DWORD [edx+0x4];// Isx86NativeOS ?
    test eax, eax
    jz lol
    mov ecx, fs:[0x18]
    mov ecx, [ecx+0x1b0]
    ;;cmp ecx, [esp]
    ;;jnz lol
    
lol:
    cmp BYTE [edx], 0
    jne skiped
    mov eax, DWORD [ebp-0x18]
    mov BYTE [edx], ah
    
    push ecx
    push ebx
    push esi
    push edi

    call DisposableHook
    
    pop edi
    pop esi
    pop ebx
    pop ecx
    
skiped:
    pop eax
    pop edx
    leave
    jmp ecx ;;Wow64需要，也可以sub esp, 0x4, x86原生 nt syscenter直接ret (部分)
    ret
    
DisposableHook:
    mov edi, edi
    push ebp
    mov ebp, esp
    sub esp, 0x68
    
    ;;mov eax, ecx
    mov [ebp-0x3c], edx

    mov ebx, 1
    xchg DWORD [edx], ebx
    cmp ebx, 1
    je Success

    xor ecx, ecx
    push ecx
    push ecx
    push ecx
    push ecx
    push ecx
    push ecx
    call core1
    add edi, 0x5
    push edi
    push 0xffffffff
    push ecx
    push 0x1fffff
    lea esi, [ebp-0x38]
    push esi
    call eax

    cmp eax, 0
    je Success
    
    xor eax, eax
    mov edx, [ebp-0x3c]
    xchg DWORD [edx], eax;InterlockedExchange64
Success:
    leave
    ret

core1:
    call core2
    ret
core2:
    mov edi, DWORD [esp]
    ret