; SACReadIdtrAsm / soarwazhere
; x64 read and return base routine 
; signiure -> BOOLEAN SACReadIdtrAsm(PVOID* idtrBaseOut, USHORT* idtrLimitOut);
; rcx, idt baseout | rdx, idtlimit
; return eax, boolean type

OPTION CASEMAP:NONE

PUBLIC SACReadIdtrAsm

.code

SACReadIdtrAsm PROC
    sub     rsp, 48
    sidt    [rsp]
    mov     rax, qword ptr [rsp + 2]
    mov     [rcx], rax
    movzx   rax, word ptr [rsp]
    mov     word ptr [rdx], ax
    add     rsp, 48
    mov     eax, 1
    ret
SACReadIdtrAsm ENDP

END