from pwn import *

#p = process('./mycode.py')
p = remote('lac.tf', 31133)

# solve = [(11, 0), (0, 3), (8, 18), (14, 18), (17, 11), (3, 12), (19, 10), (16, 7), (16, 15), (16, 5)]

def left():
    p.sendline(b'L')

def right():
    p.sendline(b'R')

def go(x):
    p.sendline(str(x).encode())


# get to (11, 0)
go(9)
left()
go(1)
right()
go(2)
right()
go(1)

# get to (0, 3)
right()
go(8)
right()
go(1)
left()
go(3)
right()
go(2)

# get to (8, 18)
go(8)
right()
go(3)
left()
go(4)
right()
go(1)
left()
go(3)
right()
go(4)

# get to (14, 18)
go(3)
left()
go(1)
right()
go(3)
right()
go(1)

# get to (17, 11)
go(7)
left()
go(3)

# get to (3, 12)
go(1)
left()
go(4)
left()
go(15)
left()
go(3)

# get to (19, 10)
go(2)
left()
go(16)

# get to (16, 7)
right()
go(3)
right()
go(3)

# get to (16, 15)
right()
go(1)
left()
go(2)
right()
go(7)
right()
go(2)

# get to (16, 5)
right()
go(10)


p.interactive()
p.close()