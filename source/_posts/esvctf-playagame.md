---
title: Writeup - Let's Play a Game (ESVCTF 2023)
date: 2024-08-14 00:00:01
tags: 
- writeup
- pwn
- esvctf2024
---

# ESVCTF 2024 - Let's Play a Game
## Description
```markdown
ECU A

The first flag is inside the Chip-8 game engine memory. If only you could play a 
custom game and look for it...

(New to Chip 8? Try https://johnearnest.github.io/Octo/)

[ECUA.elf]
```

## Writeup
The Embedded System Village CTF was held at DEFCON 32 over a period of just over 2 days. When teams reached 10,000 points, they were provided a [Toyota RAMN board](https://github.com/ToyotaInfoTech/RAMN), a piece of equipment designed to emulate the system of a car. It emulated a CAN Bus with 4 ECUS - A, B, C, and D. While the firmware for the equipment is open-source, in this case it was modified to include vulnerabilities and flags for the CTF. 

<img src="/static/esvctf-playagame/ramn.jpg" width="500px">

For this challenge, [an ELF running on ECU A was provided](/static/esvctf-playagame/ECUA.elf) which emulated the 8-bit [CHIP-8 architecture](https://en.wikipedia.org/wiki/CHIP-8). The ELF provided included redacted flags so you'd know where the actual flags were located; note that the non-redacted version of the ELF was stored and running on the provided physical RAMN board, so exploiting it on the device would reveal the actual flag. 

### Interfacing with the Board
After wading through the documentation for a little bit, I found [a section on connecting through USB](https://ramn.readthedocs.io/en/latest/quickstart.html#usb-connection). I downloaded the provided drivers, connected it with a USB cord that supports more than just power, and found out what COM port it was available on using the Windows Device Manager (COM5 in my case). I initially used PuTTY to interface with the serial device (baud rate of 9600), but ended up moving to PySerial for my exploit.

I had to change the terminal settings to force local echo and enable implicit LF in every CR for it to appear right, but this is what it looks like when I was plugged in:

<img src="/static/esvctf-playagame/serial_con.png" width="750px">

### Challenge Recon
The description told us the first flag was located somewhere in memory, and if we could load our own game we could retrieve it. The output for `file ECUA.elf` was:

```
ECUA.elf: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, with debug_info, not stripped
```

Not only was it not stripped, it was compiled with debug symbols and very easy to reverse in Ghidra. You'll note it's a 32-bit ARM binary and not CHIP-8. This particular binary implements the CHIP-8 architecture as a VM, with global variables for the memory and registers. It was not compiled with any mitigations.

A quick search for flag reveals the string `flag{REDACTED_FLAG_1}` which is referenced once in the `RAMN_CHIP8_Init()` function. Some quick reversing showed how CHIP-8 games are loaded to be ran. The bytes for the game (provided as an argument to the function) were copied to the global variable `memory` starting at offset `0x200`. Then, all bytes from the game to the end of the `memory` variable were cleared (to prevent info leaks). Lastly, `flag1` was copied to `memory` from offset `0x1e9` to `0x1ff`. This means if we could load our own game, all we would have to do is leak/print out the bytes stored at those addresses.

<img src="/static/esvctf-playagame/flag1_location.png" width="750px">

Okay, so now we needed to figure out how to:
1. Load our own custom game
2. Write CHIP-8 assembly code that would leak the flag at address `0x1e9`

### Loading Our Custom Game
By looking at the references to the `RAMN_CHIP8_Init()` function, I found one call inside the `RAMN_ScreenChip8_StartGameFromIndexString()`

<img src="/static/esvctf-playagame/overflow.png" width="750px">

Here, we can see that the game being loaded comes from the `chip8_usb_data` global variable, a custom struct that looks like this:

<img src="/static/esvctf-playagame/struct.png" width="600px">

However, there is a buffer overflow here with the `strcpy()` function call. It's copying the entire `index_str` argument into the beginning of the `chip8_usb_data` struct, so if the argument is longer than the 2 bytes set aside for the `game_index_str` attribute, it overwrites the rest of the struct. This means we can overwrite the `usb_chip8_ROM` attribute (storing the CHIP8 assembly code) and the `game_size` attribute. However, there are some checks we need to pass first:

* The `game_index` can't be 1, 2, or 3
* The `game_size` must be between 0 and `0xfff` but large enough to copy all the CHIP8 assembly over
    * The reason this exists is because the chip only has `0x1000` memory addresses

This function is called from `RAMN_ReceiveUSBFunc()`, where input from the USB connection is parsed as commands. If the `play` command is used, then the second argument is passed as the `index_str` to our vulnerable function. Note that the number of arguments is checked, so the `index_str` can't have a space in it either.

<img src="/static/esvctf-playagame/arg.png" width="600px">

### Exploit Setup
Before I wrote the CHIP8 assembly code for our exploit, I wrote a short Python script that would trigger this overflow and run a custom game:

```python
import serial

game = b'...'

s = serial.Serial('COM5')
s.write(b"play xxx\x01\x01\x01" + game + b'\r')
res = s.read_until(b'\r')
print(res)
```

I connect to the `COM5` port and overflow the `chip8_usb_data` struct with x's and `\x01`s for the `game_size` so it passes all the checks. Running this shows `b'Starting game.\r'` on my computer and a crash on the small LED screen of the board.

<img src="/static/esvctf-playagame/crash.jpg" width="400px">

### Exploit
Since the CHIP8 crash displays memory before and after the crash for both the `PC` and `I` register, I figured an easy way to get the flag would be to simply set the `I` variable to the flag and write down the leaked values 6 bytes at a time. By following the simple ISA [outlined on Wikipedia](https://en.wikipedia.org/wiki/CHIP-8#Opcode_table), I just used the assembly `A1EC` (or `b'\xa1\xec'`) to set `I` to `0x1ec` and leak the first 6 values of the flag. I then repeated this, incrementing the address, until I got all the flag values. 

Solve script:
```python
import serial

game = b'\xa1\xec' # set I to 0x1fc

s = serial.Serial('COM5')
s.write(b"play xxx\x01\x01\x01" + game + b'\r')
res = s.read_until(b'\r')
print(res)
```

<img src="/static/esvctf-playagame/flag.jpg" width="400px">

**Flag** - `flag{CL053_T0_F0NTS_}`