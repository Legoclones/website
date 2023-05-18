---
title: 'Hacking the GL-AR750S, Part 1: Physical Compromise'
date: 2023-05-18 00:00:09
tags: 
- security-research
- hardware
- iot
---

# Hacking the GL-AR750S, Part 1: Physical Compromise
Ever since I started hacking in 2020, I've mainly stayed on the software side of things - digital forensics, web exploitation, and some binary exploitation through CTFs. I won 2nd place at my local security conference (SAINTCON) in 2021, and received a [GL-AR750S-EXT travel router](https://www.gl-inet.com/products/gl-ar750s/) as one of my prizes. It's intended to be a secure middleman that allows you to use public/open WiFi with encryption. I never really needed to use it, and it sat on my shelf for about a year before I decided to test it for vulnerabilities. 

I had seen and even done a little bit of hardware hacking before. I knew what UART and JTAG were, and had worked with serial connections. The process that I followed to physically connect to the device is outlined [here on OpenWRT.org](https://openwrt.org/toh/gl.inet/gl-ar750s#opening_the_case). Like it says, I removed the dot feet, unscrewed and opened the case, removed the antennaes, extracted the PCB from the case, and removed the heatsink. Then, using my roommate's soldering iron and connectors, I soldered on 7 pins for the I2C and UART connectors, and used a UART-to-USB adapter to connect my laptop to the PCB. 

My setup:

<img src="/static/glinet-1/board.jpg" width="800px">

<img src="/static/glinet-1/board_closeup.jpg" width="400px">

More photos of the inside of the GL-AR750S can be found [here](https://fcc.report/FCC-ID/2AFIWGL-AR750S/3977852.pdf). 

Once physically connected, I opened up PuTTY on my machine, and established a Serial connection through the USB adapter at a 115200 baud rate (which I found by looking at [the datasheet for the QCA9563 chip](https://my-files.su/2mwodv)). Upon powering it on, a lot of boot information flew across my screen (see the full text at [boot.txt](/static/glinet-1/boot.txt)):

```
U-Boot 1.1.4 (Fri May 17 09:44:06 2019)

ar750s - Dragonfly 1.0DRAM:
sri
ath_ddr_initial_config(278): (ddr2 init)
ath_sys_frequency: cpu 775 ddr 650 ahb 258
Tap values = (0xf, 0xf, 0xf, 0xf)
128 MB
Flash Manuf Id 0xef, DeviceId0 0x40, DeviceId1 0x18
flash size 16MB, sector count = 256
*** Warning - bad CRC, using default environment

...

Press the [f] key and hit [enter] to enter failsafe mode
Press the [1], [2], [3] or [4] key and hit [enter] to select the debug level
Failed to connect to ubus
Please press Enter to activate this console.
```

Pressing `ENTER` revealed a root shell, no password required!

```
BusyBox v1.30.1 () built-in shell (ash)

  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 OpenWrt 19.07.7, r11306-c4a6851c72
 -----------------------------------------------------
root@GL-AR750S:/# 
```

After some research and discussing with peers, this is fairly common actually. The industry "default" I guess you could say is to assume that if someone gets physical access to a device, it's been compromised. This is a prime example - just a little physical finangling, and you have full, unrestricted access to the device with all current data. Now, the root user *does* have a password, which is actually the **same** password as the admin account on the GUI (see the [documentation](https://docs.gl-inet.com/en/3/setup/gl-ar750s/first_time_setup/#2-admin-password-setting)), but it never asked you for it. Go figure. Apparently [GL.iNET knows about it](https://boschko.ca/glinet-router/#connecting-to-uart) and doesn't intend to fix it \o/. 

My next goal was to copy all the files onto my local machine so I could examine them, especially the web source code. I found that the machine was running Dropbear, a very small SSH client/server on port 22. I connected my laptop to the board using an Ethernet cable in one of the two LAN slots, and found I was able to SSH onto the machine with the root account and password. Note that I did have to use the command `ssh -oHostKeyAlgorithms=+ssh-rsa root@192.168.8.1`, since Dropbear only supported `ssh-rsa`, not allowed by default. I then used SCP to copy all the contents of the chip to my machine (using the command `scp -r -oHostKeyAlgorithms=+ssh-rsa -O root@192.168.8.1:/folder .` for compatibility reasons). 

Now that I had remote access to the machine and source code to work with, I was ready to start looking for vulnerabilities!

To read about the 7 CVEs I later discovered, [hop on over to Part 2](/2023/glinet-2/)!