---
title: 'Hacking the GL-AR750S, Part 2: 7 CVEs'
date: 2023-05-18 00:00:08
tags: 
- security-research
- iot
---

# Hacking the GL-AR750S, Part 2: 7 CVEs
After extracting the source code and firmware for the GL-AR750S-Ext device, I started combing through it to understand how the device worked. It turns out **all** GL.iNET devices use the same firmware, the web API simply looks up the device model to ensure the physical device can perform what the user is asking. This is nice for the developers since they don't have to create separate firmware for each device, but that also means a vulnerability found in one device likely affects ALL other GL.iNET devices (which was the case for most of the vulnerabilities I found). 

## GL.iNET IoT Device Setup
All of GL.iNET's IoT devices use the [OpenWRT Linux Operating System](https://openwrt.org/start), which is built upon BusyBox and designed specifically for use by IoT devices and vendors. On top of the OpenWRT OS is custom GL.iNET firmware. This firmware provides a web GUI for users to utilize while setting up their networks, gateways, or other IoT functions. 

GL.iNET's firmware is deployed through a lightweight package manager native to OpenWRT called [opkg](https://openwrt.org/docs/guide-user/additional-software/opkg). Curl requests are made to the `fw.gl-inet.com` website, where the latest version is identified and downloaded, if needed. When the latest package is downloaded, one of the files inside is a squashfs file that contains the entire directory structure of the machine (including `/bin` executables, `/etc` config files, etc.). This directory structure and all files inside can be found in my GitHub repo, [pentesting GL.iNET](https://github.com/Legoclones/pentesting-GL.iNET).  

While most of the contents of these `rom` folders is copied from OpenWRT, there are some changes made to it for GL.iNET devices. Specifically, a number of packages that are normally available on OpenWRT through the `opkg` manager but *not* installed by default are included in the firmware package, such as `dropbear` (a lightweight SSH client) and `lighttpd` (a lightweight web server). Most notable, however, are the inclusion of a custom website located in `/www`, and custom C executables and libraries in `/usr/bin` and `/usr/lib`. 

The webserver located in `/www` and launched on startup uses Vue as the front-end framework, and all information is populated by an API. The API (instead of being programmed in PHP or NodeJS) is actually written as a C binary called `api`, found in `/www`. In addition, a web interface called `LuCI` (which is the official web interface for OpenWRT) is also included in GL.iNET devices, and binaries for this interface are found in `/www/cgi-bin`. In earlier versions of GL.iNET firmware (such as 3.201), `LuCI` was **NOT** included by default, and could be optionally installed. However, in the latest version as of this writing (3.216), `LuCI` is installed by default. 

## CVEs Found and Published
In the course of reverse engineering the `/www/cgi-bin/api` binary, I found several vulnerabilities, 5 of which affect **ALL** GL.iNET models, and 2 of which affect only specific GL.iNET models. A short description of each CVE is below, along with links to a more detailed explanation of the vulnerability and Python PoCs (where relevant). 

* [CVE-2023-24261](/2023/glinet-CVE-2023-24261/) (8.4, High) - the value of the `ssid` parameter in an authenticated POST request to `/cgi-bin/api/ap/enable` is piped directly into a command
* [CVE-2023-31472](/2023/glinet-CVE-2023-31472/) (7.5, High) - an empty file can be created anywhere on the filesystem due to a filtered command injection vulnerability
* [CVE-2023-31475](/2023/glinet-CVE-2023-31475/) (9.0, Critical) - the function `guci2_get()` found in `libglutil.so` has a buffer overflow vulnerability where an item is requested from a UCI context, and the value is pasted into a char pointer to a buffer without checking the size of the buffer.
* [CVE-2023-31476](/2023/glinet-CVE-2023-31476/) (7.5, High) - an empty file can be created anywhere on the filesystem due to a filtered command injection vulnerability
* [CVE-2023-31478](/2023/glinet-CVE-2023-31478/) (8.3, High) - the web GUI admin password can be retrieved through a single, unauthenticated POST request
* [CVE-2023-XXXXX (currently unassigned)](/2023/glinet-CVE-2023-XXXX1/) (6.8, Medium) - all GL.iNET IoT devices use the same default self-signed HTTPS cert, allowing for a MITM attack
* [CVE-2023-XXXXX (currently unassigned)](/2023/glinet-CVE-2023-XXXX2/) (5.3, Medium) - the authentication token is sent in a GET query string when exporting the server VPN config file

## Informational Findings
In addition to the CVEs published, there were other things I noticed and felt would be good to include here to guide anyone looking to red team or search for more vulnerabilities in these IoT devices. 

* The default LAN SSID key is `goodlife`. The Web GUI admin password does *not* have a default value, but rather is created initially (and cannot be set to `goodlife`). The only requirement is it must be at least 5 characters long.
* The folder `/var` is symlinked to `/tmp`, which means that any information that would normally go in `/var` (such as log files in `/var/log`) is erased upon reboot since `/tmp` is always wiped upon reboot.
* Router-specific information such as model name, factory-issued MAC address, serial number, timezone, language, and the hashed admin web GUI password is found at `/etc/config/glconfig`.
* As of May 2023 (time of writing), the initial firmware version shipped with the AR-750S-Ext router was 3.201, and the latest available version is 3.216. Other models may be shipped with different initial versions. Firmware versions 4.x is currently in beta testing and only available for a few, limited models. 
* GL.iNET devices have **no concept of least privilege**. All processes run as root, and the root password for the device is the same as the web GUI admin password. This means that certain vulnerabilities are much more impactful; for example, arbitrary file write is practically the same as remote code execution (RCE) since you can overwrite `/etc/shadow` with your own hash, or write to a cronjob or other script that is executed often (like `/www/api`), etc.

## Dependency Vulnerabilities
All GL.iNET devices with 3.x firmware have many outdated dependencies, which are not intended to be updated. Instead, customers are advised to update to the GL.iNET 4.x firmware version which is the latest version. Dependency versions (with links to vulnerability pages) for 3.x firmware:

* [OpenWRT, v 19.07.8](https://openwrt.org/advisory/start) released Aug 2021 (EOL)
* [BusyBox, v 1.30.1](https://www.cvedetails.com/vulnerability-list/vendor_id-4282/product_id-7452/Busybox-Busybox.html) released Feb 2019
* [lighttpd v 1.4.48](https://www.cvedetails.com/vulnerability-list/vendor_id-2713/Lighttpd.html) released Nov 2017
* [Dropbear v 2019.78](https://www.cvedetails.com/vulnerability-list/vendor_id-15806/Dropbear-Ssh-Project.html) released March 2019

## Scanner
I created [a Python script](https://github.com/Legoclones/pentesting-gl.inet/blob/main/scanner.py) to act as a scanner for all GL.iNET devices that will query various unauthenticated endpoints and print out information specific to this instance. Depending on the configuration and version, information such as firmware version, language, MAC address, and even SSID and password may be available. 

To use the scanner, run the command `python3 scanner.py <domain/IP>`, such as `python3 scanner.py 192.168.8.1`.

*Note - this has only been tested on devices with firmware versions 3.x, not any 4.x devices*