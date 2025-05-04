---
title: 'Vilo Router 0day Research'
date: 2024-08-13 00:00:00
tags: 
- security-research
- iot
- embedded
---

# Vilo Router 0day Research
From January to August 2024, I led a team of BYU students in discovering 9 vulnerabilities in Vilo 5 Mesh WiFi System routers. All vulnerabilities were issued CVEs, reported to the vendor, and affected the latest version of the firmware at the time (5.16.1.33). These were discovered after evaluating the physical router hardware, firmware and active network services, mobile app code, and cloud infrastructure interactions. 

* [CVE-2024-40083](https://www.cve.org/CVERecord?id=CVE-2024-40083) - [Buffer Overflow in `local_app_set_router_token()`](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40083.md) (9.6 Critical)
* [CVE-2024-40084](https://www.cve.org/CVERecord?id=CVE-2024-40084) - [Buffer Overflow in Boa Webserver](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40084.md) (9.6 Critical)
* [CVE-2024-40085](https://www.cve.org/CVERecord?id=CVE-2024-40085) - [Buffer Overflow in `local_app_set_router_wan()`](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40085.md) (9.6 Critical)
* [CVE-2024-40086](https://www.cve.org/CVERecord?id=CVE-2024-40086) - [Buffer Overflow in `local_app_set_router_wifi_SSID_PWD()`](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40086.md) (9.6 Critical)
* [CVE-2024-40087](https://www.cve.org/CVERecord?id=CVE-2024-40087) - [No Authentication in Custom Port 5432 Service](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40087.md) (9.6 Critical)
* [CVE-2024-40088](https://www.cve.org/CVERecord?id=CVE-2024-40088) - [Arbitrary File Enumeration in Boa Webserver](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40088.md) (4.7 Medium)
* [CVE-2024-40089](https://www.cve.org/CVERecord?id=CVE-2024-40089) - [Blind Authenticated Command Injection in Vilo Name](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40089.md) (9.1 Critical)
* [CVE-2024-40090](https://www.cve.org/CVERecord?id=CVE-2024-40090) - [Info Leak in Boa Webserver](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40090.md) (4.3 Medium)
* [CVE-2024-40091](https://www.cve.org/CVERecord?id=CVE-2024-40091) - [No Authentication in Boa Webserver](https://github.com/byu-cybersecurity-research/vilo/blob/main/vulns/CVE-2024-40091.md) (5.3 Medium)

Our team presented our research at IoT Village @ DEFCON 32 and SAINTCON 2024. To see more information, we published details of the vulnerabilities, slides from our talks, and some documentation pertaining to the Vilo attack surface on our GitHub here --> https://github.com/byu-cybersecurity-research/vilo. 