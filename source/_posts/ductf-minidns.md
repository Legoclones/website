---
title: Writeup - Mini DNS Server (DUCTF 2023)
date: 2023-09-04 00:00:00
tags: 
- writeup
- misc
- ductf2023
---

# DUCTF 2023 - Mini DNS Server
## Description
```markdown
This mini DNS server hands out free flags to fellow mini DNS enthusiasts.

Author: joseph, pix

`dig @34.82.169.203 -p 8053 give.me.the.flag`

[mini_dns_server.py]
```

## Writeup
If you want to learn everything that you never wanted to learn about DNS, this writeup is for you. I'll be getting really deep into the DNS protocol, referencing RFCs and Python source code.

The [Python file that runs this DNS server](/static/ductf-minidns/mini_dns_server.py) is only 32 lines of code:
```python
import time
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, TXT, QTYPE, RCODE


class Resolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        reply.header.rcode = RCODE.reverse['REFUSED']

        if len(handler.request[0]) > 72:
            return reply

        if request.get_q().qtype != QTYPE.TXT:
            return reply

        qname = request.get_q().get_qname()
        if qname == 'free.flag.for.flag.loving.flag.capturers.downunderctf.com':
            FLAG = open('flag.txt', 'r').read().strip()
            txt_resp = FLAG
        else:
            txt_resp = 'NOPE'

        reply.header.rcode = RCODE.reverse['NOERROR']
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt_resp)))
        return reply


server = DNSServer(Resolver(), port=8053)
server.start_thread()
while server.isAlive():
    time.sleep(1)
```

It uses the [dnslib](https://pypi.org/project/dnslib/) Python library to power this DNS server, with all the default options except overwriting the `resolve()` function. This function has been [considerably modified](https://github.com/paulc/dnslib/blob/master/dnslib/zoneresolver.py#L25) from the original, but helps us see the goal of the challenge. First, `reply = request.reply()` generates a proper DNS reply based on the DNS request sent by the client. However, if some special requirements are met, the flag is also returned in the reply. Those requirements are:

* The length of the entire DNS request is 72 bytes or less
    * (`handler.request` returns a tuple with the DNS request information, the first item of which is the raw bytes of the DNS portion of the packet)
* The request has to be for a TXT record
    * You can read about different DNS records [here](https://constellix.com/news/dns-record-types-cheat-sheet)
* The DNS name to be resolved must be `free.flag.for.flag.loving.flag.capturers.downunderctf.com` (57 chars)

The hardest part of this challenge is meeting the character requirement, as the domain name is already 57 of the 72 chars, meaning all the other information must fit into 15 bytes. This is kind of like code golfing but for DNS queries!

As you may have guessed, using pre-defined commands like `dig` or APIs like `Scapy` weren't sufficient, we had to hand-craft DNS packet byte-by-byte and send it through a raw socket. 

### Base DNS Request
To conserve bytes, we created a DNS request from scratch. According to [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035#section-4), DNS messages (both requests and responses) have 5 main sections:

* Header
* Question(s)
* Answer(s)
* Authority
* Additional record(s)

Since we only need to send a single request for a TXT record, we only need the header and a single question section. The DNS header looks like the following:

<img src="/static/ductf-minidns/header.png" width="600px">

Each row is 16 bits, or 2 bytes. The header as a whole is 12 bytes, and all fields must be present. Questions look like the following:

<img src="/static/ductf-minidns/question.png" width="600px">

All 3 fields are required, but only `QTYPE` and `QCLASS` have set lengths (2 bytes each). This is already 16 bytes without even including the domain name (which is 57 characters), so it's not looking super good. 

`QNAME`s are special in how they're created. The RFC states it's "represented as a sequence of labels". These labels are the period-delimited sections of the domain name. For example, the domain `www.google.com` has 3 labels - `www`, `google`, and `com` (in that order). These labels are formatted with a single byte for the character length of the label, followed by the label characters. Once the last label is formatted, a null byte marks the end of the `QNAME` section. 

Following this format, `www.google.com` would be stored in the `QNAME` section as `\x03www\x06google\x03com\x00` (16 bytes). The domain name needed for the flag, `free.flag.for.flag.loving.flag.capturers.downunderctf.com`, would be formatted as `\x04free\x04flag\x03for\x04flag\x06loving\x04flag\x09capturers\x0cdownunderctf\x03com\x00` (59 bytes). 

So far, this is our entire DNS request:

```python
header = b'\x69\x69\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00'
qname = b'\x04free\x04flag\x03for\x04flag\x06loving\x04flag\x09capturers\x0cdownunderctf\x03com\x00'
end = b'\x00\x10\x00\x01'

dns_packet = header + qname + end
```

Inside the header, we set the ID to `\x69\x69`, the bitmap to `\x01\x20` (normal bits for a DNS request), then the question count was set to 1 and all other fields were set to 0. Inside the question section, our `QNAME` was set to what we discussed earlier, the DNS type was set to `\x00\x10` (TXT record), and the class was set to `\x00\x01` (`IN`).

Our problem is that this DNS request is 75 bytes long, which is 3 bytes too many. My teammate and I spent a lot of time combing through the [parsing done by the `dnslib` library](https://github.com/paulc/dnslib/blob/master/dnslib/dns.py#L108) to see if we could just remove extra bytes in any sections without it noticing, but to no avail. 

### Message Compression
In order to save a few bytes, [the RFC outlines message compression](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4) that can be done in DNS messages, specifically in the domain names (like the one in `QNAME`, the only section without a standard size). This was an interesting avenue we started to look into, but there were some caveats. Since many DNS replies contain DNS names with similar endings (like `www.google.com`, `auth.google.com`, and `account.google.com`), the `QNAME` could contain pointers that would point to other labels in the same DNS message. 

For example, the first domain name would be null-terminated 3 labels - `\x03www\x06google\x03com\x00`, the second would be 1 label and 1 pointer - `\x04auth<ptr to google.com labels>`, and the third would be 1 label and 1 pointer - `\x07account<ptr to google.com labels>`. Pointers are 2 bytes (16-bits) long, with the first 2 bits set to `11`, and the last 14 bits equal to the byte offset of the label (starting at the beginning of the DNS packet).

If the first QNAME `\x03www\x06google\x03com\x00` started at byte `0x20`, then the null-terminated labels `\x06google\x03com\x00` would start at byte `0x24`. This means the second `QNAME` would be `\x04auth\xc0\x24`, and the third `QNAME` would be `\x07account\xc0\x24`, which saves significant bytes. 

Since the label `flag` is repeated multiple times in our desired DNS name, we figured we could convert subsequent `flag` labels into pointers and save some bytes. There were several problems with this approach:

* Pointers don't just point to a single label, they point to a series of labels ending in a null byte (which `flag` did not)
* Domain names can only END in a pointer, pointers cannot be placed in the middle of one
    * If you placed a pointer in the middle, it would just treat whatever labels pointed to as the end of the domain name and not process later labels
* There are no other domain names in the entire packet

The first two problems were identified during testing, confirmed in the RFC, and verified in the actual `dnslib` source code (which we spent more hours combing through). This led us to one other idea - use a pointer instead of the `com` label, but stick it somewhere in the DNS packet where it shouldn't be but isn't checked. 

This would bring us down to 72 bytes from 75 because the end of the domain name would go from `\x03com\x00` to `\xc0\x??` (no null byte is needed after a pointer).

### Byte Smuggling
We now needed to identify pre-existing fields that were not verified or insufficiently verified to get 5 extra bytes `\x03com\x00`. After going back through the parsing process, we found that we could not stick arbitrary bytes in any fields.... except for the `id` and `bitmap` sections. These two sections are next to each other and 2 bytes each, and the next byte afterwards was a null byte (it's almost as if this was intended...). So we set the ID to `\x03c` and the bitmap to `om`, making it a technically "invalid" DNS packet (unrecognized by Wireshark), but is still processed correctly by `dnslib`. 

Our final payload was:

```python
header = b'\x03com\x00\x01\x00\x00\x00\x00\x00\x00'
qname = b'\x04free\x04flag\x03for\x04flag\x06loving\x04flag\x09capturers\x0cdownunderctf\xc0\x00'
end = b'\x00\x10\x00\x01'

dns_packet = header + qname + end
```

[Full solve script](/static/ductf-minidns/solve.py):

```python
### Compile DNS packet ###
header = b'\x03com\x00\x01\x00\x00\x00\x00\x00\x00'
qname = b'\x04free\x04flag\x03for\x04flag\x06loving\x04flag\x09capturers\x0cdownunderctf\xc0\x00'
end = b'\x00\x10\x00\x01'

dns_packet = header + qname + end
print(len(dns_packet))


### Send DNS packet ###
import socket

UDP_IP = "34.82.169.203"
UDP_PORT = 8053
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(dns_packet, (UDP_IP, UDP_PORT))


### Receive DNS response ###
data, addr = sock.recvfrom(1024)
print(data)
```