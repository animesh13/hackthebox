# Bashed

## Overview

This was a fairly easy box. Initial foothold was achieved by a backdoor and from there exploit a root cron to get into root.

![Bashed.png](uploads/Bashed.png)

**Name -** Bashed

**Difficulty -** Easy

**OS -** Linux

**Points -** 20

## Information Gathering

### **Port Scan**

Basic nmap scan

![Untitled](uploads/Untitled.png)

Service Scan

```bash
╭╴root @ …/c/Users/SiliconBits took 21s
╰─ nmap 10.129.74.102 -sC -sV -p 80
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-31 17:45 +06
Nmap scan report for 10.129.74.102
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.68 seconds
```

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](uploads/Untitled%201.png)

Gobuster found some interesting directory.

![Untitled](uploads/Untitled%202.png)

on the php directory there is a single file but not usable at the moment. Will look at it later if necessary

![Untitled](uploads/Untitled%203.png)

/dev directory contains backdoor

![Untitled](uploads/Untitled%204.png)

phpbash.php

![Untitled](uploads/Untitled%205.png)

## Getting User.txt

From the user’s home directory, It was easy to get the user.txt file

![Untitled](uploads/Untitled%206.png)

User flag - c56de767dcc62cf4aa6e763943b13573

## Enumeration for privilege escalation

I took a reverse shell for further testing

![Untitled](uploads/Untitled%207.png)

It was very easy to switch to scriptmanager user

![Untitled](uploads/Untitled%208.png)

## Getting root.txt

There was a cron running as root. It is running every .py file from /scripts directory.

![Untitled](uploads/Untitled%209.png)

So, I changed the [text.py](http://text.py) file with following payload

![Untitled](uploads/Untitled%2010.png)

And after some time I got the flag

![Untitled](uploads/Untitled%2011.png)

Root flag - 03801dfb739f482192e659dc9019d61e

## Flags

**user.txt -** c56de767dcc62cf4aa6e763943b13573

**root.txt -** 03801dfb739f482192e659dc9019d61e
