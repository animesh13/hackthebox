# Poison

## Overview

This was a fairly easy box. Initial foothold was the easiest I have solved. Later a vnc server process was exploited to get the root.

![Poison.png](uploads/Poison.png)

**Name -** Poison

**Difficulty -** Medium

**OS -** FreeBSD

**Points -** 30

## Information Gathering

### **Port Scan**

![Untitled](uploads/Untitled.png)

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](uploads/Untitled%201.png)

Looks like lfi to me

![Untitled](uploads/Untitled%202.png)

And I was right

![Untitled](uploads/Untitled%203.png)

Checking the other files I got this

![Untitled](uploads/Untitled%204.png)

pwdbackup.txt looks interesting

![Untitled](uploads/Untitled%205.png)

and after several time decoding it as base64 I got a password for charix user

![Untitled](uploads/Untitled%206.png)

So, The creds are - **charix:Charix!2#4%6&8(0**

![Untitled](uploads/Untitled%207.png)

## Getting User.txt

Getting user flag was very easy

![Untitled](uploads/Untitled%208.png)

User Flag - eaacdfb2d141b72a589233063604209c

## Getting root.txt

In the previous image, I can see a secret.zip file. The file was encrypted. The same password was used to unzip this. but there was some binary content.

![Untitled](uploads/Untitled%209.png)

Also, I found VNC server is running as root user

![Untitled](uploads/Untitled%2010.png)

The previous file might be some necessary file for exploiting the vnc

![Untitled](uploads/Untitled%2011.png)

The default vnc port is listening to 5901. I did a local port forwarding

```bash
ssh -L 5901:127.0.0.1:5901 charix@10.129.1.254
```

I used the following command to connect with the server

```bash
vncviewer -passwd secret localhost:5901
```

![Untitled](uploads/Untitled%2012.png)

Root Flag - 716d04b188419cf2bb99d891272361f5

## Flags

**user.txt -** eaacdfb2d141b72a589233063604209c

**root.txt -** 716d04b188419cf2bb99d891272361f5
