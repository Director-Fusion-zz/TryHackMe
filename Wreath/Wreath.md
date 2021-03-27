---
title: "Wreath Network - A Penetration Test and An Act of Learning - Try Hack Me"
author: [Cory Keller]
date: "2021-03-28"
subject: "Wreath Network Penetration Test"
keywords: [Pentesting, Try Hack Me, Wreath, Director Fusion]
lang: "en"
titlepage: true
titlepage-text-color: "7137C8"
titlepage-rule-color: "7137C8"
titlepage-rule-height: 2
logo: "/home/cory/Pictures/doc_0.webp"
logo-width: 100mm
colorlinks: true
header-includes:
- |
  ```{=latex}
  \usepackage{awesomebox}
  ```
pandoc-latex-environment:
  noteblock: [note]
  tipblock: [tip]
  warningblock: [warning]
  cautionblock: [caution]
  importantblock: [important]
...

# Wreath Network -  Try Hack Me

# MY IP - 10.50.99.27/24

## Scope

I was asked by a personal friend Thomas Wreath to perform a penetration test on his personal setup. The three machines in scope are:

1 personal computer running a server OS instead of a traditional OS.

1 Web Server (port forwarded ***Probably a hint***)

1 Git Server

## Network NMAP Scan

Ran the first scan with the -sn flag set on nmap. This will slowly...yet some what reliably tell us how many hosts are up on the network.

```markdown
> nmap -sn 10.200.98.0/24
```

```markdown
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 19:38 MDT
Nmap scan report for 10.200.98.200
Host is up (0.19s latency).
Nmap scan report for 10.200.98.250
Host is up (0.20s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 107.97 seconds
```

Next, I will perform a service scan with those two devices. I want to see what version and services these machines are serving. Depending on the service(s). I will run a nmap nse script to enumerate the services even further or go to manual tools.

```markdown
nmap -sC -sV -oN nmap/wreath.nmap -p- -T4 10.200.98.200,250
```
![NMAP Service Scan](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/Wreath-nmap.png)

---

The next enumeration scan is the OS guesser and the http enumeration scan.

```markdown
sudo nmap -oN nmap/Service-all.nmap -A --script=http-enum -p22,80,443,9090,10000 10.200.98.200 

80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
```
![NMAP Service Scan](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/

---

The scan results look like we are dealing wit a centos server.

---

The last nmap scan on the webserver(10.200.98.200). I performed a vuln scan via nmap. I got a lot of useful information

```markdown
sudo nmap -oN nmap/Service-all.nmap -A --script=vuln -p22,80,443,9090,10000 10.200.98.200
```
```markdown
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 20:30 MDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.200.98.200
Host is up (0.22s latency).

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:8.0: 
|     	CVE-2020-15778	6.8	https://vulners.com/cve/CVE-2020-15778
|     	CVE-2021-28041	4.6	https://vulners.com/cve/CVE-2021-28041
|     	CVE-2019-16905	4.4	https://vulners.com/cve/CVE-2019-16905
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	MSF:EXPLOIT/SOLARIS/SSH/PAM_USERNAME_BOF/	0.0	https://vulners.com/metasploit/MSF:EXPLOIT/SOLARIS/SSH/PAM_USERNAME_BOF/	*EXPLOIT*
|     	MSF:EXPLOIT/LINUX/SSH/CERAGON_FIBEAIR_KNOWN_PRIVKEY/	0.0	https://vulners.com/metasploit/MSF:EXPLOIT/LINUX/SSH/CERAGON_FIBEAIR_KNOWN_PRIVKEY/	*EXPLOIT*
|_    	MSF:AUXILIARY/SCANNER/SSH/FORTINET_BACKDOOR/	0.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/FORTINET_BACKDOOR/	*EXPLOIT*
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.37: 
|     	CVE-2020-11984	7.5	https://vulners.com/cve/CVE-2020-11984
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2019-10097	6.0	https://vulners.com/cve/CVE-2019-10097
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	CVE-2019-0215	6.0	https://vulners.com/cve/CVE-2019-0215
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
|     	CVE-2020-9490	5.0	https://vulners.com/cve/CVE-2020-9490
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-10081	5.0	https://vulners.com/cve/CVE-2019-10081
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11993	4.3	https://vulners.com/cve/CVE-2020-11993
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
|     	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
|     	EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
|     	1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
|_    	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /css/: Potentially interesting folder w/ directory listing
|   /icons/: Potentially interesting folder w/ directory listing
|   /img/: Potentially interesting folder w/ directory listing
|_  /js/: Potentially interesting folder w/ directory listing
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
| http-sql-injection: 
|   Possible sqli for queries:
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dD%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dD%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dD%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     https://10.200.98.200:443/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|_    https://10.200.98.200:443/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_sslv2-drown: 
| vulners: 
|   cpe:/a:apache:http_server:2.4.37: 
|     	CVE-2020-11984	7.5	https://vulners.com/cve/CVE-2020-11984
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2019-10097	6.0	https://vulners.com/cve/CVE-2019-10097
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	CVE-2019-0215	6.0	https://vulners.com/cve/CVE-2019-0215
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
|     	CVE-2020-9490	5.0	https://vulners.com/cve/CVE-2020-9490
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-10081	5.0	https://vulners.com/cve/CVE-2019-10081
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11993	4.3	https://vulners.com/cve/CVE-2020-11993
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
|     	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
|     	EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
|     	1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
|_    	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-litespeed-sourcecode-download: 
| Litespeed Web Server Source Code Disclosure (CVE-2010-2333)
| /index.php source code:
| <h1>Error - Document follows</h1>
|_<p>This web server is running in SSL mode. Try the URL <a href='https://ip-10-200-98-200.eu-west-1.compute.internal:10000/'>https://ip-10-200-98-200.eu-west-1.compute.internal:10000/</a> instead.<br></p>
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)
| http-phpmyadmin-dir-traversal: 
|   VULNERABLE:
|   phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion
|     State: UNKNOWN (unable to test)
|     IDs:  CVE:CVE-2005-3299
|       PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
|       
|     Disclosure date: 2005-10-nil
|     Extra information:
|       ../../../../../etc/passwd :
|   <h1>Error - Document follows</h1>
|   <p>This web server is running in SSL mode. Try the URL <a href='https://ip-10-200-98-200.eu-west-1.compute.internal:10000/'>https://ip-10-200-98-200.eu-west-1.compute.internal:10000/</a> instead.<br></p>
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299
|_      http://www.exploit-db.com/exploits/1244/
|_http-server-header: MiniServ/1.890
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|       
|     Disclosure date: 2006-06-29
|     References:
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
|_      http://www.exploit-db.com/exploits/1997/
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Linux 3.7 (90%), Linux 5.1 (90%), Ubiquiti AirOS 5.5.9 (90%), Linux 5.0 - 5.4 (89%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9090/tcp)
HOP RTT       ADDRESS
1   244.55 ms 10.50.99.1
2   244.72 ms 10.200.98.200
```
Performing some research ***Thunder claps*** BY THE POWER OF GOOGLE...

This server that is hosted on port 10000, "WebMin 1.890" is susceptible to unauthorized remote code execution. https://medium.com/@foxsin34/webmin-1-890-exploit-unauthorized-rce-cve-2019-15107-23e4d5a9c3b4

The github link:

https://raw.githubusercontent.com/foxsin34/WebMin-1.890-Exploit-unauthorized-RCE/master/webmin-1.890_exploit.pys

Followed the link to download the exploit file.

Lets try and break this exploit down...

The exploit defines a function named exploit that accepts arguments:

1. target
2. port
3. url
4. command

A header and a payload are defined. Then it takes those arguments into a curl command. 

Super high level overview but it appears that this is not something that is impossible for mortal men like me.

## Web Server

When trying to attempt to log into the webserver I could not connect because there is no DNS for serving this web application. I modified my "/etc/hosts" file to add the domain thomaswreath.thm. Now I can connect.

### Task 5 Question 1

1. How many of the first 15K ports are open on the target?

> 4

2. What OS does NMAP think is running?

> centos

3. What site is the server trying to redirect you too?

> https://thomaswreath.thm/

4. Read through the page what is Thomas's phone number?

> +447821548812 

5. What server version does NMAP detect?

>  MiniServ 1.890 (Webmin httpd)

6. What is the CVE number for this exploit?

> CVE-2019-15107

## Webmin Exploit

When running the command i followed the persons blog. You can run some multi-worded command by placing quotes around it.

![Root](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/webserv-root.png)

---

![Wget-Fail 1](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/wget-fail.png)

---

![Wget-Fail 2](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/wget-fail2.png)

---

Now I have a stabile shell from the explit creating a stabile netcat reverse shell.

TIme for dir enumeration.

## Task 6 Quesitons

1. What is the root users password hash?

> $6$i9vT8tk3SoXXxK2P$HDIAwho9FOdd4QCecIJKwAwwh8Hwl.BdsbMOUAd3X/chSCvrmpfy.5lrLgnRVNq6/6g0PxK9VqSdy47/qKXad1::0:99999:7:::

2. Whatis the full path to the file to maintain access.

> /root/.ssh/id_rsa

I downloaded the root user's ssh key then changed the permissions to allow ssh to utilize the key.

```markdown
chmod 600 id_rsa
```
Now I have a stable bash shell after running the following:

```markdown
ssh -i id_rsa root@10.200.98.200
```
![ssh-root](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/root-ssh.png)

---

![Curl-download](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/meter-download.png)

I was able to download a msfvenom payload for a meterpreter shell. Finally I can do this as the lord intended...with a meterpreter shell.

![Root-Meterpreter](/home/cory/Try\ Hack\ Me/Wreath/Screenshots/meterpreter.png)


## Task 8 Question

3. How can you use living off the land to see which ip addresses are active and allow for ICMP echo requests on the "172.16.0.x/24 network using bash?

> for i in {1..255}; do (ping-c 172.16.0.${i} | grep "bytes from" &); done

# Night 1 Summary

We enumerated the webserver. 

Identified a root level RCE with CVE-2019-15107.

Exploited it to created a reverse shell via netcat.

Pillaged the ssh id_rsa key from the "/root/.ssh" directory.

Used ssh bash connection to download a meterpreter payload and get an meterpreter shell in metasploit.

## Pivoting and Proxychaining

I setup my socks proxy server via metaplsploits socks proxy module and set it to port 88 and edited my proxy chains configuraiton file to have the following listed on the end of the proxychains4.conf file:

```markdown
socks4 127.0.0.1 88
socks5 127.0.0.1 88
```
While enumerating the compromised machince I found a file called "zoki" in the /tmp directory, it looked like an interesting name and gave me 3 new IPs to look into.

1. 10.200.98.100
2. 10.200.98.150
3. 10.200.98.250

```markdown
Nmap scan report for ip-10-200-98-100.eu-west-1.compute.internal (10.200.98.100)
Host is up (0.00021s latency).
MAC Address: 02:3A:F2:DB:E3:0D (Unknown)
Nmap scan report for ip-10-200-98-150.eu-west-1.compute.internal (10.200.98.150)
Host is up (-0.10s latency).
MAC Address: 02:C2:DD:8E:F1:A9 (Unknown)
Nmap scan report for ip-10-200-98-250.eu-west-1.compute.internal (10.200.98.250)
Host is up (0.00022s latency).
MAC Address: 02:9C:11:2F:82:17 (Unknown)
Nmap scan report for ip-10-200-98-200.eu-west-1.compute.internal (10.200.98.200)
Host is up.
```
## 10.200.98.250

## NMAP SCAN

```markdown
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:20:62:d2:ba:36:93:54:15:3a:aa:0a:08:f1:a7:19 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyLp5ZEiaXOVa95IGCrYqB1Ow235dZ4bQGATlOvmsN2+wnvDmyRQA6vyFq7/pYX/vT2xkbWlNzb7/yOUi4Qp3W83vqUdSI8ibTtxKJ48x0faAQmH6asSFhgAvqMwgUM/7KcbMve2AhOYkkHMwJW+rncEN7SQo5RMAdIuaKqiyO0Fph7OfAzT5hZcypRMzXJ7xrTMIDfrxGtnLNfIBrgSeVwgb6BkQvoHJImUS2k+4jkq9IgQQ2uYZC8wXKU6h0dxwEpIHH9+GgkRlt7HgA886Qd6yFRFgKAby7YJ7arpKx0lTEG1sIUA0Hf+5Bv4zrkCiKZrVMMec6uUsedyz+QV0Z
|   256 90:5b:20:a9:0d:78:d2:7c:5e:50:25:e5:f3:d8:94:31 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJw7SZFGSQ2KSLhlhSn8BPseyanyc+koGCGXrnKfcvHZXi3mqCYMkf7RuNFTrU7B7Om0uHZJ213acNLpPlYXQN8=
|   256 7f:61:c9:bc:ef:8a:38:a1:10:21:bb:f5:e2:cc:4d:8e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGBzi3t2P5ZLzjCrtCkKowtxKKsuUwMo83lID45oRj8Y
1337/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Error
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Nikto and Gobuster

No informaton enumerated.

## NMAP on the compormised host

Used my metasploit sessions to upload the NMAP-Username to the compromised system. 

```markdown
Nmap scan report for ip-10-200-98-150.eu-west-1.compute.internal (10.200.98.150)
Host is up (0.00045s latency).
Not shown: 6147 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
MAC Address: 02:C2:DD:8E:F1:A9 (Unknown)
```

Now I did a complete service and vuln scan on the host and only those ports.

```markdown
NO LUCK
```

This did not work as it is only the standalone binary.

trying a proxychains scan.

Connection refused. Adding a portfwd.

portfwd no dice.

I forgot to add my routes in my metasploit session to see the new devices.

I successfully scanned services and versions on 10.200.92.150

```markdown
Nmap scan report for 10.200.98.150
Host is up (5.3s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PH
|_http-server-header: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3
|_http-title: Page not found at /
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=git-serv
| Not valid before: 2020-11-07T14:48:18
|_Not valid after:  2021-05-09T14:48:18
|_ssl-date: 2021-03-26T20:42:46+00:00; -13s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The scan returned information about a git-serv, and the questions led to it. I was bot able to foxy proxy to the webpage to try the log in so I left it to the automated tools. 

Performed a searchsploit search for the terms "gitstack 2.3.10". It returned the edb 43777.py. 

I copied over to the current directory and renames it "git-rce.py"

## SSHUTTLE

Here is where I learned something so useful I wanted to stop doing what I was doing for a proxy(proxychains) and convert my proxy religion to sshuttle. It is essentially a poor mans VPN, their words not mine actually. What it does is to use the ssh cert that I pillaged from the webserver.