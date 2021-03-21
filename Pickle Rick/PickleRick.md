# Pickle Rick Try Hack Me Notes

## NMAP SCAN

```
sudo nmap -sC -sV -T4 10.10.89.136

```
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-08 20:21 MST
Nmap scan report for 10.10.89.136
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:10:42:06:db:2d:dc:9f:a8:9d:49:d9:42:69:da:44 (RSA)
|   256 f9:68:3a:35:c7:8c:d2:4c:8a:c5:3e:e6:b5:7f:70:65 (ECDSA)
|_  256 d8:b8:23:24:16:ef:6b:63:01:53:a7:51:b0:a8:af:fe (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## GoBuster

```
gobuster dir -u http://10.10.89.136 -w /usr/share/wordlists/dirb/common.txt 
```
```
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/assets (Status: 301)
/index.html (Status: 200)
/robots.txt (Status: 200)
/server-status (Status: 403)
```

## Nikto



## Password

The website contained a robots.txt file and inside there was only written...

```
Wubbalubbadubdub
```
I assumt this is password for the username we found earlier. The nikto scan gave us a login.php page. Lets try. (I assume its a password since its a recurring saying on the show)

## LOGIN

```
username: R1ckRul3s
password: xxxxxxxxxxxxxx
```
Success! We are now logged into via remote cli webpage.

## CLI

First I checked with a "whoami" command to see our user. We are www-data.

Next I checked what directory we are in. We are in "/var/log/html" which is the default directory for http servers on linux devices.

Then I ran a "ls" command to see all items in the directory.

```
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 Sup3rS3cretPickl3Ingred.txt
drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 10  2019 assets
-rwxr-xr-x 1 ubuntu ubuntu   54 Feb 10  2019 clue.txt
-rwxr-xr-x 1 ubuntu ubuntu 1105 Feb 10  2019 denied.php
-rwxrwxrwx 1 ubuntu ubuntu 1062 Feb 10  2019 index.html
-rwxr-xr-x 1 ubuntu ubuntu 1438 Feb 10  2019 login.php
-rwxr-xr-x 1 ubuntu ubuntu 2044 Feb 10  2019 portal.php
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 robots.txt
```
Clue and the Super Secret Ingredient files look useful. 

The commands cat, more are disabled but less turned out to work on clue.txt, it says:

```
Look around the file system for the other ingredient.
```
Running less on Super secret got the first flag...

```
xxx xxxxxx xxxx
```
Now I used the CLI to enumerate the home directory. I was able to see a file for the second ingredient:

```
x xxxxx xxxx
```

## Privilege Escalasion

I checked the CLI for the command sudo. It ran with no output. I assume that means it worked. SO I ran sudo -l to list what this user can run as sudo. It can run everything with no password. Now we can see what is inside the root directory.

```
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Feb 10  2019 .ssh
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
drwxr-xr-x  3 root root 4096 Feb 10  2019 snap
```
ohhhhh we see a ssh directory and the third and final text document.

```
sudo less /root/3rd.txt

3rd ingredients: XXXXXXXXXX
```

## SSH Directory

Nadda.

## Summary

This was a quick and fun challenge to get my brain going. I need to start doing more web application boxes to try and better myself. I understand alot of the core concepts of web application testing. But however I run into an issue when push coes to show whats going on with the devices if I cant get a useful directory. 

