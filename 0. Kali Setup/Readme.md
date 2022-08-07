# Kali Setup

## Super Basic and Simple Setup for CTFs
- Run script from my [github](https://github.com/bianfusia/Beeeatant-THM-Box) repo.
``` bash
wget https://raw.githubusercontent.com/bianfusia/Beeeatant-THM-Box/main/bee.sh
chmod +x bee.sh
sudo ./bee.sh
```

## Proper Setup for Kali Through PimpMyKali

- You may refer to the [pimpmykali](https://github.com/Dewalt-arch/pimpmykali) github repo for more info.

```bash
# Run this if you use pimpmykali before
rm -rf pimpmykali/
```
```bash
# install
git clone https://github.com/Dewalt-arch/pimpmykali
cd pimpmykali
sudo ./pimpmykali.sh
```
Note: For a new kali vm, run menu option N

## Setting up Burpsuite

1. Refer to this [page](https://github.com/bianfusia/PEH-notes/blob/main/04.%20Reconnaissance/Info%20Gathering%20with%20BurpSuite.md) for Burpsuite setup
2. Highly recommend to install this [Extender](https://github.com/bianfusia/PEH-notes/blob/main/04.%20Reconnaissance/Info%20Gathering%20with%20BurpSuite.md)

## Running Kali as ```root``` (Not Recommended)
```bash
#this is to switch you to root user
sudo su
#press <enter>

#change root password
passwd root

#<enter new password>
```

