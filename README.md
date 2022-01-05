# uFastAuthD 

Unmanarc Fast Authentication Daemon  
  
Author: Aaron Mizrachi (unmanarc) <aaron@unmanarc.com>   
Main License: GPLv3   

***
## Project Description

This server provides a directory/authorization implementation for managing users for your applications.

***
## Installing packages (HOWTO)


- [Manual build guide](BUILD.md)
- COPR Packages (Fedora/CentOS/RHEL/etc):  
[![Copr build status](https://copr.fedorainfracloud.org/coprs/amizrachi/uFastAuthD/package/uFastAuthD/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/amizrachi/uFastAuthD/package/uFastAuthD/)


### Simple installation guide for Fedora/RHEL:

- First, proceed to install EPEL in your distribution (https://docs.fedoraproject.org/en-US/epel/), sometimes this is required for jsoncpp.


- Then, proceed to activate our repo's and download/install uFastAuthD:
```bash
# NOTE: for RHEL7 replace dnf by yum
dnf copr enable amizrachi/libMantids
dnf copr enable amizrachi/uFastAuthD

dnf -y install uFastAuthD
```

- Once installed, you can continue by activating/enabling the service:
```bash
systemctl enable --now uFastAuthD
```

- Don't forget to open the firewall:

```bash
# Add Website port:
firewall-cmd --zone=public --permanent --add-port 40443/tcp
# Add Authentication daemon port:
firewall-cmd --zone=public --permanent --add-port 30301/tcp
# Reload Firewall rules
firewall-cmd --reload
```

- If it's your first time installing this program, you can check for the master password using journalctl:
```bash
journalctl -xefu uFastAuthD
```

- And in that output you should check the path of syspwd-randomvalue file in /tmp. eg.:

```
File '/tmp/syspwd-98ZAisMO' created with the super-user password. Login and change it immediatly
```

- Now you can proceed to discover and change the temporary password (change **98ZAisMO** by the random value that your system has printed):

```bash
cat /tmp/syspwd-98ZAisMO
```

- Then, take the string inside that file and use it as password, and login as `admin` into the website (change the ip address or domain corresponding to your installation...): https://YOURHOSTIP:40443/login

- Now you are ready to operate the authentication daemon.