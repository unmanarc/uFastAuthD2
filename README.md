# uFastAuthD 

Unmanarc Fast Authentication Daemon  
  
Author: Aaron Mizrachi (unmanarc) <aaron@unmanarc.com>   
Main License: GPLv3   

***
## Builds

- COPR (Fedora/CentOS/etc):  
[![Copr build status](https://copr.fedorainfracloud.org/coprs/amizrachi/uFastAuthD/package/uFastAuthD/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/amizrachi/uFastAuthD/package/uFastAuthD/)


Install in Fedora/RHEL8/9:
```bash
dnf copr enable amizrachi/libMantids
dnf copr enable amizrachi/uFastAuthD

dnf -y install uFastAuthD
```

Install in RHEL7:
```bash
yum copr enable amizrachi/libMantids
yum copr enable amizrachi/uFastAuthD

yum -y install uFastAuthD
```


***
## Project Description

This server provides a directory/authorization implementation for managing users for your applications.

***
## Building/Installing uFastAuthD

### Building Instructions:

First, you must remember to have installed libMantids

as root:

```
cd /root
git clone https://github.com/unmanarc/uFastAuthD
cmake -B../builds/uFastAuthD . -DCMAKE_VERBOSE_MAKEFILE=ON
cd ../builds/uFastAuthD
make -j12 install
```

### Installing Instructions:

Then:
- copy the **/etc/ufastauthd** directory
- create the **/var/lib/ufastauthd** if does not exist
- fully update/rewrite **/var/www/ufastauthd**

```
cp -a ~/uFastAuthD/etc/ufastauthd /etc/
chmod 600 /etc/ufastauthd/snakeoil.key
mkdir -p /var/www
mkdir -p /var/lib/ufastauthd
rm -rf /var/www/ufastauthd
cp -a ~/uFastAuthD/var/www/ufastauthd /var/www
```

Security Alert:

`Remember to change the snakeoil X.509 Certificates with your own ones, if not the communication can be eavesdropped or tampered!!!`

### Service Intialization Instructions:

- Create the services...
- Restart daemon
```
cat << 'EOF' | install -m 640 /dev/stdin /usr/lib/systemd/system/ufastauthd.service
[Unit]
Description=Unmanarc Fast Authentication Daemon
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
EnvironmentFile=/etc/default/ufastauthd
ExecStart=/usr/local/bin/uFastAuthD

[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' | install -m 640 /dev/stdin /etc/default/ufastauthd
LD_LIBRARY_PATH=/usr/local/lib:
EOF

systemctl daemon-reload
systemctl enable --now ufastauthd.service
```

Now, check via `journalctl -xefu ufastauthd` the path of syspwd file in /tmp:

```
File '/tmp/syspwd-98ZAisMO' created with the super-user password. Login and change it immediatly
```

Take the password inside, and login as `admin` into the website (change the ip address or domain corresponding to your installation...):

```
> https://192.168.1.100:40443/login
```


***
## Compatibility

This program was tested so far in:

* Fedora Linux 34 (remember to replace ` /etc/default by /etc/sysconfig`)
* Ubuntu 20.04 LTS (Server)
* CentOS/RHEL 7/8

### Overall Pre-requisites:

* libMantids
* C++11 Compatible Compiler (like GCC >=5)
* pthread
* openssl (1.1.x)
* jsoncpp
* boost
* SQLite3 devel libs
