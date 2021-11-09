# uFastAuthD 

Unmanarc Fast Authentication Daemon  
  
Author: Aaron Mizrachi (unmanarc) <aaron@unmanarc.com>   
Main License: GPLv3   


***
## Project Description

This server provides a directory/authorization implementation for managing users for your applications.

***
## Building/Installing uFastAuthD

### Building Instructions:

First, you must remember to have installed cxFramework2

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
- create the **/var/lib/cx2_authserver** if does not exist
- fully update/rewrite **/var/www/ufastauthd**

```
cp -a ~/uFastAuthD/etc/ufastauthd /etc/
mkdir -p /var/www
mkdir -p /var/lib/cx2_authserver
rm -rf /var/www/ufastauthd
cp -a ~/uFastAuthD/var/www/ufastauthd /var/www
```

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

* cxFramework2
* C++11 Compatible Compiler (like GCC >=5)
* pthread
* openssl (1.1.x)
* jsoncpp
* boost
* SQLite3 devel libs
