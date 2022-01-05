# Manual Build/Install Instructions

This guide will help you in case you want to understand/build/install uFastAuthD from scratch.

***

## STEP 1: Building

### Overall Pre-requisites:

* gcc-c++ or C++11 Compatible Compiler (like GCC >=5)
* SystemD enabled system (ubuntu, centos, fedora, etc)
* libMantids-devel
* libMantids-sqlite
* pthread
* zlib-devel
* openssl-devel
* jsoncpp-devel
* boost-devel
* sqlite-devel

***

Having these prerequisites (eg. by yum install), you can start the build process (as root) by doing:

```
cd /root
git clone https://github.com/unmanarc/uFastAuthD
cmake -B../builds/uFastAuthD . -DCMAKE_VERBOSE_MAKEFILE=ON
cd ../builds/uFastAuthD
make -j12 install
```

Now, the application is installed in the operating system, you can proceed to the next step

## STEP 2: Installing files and configs

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

## STEP 3: Service Intialization

We are going to create the services by executing:

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

Now, check via `journalctl -xefu ufastauthd` the path of syspwd-randomvalue file in /tmp:

```
File '/tmp/syspwd-98ZAisMO' created with the super-user password. Login and change it immediatly
```

Take the password inside that file, and login as `admin` into the website (change the ip address or domain corresponding to your installation...):

```
> https://192.168.1.100:40443/login
```
 
