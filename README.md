# uFastAuthD 

Unmanarc Fast Authentication Daemon  
  
Author: Aaron Mizrachi (unmanarc) <aaron@unmanarc.com>   
Main License: GPLv3   


***
## Project Description

This server provides a directory/authorization implementation for managing users for your applications.

***
## Building uFastAuthD

### Instructions:

as root:

```
cmake .
make -j12
make install
```

Then:
- copy the **/etc/ufastauthd** directory
- create the **/var/lib/cx2_authserver** if does not exist
- fully update/rewrite **/var/www/ufastauthd**


***
## Compatibility

This program was tested so far in:

* Fedora Linux 34
* Ubuntu 20.04 LTS (Server)
* CentOS/RHEL 7/8

### Overall Pre-requisites:

* cx2Framework
* C++11 Compatible Compiler (like GCC >=5)
* pthread
* openssl (1.1.x)
* jsoncpp
* boost
* SQLite3 devel libs
