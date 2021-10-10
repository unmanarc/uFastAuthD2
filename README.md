# uFastAuthD 

Unmanarc Fast Authentication Daemon  
  
Author: Aaron Mizrachi (unmanarc) <aaron@unmanarc.com>   
Main License: GPLv3   


***
## Building uFastAuthD

### Instructions:

as root:

```
qmake . PREFIX=/usr
make -j8 install
```

`NOTICE: This project does not use QT libraries, We only rely on QT Make files`

***
## Project Description

This server provides a directory/authorization implementation for managing users for your applications.


***
## Compatibility

This library was tested so far in:

* Fedora Linux 32
* Ubuntu 18.04/20.04
* CentOS/RHEL 7/8
* CentOS/RHEL 5/6, but may require special/external C++11 compilers, we don't recommend it

### Overall Pre-requisites:

* cx2Framework
* C++11 Compatible Compiler (like GCC >=5)
* pthread
* openssl (1.1.x)
* jsoncpp
* boost
* SQLite3 devel libs

### Win32 Pre-requisites:

* Fedora MinGW (x86_64 or i686) compiler and required libs
