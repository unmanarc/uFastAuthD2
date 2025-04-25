#pragma once

#include "weblogin/logindirectorymanager.h"

#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/rpclog.h>
#include "IdentityManager/identitymanager.h"

#include <boost/property_tree/ini_parser.hpp>

#include <inttypes.h>

#define LOG_RPC Globals::getRPCLog()
#define LOG_APP Globals::getAppLog()

class Globals
{
public:
    Globals() = default;

    static Mantids30::Program::Logs::RPCLog *getRPCLog();
    static void setRPCLog(Mantids30::Program::Logs::RPCLog *value);

    static Mantids30::Program::Logs::AppLog *getAppLog();
    static void setAppLog(Mantids30::Program::Logs::AppLog *value);

    static boost::property_tree::ptree * getConfig();

    static IdentityManager *getIdentityManager();
    static void setIdentityManager(IdentityManager *value);

    static bool getResetAdminPasswd();
    static void setResetAdminPasswd(bool newResetAdminPasswd);

    static LoginDirectoryManager *getLoginDirManager();
    static void setLoginDirManager(LoginDirectoryManager *newLoginDirManager);

private:
    static Mantids30::Program::Logs::RPCLog * rpclog;
    static bool resetAdminPasswd;
    static boost::property_tree::ptree pConfig;
    static LoginDirectoryManager * loginDirManager;
    static Mantids30::Program::Logs::AppLog * applog;
    static IdentityManager * identityManager;

};


