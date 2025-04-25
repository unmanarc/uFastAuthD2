#pragma once

#include "weblogin/logindirectorymanager.h"

#include <Mantids30/Protocol_FastRPC1/fastrpc.h>
#include <Mantids30/Protocol_FastRPC3/fastrpc3.h>

#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/rpclog.h>
#include "IdentityManager/identitymanager.h"

#include <boost/property_tree/ini_parser.hpp>

#include <inttypes.h>


#define LOG_APP Globals::getAppLog()
#define LOG_RPC Globals::getRPCLog()

class Globals
{
public:
    Globals() = default;

    static Mantids30::Program::Logs::AppLog *getAppLog();
    static void setAppLog(Mantids30::Program::Logs::AppLog *value);

    static Mantids30::Program::Logs::RPCLog *getRPCLog();
    static void setRPCLog(Mantids30::Program::Logs::RPCLog *value);

    static boost::property_tree::ptree * getConfig();

    // This FastRPC1 protocol will manage login from the application to the authenticator (IAM)
    static Mantids30::Network::Protocols::FastRPC::FastRPC1 *getLoginFastRPC();
    static void setLoginFastRPC(Mantids30::Network::Protocols::FastRPC::FastRPC1 *value);

    static IdentityManager *getIdentityManager();
    static void setIdentityManager(IdentityManager *value);

    static bool getResetAdminPasswd();
    static void setResetAdminPasswd(bool newResetAdminPasswd);

    static Mantids30::Network::Protocols::FastRPC::FastRPC3 *getWebAdminManager();
    static void setWebAdminManager(Mantids30::Network::Protocols::FastRPC::FastRPC3 *newAdminRPC);

    static LoginDirectoryManager *getLoginDirManager();
    static void setLoginDirManager(LoginDirectoryManager *newLoginDirManager);

private:
    static bool resetAdminPasswd;
    static boost::property_tree::ptree pConfig;
    static LoginDirectoryManager * loginDirManager;
    static Mantids30::Program::Logs::AppLog * applog;
    static Mantids30::Program::Logs::RPCLog * rpclog;
    static IdentityManager * identityManager;
    static Mantids30::Network::Protocols::FastRPC::FastRPC1 * loginFastRPC;
    static Mantids30::Network::Protocols::FastRPC::FastRPC3 * adminRPC;

};


