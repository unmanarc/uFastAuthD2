#pragma once

#include "WebLogin/logindirectorymanager.h"

#include <Mantids30/Server_WebCore/apienginecore.h>
#include <Mantids30/Program_Logs/applog.h>
#include <Mantids30/Program_Logs/rpclog.h>
#include <Mantids30/Protocol_FastRPC1/fastrpc.h>

#include "IdentityManager/identitymanager.h"

#include <boost/property_tree/ptree.hpp>


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

    static Mantids30::Network::Servers::Web::APIEngineCore *getWebLoginServer();
    static void setWebLoginServer(Mantids30::Network::Servers::Web::APIEngineCore *newWebLoginServer);

    static Mantids30::Network::Protocols::FastRPC::FastRPC1 *getFastRPC();
    static void setFastRPC(Mantids30::Network::Protocols::FastRPC::FastRPC1 *newFastRPC);

private:
    static Mantids30::Program::Logs::RPCLog * rpclog;
    static bool resetAdminPasswd;
    static boost::property_tree::ptree pConfig;
    static LoginDirectoryManager * loginDirManager;
    static Mantids30::Program::Logs::AppLog * applog;
    static IdentityManager * identityManager;
    static Mantids30::Network::Servers::Web::APIEngineCore * webLoginServer;
    static Mantids30::Network::Protocols::FastRPC::FastRPC1 * fastRPC;

};


