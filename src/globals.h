#ifndef GLOBALS_H
#define GLOBALS_H


#include <Mantids29/Protocol_FastRPC1/fastrpc.h>
#include <Mantids29/Program_Logs/applog.h>
#include <Mantids29/Program_Logs/rpclog.h>
#include <Mantids29/Auth/manager.h>

#include <boost/property_tree/ini_parser.hpp>

#include <mutex>
#include <list>

#define LOG_APP Globals::getAppLog()
#define LOG_RPC Globals::getRPCLog()

namespace AUTHSERVER {

class Globals
{
public:
    Globals();

    static Mantids29::Program::Logs::AppLog *getAppLog();
    static void setAppLog(Mantids29::Program::Logs::AppLog *value);

    static Mantids29::Program::Logs::RPCLog *getRPCLog();
    static void setRPCLog(Mantids29::Program::Logs::RPCLog *value);

    static boost::property_tree::ptree * getConfig_main();

    static std::string getRulesDir();
    static void setRulesDir(const std::string &value);

    static std::string getActionsDir();
    static void setActionsDir(const std::string &value);

    static Mantids29::Network::Protocols::FastRPC::FastRPC1 *getFastRPC();
    static void setFastRPC(Mantids29::Network::Protocols::FastRPC::FastRPC1 *value);

    static Mantids29::Authentication::Manager *getAuthManager();
    static void setAuthManager(Mantids29::Authentication::Manager *value);


    static bool getResetAdminPasswd();
    static void setResetAdminPasswd(bool newResetAdminPasswd);

private:
    static bool resetAdminPasswd;
    static std::string rulesDir,actionsDir;
    static std::mutex mDatabase,mDirs;
    static boost::property_tree::ptree config_main;
    static Mantids29::Program::Logs::AppLog * applog;
    static Mantids29::Program::Logs::RPCLog * rpclog;


    static Mantids29::Authentication::Manager * authManager;
    static Mantids29::Network::Protocols::FastRPC::FastRPC1 * fastRPC;

};

}

#endif // GLOBALS_H
