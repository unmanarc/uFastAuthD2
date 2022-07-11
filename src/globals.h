#ifndef GLOBALS_H
#define GLOBALS_H


#include <mdz_xrpc_fast/fastrpc.h>
#include <mdz_auth/manager.h>
#include <boost/property_tree/ini_parser.hpp>
#include <mdz_prg_logs/applog.h>
#include <mdz_prg_logs/rpclog.h>
#include <mutex>
#include <list>

#define LOG_APP Globals::getAppLog()
#define LOG_RPC Globals::getRPCLog()

namespace AUTHSERVER {

class Globals
{
public:
    Globals();

    static Mantids::Application::Logs::AppLog *getAppLog();
    static void setAppLog(Mantids::Application::Logs::AppLog *value);

    static Mantids::Application::Logs::RPCLog *getRPCLog();
    static void setRPCLog(Mantids::Application::Logs::RPCLog *value);

    static boost::property_tree::ptree * getConfig_main();

    static std::string getRulesDir();
    static void setRulesDir(const std::string &value);

    static std::string getActionsDir();
    static void setActionsDir(const std::string &value);

    static Mantids::RPC::Fast::FastRPC *getFastRPC();
    static void setFastRPC(Mantids::RPC::Fast::FastRPC *value);

    static Mantids::Authentication::Manager *getAuthManager();
    static void setAuthManager(Mantids::Authentication::Manager *value);


    static bool getResetAdminPasswd();
    static void setResetAdminPasswd(bool newResetAdminPasswd);

private:
    static bool resetAdminPasswd;
    static std::string rulesDir,actionsDir;
    static std::mutex mDatabase,mDirs;
    static boost::property_tree::ptree config_main;
    static Mantids::Application::Logs::AppLog * applog;
    static Mantids::Application::Logs::RPCLog * rpclog;


    static Mantids::Authentication::Manager * authManager;
    static Mantids::RPC::Fast::FastRPC * fastRPC;

};

}

#endif // GLOBALS_H
