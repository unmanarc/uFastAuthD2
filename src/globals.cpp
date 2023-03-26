#include "globals.h"

using namespace AUTHSERVER;

Mantids29::Authentication::Manager * Globals::authManager = nullptr;
Mantids29::Program::Logs::AppLog * Globals::applog = nullptr;
Mantids29::Program::Logs::RPCLog * Globals::rpclog = nullptr;
std::string Globals::rulesDir,Globals::actionsDir;
std::mutex Globals::mDatabase, Globals::mDirs;
boost::property_tree::ptree Globals::config_main;
bool Globals::resetAdminPasswd = false;

Mantids29::Network::Protocols::FastRPC::FastRPC1 * Globals::fastRPC = nullptr;

Globals::Globals()
{
}

Mantids29::Program::Logs::AppLog *Globals::getAppLog()
{
    return applog;
}

void Globals::setAppLog(Mantids29::Program::Logs::AppLog *value)
{
    applog = value;
}

boost::property_tree::ptree *Globals::getConfig_main()
{
    return &config_main;
}

std::string Globals::getRulesDir()
{
    std::string r;
    mDirs.lock();
    r = rulesDir;
    mDirs.unlock();
    return r;
}

void Globals::setRulesDir(const std::string &value)
{
    mDirs.lock();
    rulesDir = value;
    mDirs.unlock();
}

std::string Globals::getActionsDir()
{
    std::string r;
    mDirs.lock();
    r = actionsDir;
    mDirs.unlock();
    return r;
}

void Globals::setActionsDir(const std::string &value)
{
    mDirs.lock();
    actionsDir = value;
    mDirs.unlock();
}

Mantids29::Network::Protocols::FastRPC::FastRPC1 *Globals::getFastRPC()
{
    return fastRPC;
}

void Globals::setFastRPC(Mantids29::Network::Protocols::FastRPC::FastRPC1 *value)
{
    fastRPC = value;
}

Mantids29::Authentication::Manager *Globals::getAuthManager()
{
    return authManager;
}

void Globals::setAuthManager(Mantids29::Authentication::Manager *value)
{
    authManager = value;
}

bool Globals::getResetAdminPasswd()
{
    return resetAdminPasswd;
}

void Globals::setResetAdminPasswd(bool newResetAdminPasswd)
{
    resetAdminPasswd = newResetAdminPasswd;
}

Mantids29::Program::Logs::RPCLog *Globals::getRPCLog()
{
    return rpclog;
}

void Globals::setRPCLog(Mantids29::Program::Logs::RPCLog *value)
{
    rpclog = value;
}
