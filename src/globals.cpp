#include "globals.h"

LoginDirectoryManager * Globals::loginDirManager = nullptr;
IdentityManager * Globals::identityManager = nullptr;
Mantids30::Program::Logs::AppLog * Globals::applog = nullptr;
Mantids30::Program::Logs::RPCLog * Globals::rpclog = nullptr;
boost::property_tree::ptree Globals::pConfig;
bool Globals::resetAdminPasswd = false;
Mantids30::Network::Protocols::FastRPC::FastRPC3 * Globals::adminRPC = nullptr;
Mantids30::Network::Protocols::FastRPC::FastRPC1 * Globals::loginFastRPC = nullptr;

Mantids30::Program::Logs::AppLog *Globals::getAppLog()
{
    return applog;
}

void Globals::setAppLog(Mantids30::Program::Logs::AppLog *value)
{
    applog = value;
}

boost::property_tree::ptree *Globals::getConfig()
{
    return &pConfig;
}

Mantids30::Network::Protocols::FastRPC::FastRPC1 *Globals::getLoginFastRPC()
{
    return loginFastRPC;
}

void Globals::setLoginFastRPC(Mantids30::Network::Protocols::FastRPC::FastRPC1 *value)
{
    loginFastRPC = value;
}

IdentityManager *Globals::getIdentityManager()
{
    return identityManager;
}

void Globals::setIdentityManager(IdentityManager *value)
{
    identityManager = value;
}

bool Globals::getResetAdminPasswd()
{
    return resetAdminPasswd;
}

void Globals::setResetAdminPasswd(bool newResetAdminPasswd)
{
    resetAdminPasswd = newResetAdminPasswd;
}

Mantids30::Network::Protocols::FastRPC::FastRPC3 *Globals::getWebAdminManager()
{
    return adminRPC;
}

void Globals::setWebAdminManager(Mantids30::Network::Protocols::FastRPC::FastRPC3 *newAdminRPC)
{
    adminRPC = newAdminRPC;
}

LoginDirectoryManager *Globals::getLoginDirManager()
{
    return loginDirManager;
}

void Globals::setLoginDirManager(LoginDirectoryManager *newLoginDirManager)
{
    loginDirManager = newLoginDirManager;
}

Mantids30::Program::Logs::RPCLog *Globals::getRPCLog()
{
    return rpclog;
}

void Globals::setRPCLog(Mantids30::Program::Logs::RPCLog *value)
{
    rpclog = value;
}
