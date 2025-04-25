#include "globals.h"

LoginDirectoryManager * Globals::loginDirManager = nullptr;
IdentityManager * Globals::identityManager = nullptr;
Mantids30::Program::Logs::AppLog * Globals::applog = nullptr;
boost::property_tree::ptree Globals::pConfig;
Mantids30::Program::Logs::RPCLog * Globals::rpclog = nullptr;
bool Globals::resetAdminPasswd = false;

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
