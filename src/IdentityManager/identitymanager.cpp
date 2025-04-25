#include "identitymanager.h"

IdentityManager::IdentityManager()
{
}

IdentityManager::~IdentityManager()
{
    if (users)
        delete users;
    if (roles)
        delete roles;
    if (applications)
        delete applications;
    if (authController)
        delete authController;
}

bool IdentityManager::initializeAdminAccountWithPassword(const std::string &adminUserName, std::string *adminPW, const uint32_t & schemeId, bool *alreadyExist)
{
    bool r = true;
    if (!users->doesAccountExist(adminUserName))
    {
        r = r && users->createAdminAccount(adminUserName);
        r = r && authController->setAccountPasswordOnScheme(adminUserName,adminPW,schemeId);
        *alreadyExist  = false;
    }
    else
    {
        *alreadyExist = true;
    }
    return r;
}

bool IdentityManager::initializeApplicationWithScheme(const std::string &appName,
                                                      const std::string &appDescription,
                                                      const uint32_t &schemeId,
                                                      const std::string & owner,
                                                      bool *alreadyExist)
{
    bool r = true;

    if (!applications->doesApplicationExist(appName))
    {
        r = r && applications->addApplication( appName, appDescription,  Mantids30::Helpers::Random::createRandomString(32), owner );
        r = r && applications->addWebLoginRedirectURIToApplication(appName,"https://localhost/auth/callback");
        r = r && applications->setApplicationActivities( appName, {{"LOGIN",{.description="Main Login", .parentActivity=""}}}  );
        r = r && authController->addAuthenticationSchemesToApplicationActivity( appName, "LOGIN" , schemeId );
        r = r && authController->setApplicationActivityDefaultScheme(appName,"LOGIN", schemeId);
        *alreadyExist = false;
    }
    else
    {
        *alreadyExist = true;
    }

    return r;
}

bool IdentityManager::Users::createAdminAccount(const std::string &adminUserName)
{
    AccountFlags accountFlags;
    accountFlags.confirmed = true;
    accountFlags.enabled = true;
    accountFlags.superuser = true;
    accountFlags.blocked = false;

    if (!addAccount(adminUserName,  0, accountFlags))
    {
        return false;
    }
    return true;
}
