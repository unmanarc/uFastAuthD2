#include "authstorageimpl.h"
#include "Mantids30/Program_Logs/loglevels.h"
#include "globals.h"
#include "config.h"

#include <sys/stat.h>

#include <Mantids30/Program_Logs/applog.h>

#include <boost/algorithm/string/case_conv.hpp>

#include <Mantids30/DB_SQLite3/sqlconnector_sqlite3.h>
#include <Mantids30/Helpers/random.h>
#include <Mantids30/Helpers/crypto.h>

#include "defs.h"

#ifdef WIN32
#include <windows.h>
#endif

using namespace Mantids30::Database;
using namespace Mantids30::Program;
using namespace Mantids30;

bool AuthStorageImpl::createAuth()
{
    std::string sDriverName = Globals::getConfig()->get<std::string>("Auth.Driver","");
    std::string sDefaultUser = Globals::getConfig()->get<std::string>("Auth.DefaultUser","admin");

    IdentityManager_DB * identityManager = nullptr;

    if (boost::to_lower_copy(sDriverName) == "sqlite3")
    {
        std::string dbFilePath = Globals::getConfig()->get<std::string>("Auth.File","");
        SQLConnector_SQLite3 * sqlConnector = new SQLConnector_SQLite3;
        sqlConnector->setThrowCPPErrorOnQueryFailure(true);
        if (!sqlConnector->connect(dbFilePath))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error, Failed to open/create SQLite3 file: '%s'", dbFilePath.c_str());
            return false;
        }

        identityManager = new IdentityManager_DB(sqlConnector);
    }
    /*    else if (boost::to_lower_copy(driver) == "postgresql")
    {
        // TODO:
        return false;
    }
    else if (boost::to_lower_copy(driver) == "mariadb")
    {
        // TODO:
        return false;
    }*/
    else
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error, Authentication driver '%s' not implemented", sDriverName.c_str());
    }

    if (!identityManager)
        return false;

    std::string sInitPW;

    if (!identityManager->initializeDatabase())
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error (Driver: %s), Unknown error during database scheme initialization.", sDriverName.c_str());
        return false;
    }

    bool r = true;
    bool appExisted,userExisted,defaultPasswordSchemesExisted;

    uint32_t schemeId = r?identityManager->authController->initializateDefaultPasswordSchemes(&defaultPasswordSchemesExisted):UINT32_MAX;
    if ( defaultPasswordSchemesExisted )
    {
        if (schemeId == UINT32_MAX)
        {
            r = false;
            LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Default password scheme for simple login does not exist anymore.");
        }
        else
        {
            // Perfect, continue.
        }
    }
    else
    {
        if (schemeId == UINT32_MAX)
        {
            r = false;
            LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Default password scheme for simple login can't be created.");
        }
        else
        {
            LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Default password scheme for simple login successfully created.");
        }
    }

    if (r)
    {
        r=r&&identityManager->initializeAdminAccountWithPassword(sDefaultUser,&sInitPW,schemeId,&userExisted);

        if ( userExisted )
        {
            // User exist, do nothing.
            LOG_APP->log0(__func__, Logs::LEVEL_DEBUG, "Default user '%s' already exist.",sDefaultUser.c_str());
        }
        else
        {
            if (r)
            {
                LOG_APP->log0(__func__, Logs::LEVEL_INFO, "Default user '%s' successfully created.",sDefaultUser.c_str());
            }
            else
            {
                LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Default user '%s' can't be created.",sDefaultUser.c_str());
                return false;
            }
        }
    }

    if (r)
    {
        r=r&&identityManager->initializeApplicationWithScheme(  DB_APPNAME,
                                                                DB_APPDESCRIPTION,
                                                                schemeId,
                                                                sDefaultUser,
                                                                &appExisted
                                                                  );
        if ( appExisted )
        {
            // User exist, do nothing.
            LOG_APP->log0(__func__, Logs::LEVEL_DEBUG, "App '%s' already exist.", DB_APPNAME);
        }
        else
        {
            if (r)
            {
                LOG_APP->log0(__func__, Logs::LEVEL_INFO, "APP '%s' successfully created.",DB_APPNAME);
            }
            else
            {
                LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "APP '%s' can't be created.",DB_APPNAME);
                return false;
            }
        }
    }

    // Check account flags:
    auto accountFlags = identityManager->users->getAccountFlags(sDefaultUser);

    // Check for admin accounts:
    if ( identityManager->users->doesAccountExist(sDefaultUser) && !accountFlags.superuser )
    {
        // This account should be marked as superuser.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Account '%s' detected without superuser privileges. Manual intervention required to grant superuser status.",sDefaultUser.c_str());
    }
    else if ( identityManager->users->doesAccountExist(sDefaultUser) && identityManager->users->isAccountExpired(sDefaultUser) )
    {
        // This account should not expire.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Account '%s' is currently expired. Reactivation required immediately to ensure proper system management.", sDefaultUser.c_str());
    }
    else if ( identityManager->users->doesAccountExist(sDefaultUser) && !accountFlags.enabled )
    {
        // This account should not be disabled.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Account '%s' is disabled. Enable the account to maintain essential administrative functions.", sDefaultUser.c_str());
    }
    else if ( identityManager->users->doesAccountExist(sDefaultUser) && !accountFlags.confirmed )
    {
        // This account should not be disabled.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Account '%s' exists but is unconfirmed. Confirmation is necessary for full functionality.",sDefaultUser.c_str());
    }

    // If password marked for reset, reset:
    if (Globals::getResetAdminPasswd())
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Password marked to be reseted...");
        std::string sInitPW;      
        if (!identityManager->authController->setAccountPasswordOnScheme(sDefaultUser,&sInitPW,schemeId))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Password not resetted (Maybe the account '%s' does not have admin privileges?)...",sDefaultUser.c_str());
            return false;
        }
    }

    if (!sInitPW.empty())
    {
        // Create the password file if there is a new password...
        if (!createPassFile(sInitPW))
            return false;
    }

    if (!configureApplication(identityManager,sDefaultUser))
        return false;

    Globals::setIdentityManager(identityManager);

    return true;
}

bool AuthStorageImpl::createPassFile(const std::string & sInitPW)
{

#ifndef WIN32
    std::string initPassOutFile = "/tmp/syspwd-" +Mantids30::Helpers::Random::createRandomString(8) ;
#else
    char tempPath[MAX_PATH+1];
    GetTempPathA(MAX_PATH,tempPath);
    std::string initPassOutFile = tempPath + "\\syspwd-" +Mantids30::Helpers::Random::createRandomString(8) + ".txt";
#endif
    std::ofstream ofstr(initPassOutFile);
    if (ofstr.fail())
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to save the password account.");
        return false;
    }
#ifndef WIN32
    if (chmod(initPassOutFile.c_str(),0600)!=0)
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Failed to chmod the password file (be careful with this file and content).");
    }
#else
    LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Initial password was saved without special owner read-only privileges (be careful).");
#endif
    ofstr << sInitPW;
    ofstr.close();
    LOG_APP->log0(__func__,Logs::LEVEL_INFO, "File '%s' created with the super-user password. Login and change it immediatly", initPassOutFile.c_str());
    return true;
}

/*
bool AuthStorageImpl::resetAdminPwd(IdentityManager_DB *identityManager, std::string *sInitPW)
{
    *sInitPW = Mantids30::Helpers::Random::createRandomString(16);

    Credential credentialData;
    credentialData.hash = Helpers::Crypto::calcSHA256(*sInitPW);

    credentialData.
    credentialData.passwordFunction = FN_SHA256;
    credentialData.forceExpiration = true; // Expired (to be changed on the first login).

    return identityManager->authController->changeCredential("admin", credentialData);
}*/

bool AuthStorageImpl::configureApplication(IdentityManager_DB *identityManager, const std::string &owner)
{
    if (!identityManager->applications->doesApplicationExist(DB_APPNAME))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Application '%s' does not exist, aborting.", DB_APPNAME);
        return false;
    }
    std::list<std::pair<ApplicationPermission, std::string>> appPermissions =
    {
        {{DB_APPNAME, "SELF_PWDCHANGE"}, "Permission to change my own password"},
        {{DB_APPNAME, "SELF_READ"}, "Permission to read my own user data from the IAM system"},
        {{DB_APPNAME, "SELF_DELETE"}, "Permission to delete my own user"},

        {{DB_APPNAME, "USER_READ"},   "Permission to read users data from the IAM system"},
        {{DB_APPNAME, "USER_DELETE"}, "Permission to delete users from the IAM system"},
        {{DB_APPNAME, "USER_MODIFY"}, "Permission to edit user details, roles, and permissions"},
        {{DB_APPNAME, "USER_PWDDCHANGE"}, "Permission to change user passwords"},
        {{DB_APPNAME, "USER_DISABLE"}, "Permission to disable/lock users"},
        {{DB_APPNAME, "USER_ENABLE"}, "Permission to enable/unlock users"},

        {{DB_APPNAME, "ROLE_CREATE"}, "Permission to create roles on the IAM system"},
        {{DB_APPNAME, "ROLE_READ"},   "Permission to read roles from the IAM system"},
        {{DB_APPNAME, "ROLE_DELETE"}, "Permission to remove roles from the IAM system"},
        {{DB_APPNAME, "ROLE_MODIFY"}, "Permission to modify roles and their associated permissions"},

        {{DB_APPNAME, "APP_CREATE"}, "Permission to create applications on the IAM"},
        {{DB_APPNAME, "APP_DELETE"}, "Permission to delete application's from the IAM"},
        {{DB_APPNAME, "APP_MODIFY"}, "Permission to modify application data on the IAM"},
        {{DB_APPNAME, "APP_READ"}, "Permission to read application data from the IAM"},

        {{DB_APPNAME, "AUTH_CREATE"}, "Permission to create authentication schemes and slots on the IAM"},
        {{DB_APPNAME, "AUTH_DELETE"}, "Permission to delete authentication schemes and slots on the IAM"},
        {{DB_APPNAME, "AUTH_MODIFY"}, "Permission to modify authentication schemes and slots on the IAM"},
        {{DB_APPNAME, "AUTH_READ"},   "Permission to read authentication schemes and slots on the IAM"},

        {{DB_APPNAME, "AUDIT_LOG_VIEW"}, "Permission to access, export and view IAM audit logs"},
        {{DB_APPNAME, "AUDIT_LOG_CLEAN"}, "Permission to clean/remove audit logs"}
    };

    for ( auto & permission : appPermissions )
    {
        if (!identityManager->authController->doesApplicationPermissionExist(permission.first))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Permission '%s' does not exist, creating it.", permission.first.permissionId.c_str());

            if (!identityManager->authController->addApplicationPermission(permission.first,permission.second))
            {
                LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to create the permission '%s'.", permission.first.permissionId.c_str());
                return false;
            }
        }
    }

    if (!identityManager->applications->validateApplicationAccount(DB_APPNAME,owner))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Setting up '%s' user as application '%s' user.", owner.c_str(), DB_APPNAME);

        if (!identityManager->applications->addAccountToApplication(DB_APPNAME,owner))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to set the '%s' account as application '%s' user.", owner.c_str(), DB_APPNAME);
            return false;
        }
    }

    if (!identityManager->applications->validateApplicationOwner(DB_APPNAME,owner))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Setting up '%s' user as application '%s' owner.", owner.c_str(), DB_APPNAME);

        if (!identityManager->applications->addApplicationOwner(DB_APPNAME,owner))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to set the '%s' account as application '%s' owner.", owner.c_str(), DB_APPNAME);
            return false;
        }
    }

    return true;
}
